"""DNS 记录完整性检查：收信链路、发信认证、服务发现。"""
from __future__ import annotations

import re

from . import model
from .model import Collector, Target
from .dnsq import Resolver, STATUS_NXDOMAIN

DKIM_CANDIDATES = ["dkim", "default", "mail", "poste", "s1", "s2", "selector1",
                   "selector2", "smtp", "key1", "2024", "2025"]


def _ips_of(resolver: Resolver, host: str) -> set[str]:
    res = resolver.resolve_any_address(host)
    return set(res["ipv4"]) | set(res["ipv6"])


def _fmt_ip_set(ips: set[str]) -> str:
    return ", ".join(sorted(ips)) if ips else "（无）"


# ---------------------------------------------------------------- 收信与投递

def check_mx(t: Target, r: Resolver, col: Collector) -> list[tuple[int, str]]:
    res = r.query(t.domain, "MX")
    mx = r.mx(t.domain)

    if res.status == STATUS_NXDOMAIN:
        col.fail("mx", "delivery", "MX 记录",
                 f"{t.domain} 这个域名在 DNS 里根本不存在",
                 "域名未注册或未配置 NS，邮件完全无法送达。",
                 "先在域名注册商处完成域名解析托管。", weight=10)
        return mx

    if not mx:
        null_mx = any(r.rtype == "MX" and r.data.strip().startswith("0 .")
                      for r in res.answers)
        if null_mx:
            col.info("mx", "delivery", "MX 记录", "声明了 null MX，此域不收信",
                     "记录为 0 . （RFC 7505），表示这个域名明确不接收邮件。"
                     "如果你正在用它收信，说明 MX 记录需要改成指向邮件服务器。",
                     weight=0)
            return mx
        col.fail("mx", "delivery", "MX 记录",
                 "没有 MX 记录，收不到任何外部来信",
                 f"对 {t.domain} 查询 MX 返回 {res.status}，无有效记录。"
                 "没有 MX 记录时，发信方会退回 A 记录，基本等同于收不到信。",
                 f"添加：{t.domain}. 3600 IN MX 10 {t.mail_host}.",
                 [f"{t.domain}. 3600 IN MX 10 {t.mail_host}."], weight=10)
        return mx

    hosts = [h for _, h in mx]
    primary = hosts[0]
    records = [f"{t.domain}. 3600 IN MX {p} {h}." for p, h in mx]

    missing = [h for h in hosts if not _ips_of(r, h)]
    if missing:
        col.fail("mx", "delivery", "MX 记录",
                 f"MX 指向的 {', '.join(missing)} 无法解析到 IP",
                 f"MX 记录本身存在（{', '.join(hosts)}），但目标主机没有 A/AAAA 记录。"
                 "发信方拿到 MX 后查不到 IP，投递直接失败。",
                 f"为 {missing[0]} 添加 A 记录指向你的服务器公网 IP。",
                 records, weight=10)
    else:
        col.ok("mx", "delivery", "MX 记录",
               f"{len(mx)} 条，主服务器 {primary}",
               "MX 记录存在且目标主机可解析到 IP。", records, weight=10)

    return mx


def check_mail_host_a(t: Target, r: Resolver, col: Collector) -> dict:
    res = r.resolve_any_address(t.mail_host)
    ips = res["ipv4"] + res["ipv6"]
    label = f"{t.mail_host} 的 A 记录"

    if not ips:
        detail = f"查询 {t.mail_host} 的 A/AAAA 未得到任何地址（{res['status']}）。"
        if res["chain"]:
            detail += f" CNAME 链：{t.domain} → {' → '.join(res['chain'])}，但终点没有地址。"
        col.fail("a_record", "delivery", label,
                 f"{t.mail_host} 解析不到 IP",
                 detail,
                 f"添加 A 记录：{t.mail_host}. 3600 IN A <你的服务器公网 IP>",
                 [f"{t.mail_host}. 3600 IN A <服务器公网IP>"], weight=8)
        return {"ips": []}

    chain_txt = f"（CNAME 链：{' → '.join(res['chain'])}）" if res["chain"] else ""
    col.ok("a_record", "delivery", label,
           f"{_fmt_ip_set(set(ips))} {chain_txt}".strip(),
           f"{t.mail_host} 正常解析，客户端可据此建立连接。",
           [f"{t.mail_host}. 3600 IN A {ips[0]}"], weight=8,
           data={"ips": ips, "chain": res["chain"]})
    return {"ips": ips}


def check_ptr(t: Target, mx: list[tuple[int, str]], r: Resolver, col: Collector):
    """反向解析。

    硬性要求是 FCrDNS（正向能回指同一 IP）；PTR 是否恰好等于邮件主机名属于
    加分项——大型邮件商普遍用独立的反查名，所以不能一刀切判失败。
    """
    if not mx:
        col.skip("ptr", "delivery", "PTR 反向解析", "MX 缺失，无法检查")
        return

    hosts = [h for _, h in mx]
    primary = hosts[0]
    ips = sorted(_ips_of(r, primary))
    if not ips:
        col.skip("ptr", "delivery", "PTR 反向解析", "主 MX 无 IP，无法反查")
        return

    ok_items, no_ptr, fc_fail, diff_name = [], [], [], []
    lines: list[str] = []
    for ip in ips[:4]:
        ptrs = r.ptr(ip)
        if not ptrs:
            lines.append(f"{ip} → 没有 PTR 记录")
            no_ptr.append(ip)
            continue
        name = ptrs[0]
        back = set(r.a(name)) | set(r.aaaa(name))
        fc = ip in back
        if not fc:
            lines.append(f"{ip} → {name}（回查 A 记录不含该 IP，FCrDNS 不成立）")
            fc_fail.append((ip, name))
        elif name.lower() == primary.lower():
            lines.append(f"{ip} → {name}")
            ok_items.append((ip, name))
        else:
            lines.append(f"{ip} → {name}（与邮件主机名不同，但回查一致）")
            diff_name.append((ip, name))

    if no_ptr:
        col.fail("ptr", "delivery", "PTR 反向解析",
                 f"{', '.join(no_ptr)} 没有反向解析",
                 "没有 PTR 时，Gmail / Outlook 会显著降低信誉，你的信会大量进垃圾箱。\n"
                 + "\n".join(lines) +
                 "\nPTR 不在域名解析商处配置，而在云服务器控制台的「反向解析 / rDNS」里设置。",
                 f"在云服务商控制台把 {ips[0]} 的反向解析设为 {primary}",
                 weight=7, data={"ptr": lines})
    elif fc_fail:
        col.warn("ptr", "delivery", "PTR 反向解析",
                 f"{fc_fail[0][1]} 反查不回指 {fc_fail[0][0]}",
                 "PTR 指向的域名没有解析回同一个 IP（FCrDNS 不成立），"
                 "严格校验的收件方会当作伪造来源。\n" + "\n".join(lines),
                 f"把 {fc_fail[0][0]} 的 PTR 改为 {primary}，并确保它有 A 记录",
                 weight=7, data={"ptr": lines})
    elif diff_name:
        col.ok("ptr", "delivery", "PTR 反向解析",
               f"已反向解析（{diff_name[0][1]}）",
               "反查存在且正向回指一致，可以正常收信。\n"
               f"建议把 PTR 改成与邮件主机名一致（{primary}），对送达率更友好。\n"
               + "\n".join(lines),
               weight=7, data={"ptr": lines})
    else:
        col.ok("ptr", "delivery", "PTR 反向解析",
               f"{ok_items[0][0]} → {ok_items[0][1]}",
               "正反解析完全一致。\n" + "\n".join(lines),
               weight=7, data={"ptr": lines})


# ---------------------------------------------------------------- 发信认证

def check_spf(t: Target, r: Resolver, col: Collector, mail_ips: list[str]):
    txts = r.txt(t.domain)
    spf = [x for x in txts if x.lower().startswith("v=spf1")]
    record = f'{t.domain}. 3600 IN TXT "v=spf1 mx ~all"'

    if len(spf) > 1:
        col.fail("spf", "auth", "SPF 记录",
                 f"存在 {len(spf)} 条 SPF，属于配置错误",
                 "多条 SPF 会被判定为 permerror，等于完全没有 SPF。\n"
                 + "\n".join(f'  "{s}"' for s in spf),
                 "只保留一条 SPF，把其余记录里的 ip4/include 机制合并进来。",
                 weight=10)
        return
    if not spf:
        col.fail("spf", "auth", "SPF 记录",
                 "没有 SPF 记录",
                 "缺少 SPF 时，任何人都能以你的域名发信，你的正常邮件也更容易被判为垃圾。",
                 f"添加：\n  {record}",
                 [record], weight=10)
        return

    val = spf[0]

    # all 机制
    all_m = re.search(r"([~\-+?])all\b", val, re.I)
    all_mech = all_m.group(0) if all_m else None

    # 覆盖源
    covers = False
    for ip in mail_ips:
        if f"ip4:{ip}" in val or f"ip6:{ip}" in val:
            covers = True
    if re.search(r"\bmx\b", val) or "include:" in val:
        covers = True

    issues = []
    if all_mech is None:
        issues.append("缺少 all 机制（典型写法是 ~all 或 -all）")
    elif all_mech == "?all":
        issues.append("?all 等同于不表态，几乎没有防护作用")
    elif all_mech == "+all":
        issues.append("+all 等于允许任何人冒用你的域名发信，必须改掉")

    if not covers:
        issues.append(f"没有任何机制覆盖你的发信 IP（{_fmt_ip_set(set(mail_ips))}），"
                      "建议加 mx 或 ip4:")

    if issues:
        col.warn("spf", "auth", "SPF 记录",
                 "；".join(issues),
                 f'当前记录："{val}"\n' + "\n".join("- " + i for i in issues),
                 f"建议改为：{record}",
                 [record], weight=9, data={"value": val, "all": all_mech})
    else:
        col.ok("spf", "auth", "SPF 记录",
               f"有效，策略 {all_mech}",
               f'记录："{val}"\n已覆盖发信源，all 机制明确。',
               [f'{t.domain}. 3600 IN TXT "{val}"'], weight=9,
               data={"value": val, "all": all_mech})


def check_dkim(t: Target, r: Resolver, col: Collector):
    candidates: list[str] = []
    if t.dkim_selector:
        candidates.append(t.dkim_selector)
    candidates += [c for c in DKIM_CANDIDATES if c not in candidates]

    found = []
    for sel in candidates:
        name = f"{sel}._domainkey.{t.domain}"
        txts = r.txt(name)
        dk = [x for x in txts if "p=" in x or x.lower().startswith("v=dkim1")]
        if dk:
            found.append((sel, name, dk[0]))

    if not found:
        tried = "、".join(candidates[:8])
        if t.dkim_selector:
            col.fail("dkim", "auth", "DKIM 记录",
                     f"selector「{t.dkim_selector}」查不到公钥",
                     f"{t.dkim_selector}._domainkey.{t.domain} 没有 TXT 记录。"
                     "检查这个 selector 是否与 Poste.io 后台显示的一致，"
                     "以及 TXT 值是否被拆行截断。",
                     "到 Poste.io 后台 Virtual domains → 你的域名 → DKIM，"
                     "复制「主机名」和「TXT 值」到 DNS。", weight=9)
        else:
            col.warn("dkim", "auth", "DKIM 记录",
                     "未在常见 selector 下找到公钥",
                     f"已尝试：{tried}\n"
                     "Poste.io 的 DKIM selector 是建域时按日期生成的，形如 s20240419303"
                     "（注意：没有前导下划线，下划线只出现在记录名的 _domainkey 那段）。"
                     "猜不到属于正常。请到管理后台 Virtual domains → 你的域名 → "
                     "「DKIM key」一栏看 Selector 后面的值，填到工具的「DKIM selector」里"
                     "重新扫描即可精确校验。",
                     "展开「更多选项」填入 DKIM selector 后重扫，即可精确校验这条记录。",
                     weight=6)
        return

    sel, name, val = found[0]
    p = re.search(r"\bp=([^;\s]*)", val)
    key = p.group(1) if p else ""

    problems, notes = [], []
    if not key:
        problems.append("p= 为空，等同于吊销了这把密钥")
    elif len(key) < 100:
        problems.append("公钥长度异常偏短，可能复制时被截断")
    if "k=rsa" not in val.lower() and "k=ed25519" not in val.lower():
        notes.append("未声明 k= 算法（多数实现默认 rsa，可忽略）")

    detail = f'selector：{sel}\n记录：{name} IN TXT "{val[:120]}{"…" if len(val) > 120 else ""}"'
    if notes:
        detail += "\n" + "；".join(notes)
    if problems:
        # 不给 records：当前值本身有问题，照抄只会把错误复制一遍
        col.warn("dkim", "auth", "DKIM 记录",
                 "；".join(problems), detail,
                 f"到 Poste.io 后台 Virtual domains → 你的域名 → DKIM 重新复制完整 TXT 值，"
                 f"替换 {name} 上的记录（当前这条不可用）。", weight=9,
                 data={"selector": sel, "value": val})
    else:
        extra = ""
        if len(found) > 1:
            extra = f"\n另外还探测到 {', '.join(s for s, _, _ in found[1:])} 的密钥（轮换期间属正常）。"
        col.ok("dkim", "auth", "DKIM 记录",
               f"selector「{sel}」公钥正常（{len(key)} 字节）",
               detail + extra, [f'{name}. 3600 IN TXT "{val}"'], weight=9,
               data={"selector": sel, "value": val})


def check_dmarc(t: Target, r: Resolver, col: Collector):
    name = f"_dmarc.{t.domain}"
    txts = r.txt(name)
    dm = [x for x in txts if x.upper().startswith("V=DMARC1")]

    if not dm:
        col.warn("dmarc", "auth", "DMARC 记录",
                 "没有 DMARC 记录",
                 "DMARC 不影响收发，但缺失时收件方无法得知你希望的处置策略，"
                 "也收不到伪造报告；Gmail/Outlook 对大批量发信方已要求必须配置。",
                 f'添加：{name}. 3600 IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@{t.domain}"',
                 [f'{name}. 3600 IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@{t.domain}"'],
                 weight=7)
        return

    val = dm[0]
    p = re.search(r"\bp=(\w+)", val)
    policy = p.group(1).lower() if p else ""

    if not p:
        col.warn("dmarc", "auth", "DMARC 记录", "记录缺少 p= 策略",
                 f'当前："{val}"', '补上 p=none（观察期）或 p=quarantine。',
                 weight=7)
        return

    if policy == "none":
        col.warn("dmarc", "auth", "DMARC 记录",
                 "策略为 p=none，仅观察不处置",
                 f'当前："{val}"\n'
                 "自建邮箱初期用 none 收集报告是合理的；确认 SPF/DKIM 稳定后建议升到 quarantine。",
                 "确认收发正常后把 p=none 改为 p=quarantine。",
                 [f'{name}. 3600 IN TXT "{val}"'], weight=6,
                 data={"value": val, "policy": policy})
        return

    col.ok("dmarc", "auth", "DMARC 记录",
           f"策略 p={policy}",
           f'当前："{val}"', [f'{name}. 3600 IN TXT "{val}"'], weight=7,
           data={"value": val, "policy": policy})


def check_extra_auth(t: Target, r: Resolver, col: Collector):
    """MTA-STS / TLS-RPT / BIMI / CAA / DNSSEC —— 加分项，缺失只提示。"""
    # MTA-STS
    sts_name = f"_mta-sts.{t.domain}"
    sts = [x for x in r.txt(sts_name) if x.upper().startswith("V=STSV1")]
    if sts:
        col.ok("mta_sts", "auth", "MTA-STS 记录", "已发布", f'"{sts[0]}"', weight=3,
               data={"value": sts[0]})
    else:
        col.info("mta_sts", "auth", "MTA-STS 记录", "未配置（可选）",
                 "MTA-STS 能让收件方强制对你的服务器使用 TLS，属于加分项，不影响自动配置。",
                 weight=0)

    # TLS-RPT
    rpt_name = f"_smtp._tls.{t.domain}"
    rpt = [x for x in r.txt(rpt_name) if x.upper().startswith("V=TLSRPTV1")]
    if rpt:
        col.ok("tls_rpt", "auth", "TLS-RPT 记录", "已发布", f'"{rpt[0]}"', weight=3)
    else:
        col.info("tls_rpt", "auth", "TLS-RPT 记录", "未配置（可选）",
                 "TLS-RPT 用于接收 TLS 投递失败报告，属可选增强。", weight=0)

    # CAA —— 影响 Let's Encrypt 能否签发证书
    caa = r.caa(t.domain)
    if caa:
        issuers = [v for k, v in caa if k == "issue"]
        ok_for_le = any("letsencrypt" in v.lower() for v in issuers)
        if ok_for_le:
            col.ok("caa", "auth", "CAA 记录", f"允许 Let's Encrypt（{len(caa)} 条）",
                   "证书颁发机构授权记录存在且放行 Let's Encrypt。", weight=2)
        else:
            col.warn("caa", "auth", "CAA 记录", "未放行 Let's Encrypt",
                     f"现有 issue 授权：{', '.join(issuers) or '（无）'}\n"
                     "如果你的证书由 Let's Encrypt 签发，CAA 未授权会导致续期失败，"
                     "进而让所有客户端的 TLS 连接失效。",
                     f'添加：{t.domain}. 3600 IN CAA 0 issue "letsencrypt.org"', weight=4)
    else:
        col.info("caa", "auth", "CAA 记录", "未配置（未限制 CA）",
                 "没有 CAA 记录时任何 CA 都可为你的域名签发证书。", weight=0)


# ---------------------------------------------------------------- 服务发现

def check_srv(t: Target, r: Resolver, col: Collector):
    """RFC 6186 / RFC 6764。Apple Mail、K-9、BlueMail 都会读。"""
    def probe(name: str, expect_port: int):
        return r.srv(f"{name}.{t.domain}"), expect_port

    services = [
        ("srv_imap", ["_imaps._tcp", "_imap._tcp"], 993, 6),
        ("srv_submission", ["_submissions._tcp", "_submission._tcp"], 587, 6),
    ]
    for cid, names, port, weight in services:
        hit = None
        for prefix in names:
            recs, _ = probe(prefix, port)
            if recs:
                hit = (prefix, recs)
                break
        title = "IMAP SRV 记录" if cid == "srv_imap" else "SMTP 提交 SRV 记录"
        if not hit:
            proto = "_imaps._tcp" if cid == "srv_imap" else "_submission._tcp"
            col.fail(cid, "discovery", title,
                     f"缺少 {proto} 记录",
                     "SRV 缺失时，Apple Mail、K9、BlueMail 等在 autoconfig 失败后"
                     "无法退回到这条路径，只能让用户手填服务器地址。",
                     f"添加：{proto}.{t.domain}. 3600 IN SRV 0 1 {port} {t.mail_host}.",
                     [f"{proto}.{t.domain}. 3600 IN SRV 0 1 {port} {t.mail_host}."],
                     weight=weight)
            continue
        prefix, recs = hit
        prio, wt, actual_port, target = recs[0]
        records = [f"{prefix}.{t.domain}. 3600 IN SRV {p} {w} {pt} {tg}."
                   for p, w, pt, tg in recs]
        if not _ips_of(r, target):
            col.warn(cid, "discovery", title,
                     f"SRV 目标 {target} 无法解析",
                     f"{prefix} 指向 {target}，但该主机没有 A 记录，客户端连不上。",
                     f"为 {target} 添加 A 记录，或把 SRV 改为指向 {t.mail_host}。",
                     records, weight=weight)
        else:
            col.ok(cid, "discovery", title,
                   f"{prefix} → {target}:{actual_port}",
                   "SRV 记录存在且目标可解析。", records, weight=weight)

    # Autodiscover SRV —— Outlook 在 HTTP 失败时的退路
    recs = r.srv(f"_autodiscover._tcp.{t.domain}")
    if recs:
        prio, wt, port, target = recs[0]
        col.ok("srv_autodiscover", "discovery", "Autodiscover SRV 记录",
               f"→ {target}:{port}",
               [f"_autodiscover._tcp.{t.domain}. 3600 IN SRV {prio} {wt} {port} {target}."],
               weight=3)
    else:
        col.info("srv_autodiscover", "discovery", "Autodiscover SRV 记录",
                 "未配置（可选）",
                 "Outlook 优先走 HTTPS 的 autodiscover 域名，这条 SRV 只是备用路径。",
                 weight=0)


def check_autodiscover_dns(t: Target, r: Resolver, col: Collector, mail_ips: list[str]):
    """autoconfig./autodiscover. 必须存在并指向邮件服务器，这是自动配置的前提。"""
    base_ips = set(mail_ips)
    for host, cid, label, weight in [
        (f"autoconfig.{t.domain}", "autoconfig_dns", "autoconfig 域名解析", 9),
        (f"autodiscover.{t.domain}", "autodiscover_dns", "autodiscover 域名解析", 9),
    ]:
        res = r.query(host, "A")
        resolved = r.resolve_any_address(host)
        ips = set(resolved["ipv4"]) | set(resolved["ipv6"])
        short = host.split(".")[0]

        if res.status == STATUS_NXDOMAIN:
            col.fail(cid, "discovery", label,
                     f"{host} 不存在",
                     "客户端探测自动配置时，第一步就是解析这个域名。它是 NXDOMAIN，"
                     "客户端会直接跳过这条路径去试下一种方式（通常是手填）。",
                     f"添加 CNAME：{host}. 3600 IN CNAME {t.mail_host}.\n"
                     f"（也可以直接加 A 记录指向同一 IP，但 CNAME 更好维护）",
                     [f"{host}. 3600 IN CNAME {t.mail_host}."], weight=weight)
            continue

        if not ips:
            col.warn(cid, "discovery", label,
                     f"{host} 存在但没有 A 记录",
                     f"查询状态 {res.status}，无地址返回。该域名可能是空记录或仅配置了其它类型。",
                     f"添加 A 记录指向服务器 IP，或改成 CNAME → {t.mail_host}。",
                     [f"{host}. 3600 IN CNAME {t.mail_host}."], weight=weight)
            continue

        chain = f"（CNAME → {resolved['chain'][-1]}）" if resolved["chain"] else ""
        if base_ips and not (ips & base_ips):
            col.ok(cid, "discovery", label,
                   f"→ {_fmt_ip_set(ips)}（与邮件主机不同）",
                   f"{host} {chain} 解析到 {_fmt_ip_set(ips)}，"
                   f"而 {t.mail_host} 是 {_fmt_ip_set(base_ips)}。\n"
                   "不少服务商会把自动配置放在独立集群上，这本身不算问题——"
                   "真正的判据是「自动配置端点」那一组能否取到有效 XML。",
                   weight=max(weight - 4, 2), data={"ips": sorted(ips), "base": sorted(base_ips)})
        else:
            col.ok(cid, "discovery", label,
                   f"→ {_fmt_ip_set(ips)} {chain}".strip(),
                   "域名解析正常，且与邮件服务器一致。", weight=weight,
                   data={"ips": sorted(ips), "chain": resolved["chain"]})

    # 干扰项：mailconf= TXT 会让部分客户端读到错误的配置地址
    for txt in r.txt(t.domain):
        if txt.lower().startswith("mailconf="):
            col.warn("mailconf_conflict", "discovery", "mailconf 干扰记录",
                     "存在 mailconf= TXT，可能干扰自动配置",
                     f'当前记录："{txt}"\n'
                     "部分客户端会优先读这条记录指向的配置源，指向错误时会直接配置失败。",
                     "如果不是你有意为之，删除这条 TXT 记录。", weight=3)
