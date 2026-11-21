"""端口连通性与 TLS 证书检查。

证书是最容易被忽略的一环：Poste.io 用 Let's Encrypt 默认只签 mail.<域名>，
而客户端访问 autoconfig./autodiscover. 时 SNI 是那两个名字，证书对不上就直接
握手失败——表现就是「自动配置永远转圈后让你手填」。
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from . import model
from .model import Collector, Target
from .dnsq import Resolver
from .netutil import CertInfo, human_err, is_tls_reject, probe_tls, tcp_open

PORTS = [
    ("imaps", 993, "implicit", "IMAP over TLS", "收信"),
    ("imap", 143, "starttls", "IMAP + STARTTLS", "收信"),
    ("submissions", 465, "implicit", "SMTP 提交 over TLS", "发信"),
    ("submission", 587, "starttls", "SMTP 提交 + STARTTLS", "发信"),
    ("smtp", 25, "starttls", "SMTP", "收信"),
    ("pop3s", 995, "implicit", "POP3 over TLS", "收信（可选）"),
]

ESSENTIAL = {"993", "587", "465"}

STARTTLS_KIND = {25: "smtp", 143: "imap", 587: "smtp"}


def check_ports(t: Target, col: Collector, ips: list[str] | None = None) -> dict[str, dict]:
    """检查所有端口，返回 {port: {open, elapsed, error, tls}}。

    ips 由 DNS 检查结果传入，直连这些地址而不是依赖系统解析——
    开着代理 fake-ip 的环境下，系统解析会让所有域名都「连得上」。
    """
    host = t.mail_host
    if ips is not None and not ips:
        col.fail("ports", "transport", "服务端口",
                 f"{host} 没有可用的 IP，端口全部不可达",
                 f"DNS 里查不到 {host} 的任何地址。地址不存在时，" +
                 "客户端连一个端口都建立不了连接。",
                 f"先给 {host} 添加 A 记录指向服务器公网 IP。",
                 weight=9, data={"ports": [], "ip": None})
        return {}
    ip = ips[0] if ips else None

    def one(item):
        key, port, mode, label, role = item
        opened, elapsed, err = tcp_open(host, port, timeout=4.5, ip=ip)
        info = {"key": key, "port": port, "mode": mode, "label": label,
                "role": role, "open": opened, "elapsed": elapsed, "error": err,
                "tls": None, "_tls": None, "ip": ip}
        if opened:
            tr = probe_tls(host, port, sni=host,
                           starttls=STARTTLS_KIND.get(port),
                           timeout=6, ip=ip)
            info["_tls"] = tr  # 内部使用，不参与序列化
            info["tls"] = {
                "ok": tr.ok,
                "trusted": tr.trusted,
                "protocol": tr.proto,
                "error": tr.error,
                "verify_error": tr.verify_error,
                "cert": tr.cert.as_dict() if tr.cert else None,
            }
        return info

    with ThreadPoolExecutor(max_workers=6) as pool:
        rows = list(pool.map(one, PORTS))

    by_port = {str(r["port"]): r for r in rows}
    # 去掉内部使用的 TlsResult 对象，只留可序列化的摘要
    out_rows = [{k: v for k, v in r.items() if k != "_tls"} for r in rows]
    open_count = sum(1 for r in rows if r["open"])

    paid_ports = [r for r in rows if str(r["port"]) in ESSENTIAL]
    closed_essential = [r for r in paid_ports if not r["open"]]

    if closed_essential:
        names = ", ".join(f"{r['port']}（{r['label']}）" for r in closed_essential)
        detail = "\n".join(
            f"{r['port']:>4} {r['label']:<22} {'开放' if r['open'] else '不通'}"
            + (f"  {r['error']}" if r["error"] else "")
            for r in rows)
        fix = ("检查防火墙/安全组是否放行 993、587、465；"
               "25 端口很多云厂商默认封禁，需单独申请解封。")
        # 收信端口通、SMTP 端口超时 —— 这是本地代理按端口拦截的典型指纹
        recv_ok = any(r["open"] for r in rows if r["port"] in (993, 143))
        smtp_timeout = any("超时" in (r["error"] or "") for r in closed_essential
                           if r["port"] in (587, 465))
        if recv_ok and smtp_timeout:
            detail += ("\n\n注意：收信端口是通的，只有 SMTP 端口超时。"
                       "同一台机器不会只丢这几个端口——多半是你本地的代理 / TUN 全局模式"
                       "把这些流量转给了代理节点，而节点方封禁了 SMTP 出站。")
            fix = ("先关掉 TUN / 全局代理再测一次确认。\n"
                   "根治：在代理规则里让邮件服务器直连，"
                   f"例如 DOMAIN-SUFFIX,{t.domain},DIRECT 或 "
                   "IP-CIDR,<邮件服务器IP>/32,DIRECT。")
        col.fail("ports", "transport", "服务端口",
                 f"{names} 不通",
                 "客户端自动配置成功后还要真的连上这些端口，否则照样失败。\n" + detail,
                 fix, weight=9, data={"ports": out_rows})
    elif open_count < 4:
        col.warn("ports", "transport", "服务端口",
                 f"只开放了 {open_count} 个端口",
                 "\n".join(f"{r['port']} {r['label']} {'开放' if r['open'] else '不通'}" for r in rows),
                 "核心端口 993/587/465 建议全部开放，兼容性最好。",
                 weight=7, data={"ports": out_rows})
    else:
        label = "全部开放" if open_count == len(rows) else f"{open_count}/{len(rows)} 开放"
        col.ok("ports", "transport", "服务端口", label,
               "\n".join(f"{r['port']:>4} {r['label']:<22} {'开放' if r['open'] else '不通'}"
                         for r in rows),
               weight=8, data={"ports": out_rows})
    return by_port


def _judge_cert(cert: CertInfo | None, host: str, trusted: bool,
                verify_error: str) -> tuple[str, str]:
    """返回 (status, 说明)。"""
    if cert is None:
        return model.FAIL, "没有取到证书（连接建立失败或对方未启用 TLS）"
    covers = cert.covers(host)
    if trusted and covers:
        return model.PASS, f"证书有效，签发者 {cert.issuer}"
    if not covers:
        return model.FAIL, (
            f"证书里没有 {host}。\n"
            f"现有域名：{', '.join(cert.sans) or '（无 SAN）'}\n"
            f"签发者：{cert.issuer or '未知'}"
            + (f"\n校验错误：{verify_error}" if verify_error else ""))
    return model.WARN, f"证书包含 {host} 但链校验未通过：{verify_error}"


def check_certs(t: Target, r: Resolver, col: Collector, by_port: dict):
    """三个证书视角：邮件主机、autoconfig、autodiscover。"""
    # 1) 邮件主机 —— 端口检查里已经握过手，直接复用
    mail_port = None
    for key in ("993", "465", "143"):
        if by_port.get(key, {}).get("_tls"):
            mail_port = by_port[key]
            break
    if mail_port is None:
        col.fail("tls_mail", "transport", "邮件服务器证书",
                 "无法完成 TLS 握手",
                 f"{t.mail_host} 的加密端口都没建立 TLS 会话，证书无从检查。",
                 f"先确认 993/465 端口开放且服务在跑。\n"
                 f"如果 {t.mail_host} 其实不是你的 IMAP/SMTP 主机名，"
                 "请把真实主机名（如 imap." + t.domain + "）填到「邮件主机」后重扫。",
                 weight=9)
        cert_for_mail = None
    else:
        tr = mail_port["_tls"]
        status, why = _judge_cert(tr.cert, t.mail_host, tr.trusted, tr.verify_error)
        days = tr.cert.days_left if tr.cert else None
        extra = f"\n有效期至 {tr.cert.not_after}（剩 {days} 天）" if tr.cert and days is not None else ""
        if status == model.PASS and days is not None and days < 14:
            col.warn("tls_mail", "transport", "邮件服务器证书",
                     f"证书 {days} 天后过期",
                     why + extra,
                     "Let's Encrypt 证书 90 天有效，确认自动续期任务在运行。",
                     weight=9, data={"cert": tr.cert.as_dict() if tr.cert else {}})
        elif status == model.PASS:
            col.ok("tls_mail", "transport", "邮件服务器证书",
                   f"有效，剩 {days} 天" if days is not None else "有效",
                   why + extra, weight=9,
                   data={"cert": tr.cert.as_dict() if tr.cert else {}})
        else:
            col.fail("tls_mail", "transport", "邮件服务器证书", why.split("\n")[0],
                     why + extra,
                     f"先确认「邮件主机」填的是真正的 IMAP/SMTP 主机名"
                     f"（Poste.io 通常是 mail.{t.domain}）。\n"
                     f"确认无误后，为 {t.mail_host} 重新签发证书——"
                     "Poste.io 后台 System settings → SSL 可一键申请 Let's Encrypt。",
                     weight=9, data={"cert": tr.cert.as_dict() if tr.cert else {}})
        cert_for_mail = tr.cert

    # 2) autoconfig / autodiscover —— 走 443
    def probe_web(host: str):
        res = r.resolve_any_address(host)
        ips = res["ipv4"] or res["ipv6"]
        if not ips:
            return host, None, "域名无法解析"
        tr = probe_tls(host, 443, sni=host, timeout=7, ip=ips[0])
        if not tr.ok:
            return host, None, tr.error or "TLS 握手失败"
        return host, tr, ""

    targets = [f"autoconfig.{t.domain}", f"autodiscover.{t.domain}"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        probed = list(pool.map(probe_web, targets))

    for cid, (host, tr, err) in zip(("tls_autoconfig", "tls_autodiscover"), probed):
        title = f"{host.split('.')[0]} 域名的证书"
        if tr is None:
            human = human_err(err)
            if is_tls_reject(err):
                fix = (f"服务器端问题：{host} 的解析是对的，但 Web 服务器没有认领这个域名，"
                       "握手在出示证书前就被拒绝了。\n"
                       f"Caddy：把 {host} 加进站点块，例如\n"
                       f"  {host} {{\n      reverse_proxy 127.0.0.1:8080\n  }}\n"
                       f"Nginx：为该 server_name 配置 ssl_certificate，证书需包含 {host}。")
            else:
                fix = (f"让 {host} 解析到邮件服务器，并在证书里包含这个名字"
                       f"（Poste.io 后台 SSL 可一并申请）。")
            col.fail(cid, "transport", title, human,
                     f"无法从 {host}:443 取到证书：{human}\n"
                     "客户端访问自动配置端点时，TLS 握手在这一步就断了，"
                     "后面的 XML 根本没机会被读取。",
                     fix, weight=8, data={"host": host, "error": err})
            continue

        status, why = _judge_cert(tr.cert, host, tr.trusted, tr.verify_error)
        if status == model.PASS:
            col.ok(cid, "transport", title, "证书覆盖该域名",
                   why, weight=8,
                   data={"host": host, "cert": tr.cert.as_dict() if tr.cert else {}})
            continue

        # 退化判断：如果证书覆盖 mail 主机但不覆盖这个名字，是典型 Let's Encrypt 单域名问题
        extends_mail = bool(cert_for_mail and cert_for_mail.covers(t.mail_host)
                            and tr.cert and not tr.cert.covers(host))
        fix = (
            f"把 {host} 加进证书。Poste.io：后台 → System settings → SSL → "
            f"在证书域名里同时填 {t.mail_host}、autoconfig.{t.domain}、autodiscover.{t.domain} 后重新申请。\n"
            f"通配符证书 *.{t.domain} 也能覆盖这些一级子域，但要注意通配符只匹配一层。"
        )
        if extends_mail:
            why = ("服务器返回的是 mail 主机的证书，里面没有这个域名——"
                   "这正是自建邮箱自动配置失败最常见的原因。\n" + why)
        if status == model.FAIL:
            col.fail(cid, "transport", title, "证书不含该域名", why, fix,
                     weight=8, data={"host": host, "cert": tr.cert.as_dict() if tr.cert else {}})
        else:
            col.warn(cid, "transport", title, "证书链未通过校验", why, fix,
                     weight=8, data={"host": host, "cert": tr.cert.as_dict() if tr.cert else {}})
