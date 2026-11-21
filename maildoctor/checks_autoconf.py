"""自动配置端点探测：按各客户端的真实顺序抓取并校验配置。

覆盖 Mozilla autoconfig (Thunderbird/K-9/BlueMail)、Microsoft Autodiscover
(Outlook/BlueMail/Spark)、Apple mobileconfig、MTA-STS 策略文件。
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from . import model
from .model import Collector, Target
from .dnsq import Resolver
from .netutil import HttpResult, http_fetch, human_err, is_tls_reject

PLACEHOLDER_OK = ("%EMAILADDRESS%", "%EMAILLOCALPART%", "%EMAILDOMAIN%")

BAD_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "mail", "poste", "mailserver"}


def _looks_internal(host: str) -> bool:
    """配置里出现容器名/回环地址，说明反代拿到的 Host 头不对，客户端一定连不上。"""
    h = host.strip().lower().rstrip(".")
    if not h:
        return True
    if h in BAD_HOSTS:
        return True
    if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)", h):
        return True
    return "." not in h  # 单标签主机名（容器内网名）


# ---------------------------------------------------------------- Mozilla autoconfig

def parse_config_xml(text: str) -> dict:
    out = {"incoming": None, "outgoing": None, "error": "", "provider": "",
           "domains": []}
    raw = text.strip().lstrip("\ufeff")
    start = raw.find("<")
    if start > 0:
        raw = raw[start:]
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        out["error"] = f"XML 解析失败：{exc}"
        return out

    provider = root.find("emailProvider")
    if provider is not None:
        out["provider"] = provider.get("id", "")
    else:
        provider = root

    for server in provider.findall("incomingServer") or []:
        out["incoming"] = {
            "type": (server.get("type") or "").lower(),
            "hostname": (server.findtext("hostname") or "").strip(),
            "port": (server.findtext("port") or "").strip(),
            "socketType": (server.findtext("socketType") or "").strip(),
            "authentication": (server.findtext("authentication") or "").strip(),
            "username": (server.findtext("username") or "").strip(),
        }
        break
    for server in provider.findall("outgoingServer") or []:
        out["outgoing"] = {
            "type": (server.get("type") or "").lower(),
            "hostname": (server.findtext("hostname") or "").strip(),
            "port": (server.findtext("port") or "").strip(),
            "socketType": (server.findtext("socketType") or "").strip(),
            "authentication": (server.findtext("authentication") or "").strip(),
            "username": (server.findtext("username") or "").strip(),
        }
        break
    out["domains"] = [e.text.strip().lower() for e in provider.findall("domain") if e.text]
    if not out["incoming"] and not out["outgoing"]:
        out["error"] = "XML 结构里没有 incomingServer / outgoingServer 节点"
    return out


def _judge_config(parsed: dict, t: Target, r: Resolver) -> tuple[str, str, str]:
    """返回 (status, summary, detail)。"""
    inc, out = parsed["incoming"], parsed["outgoing"]
    if not inc or not out:
        missing = "收信" if not inc else "发信"
        return model.FAIL, f"配置里缺少{missing}服务器定义", "客户端拿到这份 XML 也无法完成配置。"

    problems, notes = [], []
    for label, cfg in (("收信", inc), ("发信", out)):
        host = cfg["hostname"]
        if not host:
            problems.append(f"{label}服务器没有 hostname")
            continue
        if _looks_internal(host):
            problems.append(f"{label}服务器地址是内网名「{host}」，客户端在公网上无法连接")
            continue
        resolved = r.resolve_any_address(host)
        if not resolved["ipv4"] and not resolved["ipv6"]:
            problems.append(f"{label}服务器 {host} 在 DNS 里查不到 IP")
        notes.append(f"{label}：{host}:{cfg['port'] or '?'} / {cfg['socketType'] or '未声明'}")
        if cfg["socketType"].lower() == "plain":
            problems.append(f"{label}配置为明文传输（plain），多数客户端会拒绝或弹警告")
        uid = cfg["username"]
        if uid and uid not in PLACEHOLDER_OK and "@" not in uid:
            problems.append(f"{label}用户名写死为「{uid}」，多账号场景会失效")

    if problems:
        return model.FAIL, problems[0], "\n".join(problems + notes)
    return model.PASS, "；".join(notes), "\n".join(notes)


def check_mozilla(t: Target, r: Resolver, col: Collector):
    candidates = [
        (f"https://autoconfig.{t.domain}/mail/config-v1.1.xml", "autoconfig_xml", 9),
        (f"https://{t.domain}/.well-known/autoconfig/mail/config-v1.1.xml",
         "autoconfig_wellknown", 9),
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda c: http_fetch(c[0], timeout=9, resolver=r), candidates))

    for (url, cid, weight), res in zip(candidates, results):
        # .well-known 是 Thunderbird 的第二顺位路径，主路径可用时它 404 属正常
        optional = cid == "autoconfig_wellknown"
        title = ("Thunderbird autoconfig（autoconfig 子域）"
                 if cid == "autoconfig_xml" else
                 "Thunderbird autoconfig（.well-known）")

        if res.error and "证书" in res.error:
            err = (res.tls.verify_error if res.tls else "") or res.error
            if optional:
                col.info(cid, "endpoint", title, f"备选路径不可用（{human_err(err)}）",
                         f"请求 {url} 时 TLS 校验失败。\n"
                         "这是第二顺位路径，主路径（autoconfig 子域）可用时不影响自动配置。",
                         weight=0)
                continue
            col.fail(cid, "endpoint", title,
                     f"TLS 校验失败：{err[:90]}",
                     f"请求 {url} 时证书不被信任。客户端在这一步就会放弃，"
                     "根本看不到后面的 XML。\n"
                     + (f"证书域名列表：{', '.join(res.tls.cert.sans)}" if res.tls and res.tls.cert else ""),
                     f"给 {url.split('/')[2]} 签一份包含该域名的证书（Poste.io 后台 → SSL → "
                     "把 autoconfig/autodiscover 域名一并申请），或把该域名改成 CNAME 指向 "
                     f"{t.mail_host} 并复用同一张证书。",
                     weight=weight, data={"url": url, "error": err})
            continue

        if res.error:
            human = human_err(res.error)
            host = url.split("/")[2]
            if optional:
                col.info(cid, "endpoint", title, f"备选路径不可用（{human}）",
                         f"请求 {url} 失败：{human}\n"
                         "这是第二顺位路径，不影响主路径使用。", weight=0)
                continue
            if is_tls_reject(res.error):
                # DNS 走通了才会连到这个 SNI，所以能被拒绝说明解析没问题
                fix = (f"这是服务器端问题，不是 DNS 问题：{host} 的域名解析是对的，"
                       "但 Web 服务器没有认领这个域名，握手还没进到 HTTP 就被拒绝了。\n"
                       f"Caddy：把 {host} 写进站点块\n"
                       f"  {host} {{\n      reverse_proxy 127.0.0.1:8080\n  }}\n"
                       f"Nginx：为该 server_name 配置 ssl_certificate，且证书要包含 {host}。\n"
                       "证书申下来后，客户端才能完成握手并读到 XML。")
                detail = (f"请求 {url} 时 TLS 握手被服务器拒绝：{human}\n"
                          "CNAME 只负责把域名指到服务器；客户端握手时用的仍是自己的域名，"
                          "服务器必须显式配置这个域名（并持有包含它的证书）。")
            else:
                fix = f"确认 {host} 已解析到邮件服务器，且 443 端口开放。"
                detail = (f"请求 {url} 失败：{human}\n"
                          "客户端探测自动配置时，这个地址必须返回 200 + XML。")
            col.fail(cid, "endpoint", title, human, detail, fix,
                     weight=weight, data={"url": url})
            continue

        if res.status != 200:
            if optional:
                col.info(cid, "endpoint", title, f"备选路径返回 HTTP {res.status}",
                         f"{url} 返回 {res.status}。\n"
                         "Thunderbird 会先试 autoconfig 子域，这条路只是兜底，"
                         "主路径可用时它不存在不影响自动配置。", weight=0)
                continue
            col.fail(cid, "endpoint", title,
                     f"HTTP {res.status}",
                     f"{url} 返回 {res.status}。"
                     + (f"（最终地址：{res.redirects[-1]}）" if res.redirects else "")
                     + "\n客户端只认 200 + XML，404/403 都会被当作「不支持自动配置」。",
                     "Poste.io 内置了这些路径，404 通常意味着反代没有转发到容器，"
                     "或访问的主机名不是邮件服务器本身。",
                     weight=weight, data={"url": url, "status": res.status})
            continue

        ctype = res.content_type
        if "xml" not in ctype:
            col.warn(cid, "endpoint", title,
                     f"返回 200 但 Content-Type 是 {ctype or '空'}",
                     f"{url}\nContent-Type 不是 XML 时，部分客户端会拒绝解析（Outlook 尤其严格）。",
                     "在反代里为该路径设置 default_type application/xml。",
                     weight=weight, data={"url": url, "content_type": ctype})

        parsed = parse_config_xml(res.body)
        if parsed["error"]:
            col.fail(cid, "endpoint", title, parsed["error"],
                     f"{url} 返回的内容无法解析：\n{res.body[:300]}",
                     "检查是否被反代替换成了登录页或错误页。", weight=weight)
            continue

        status, summary, detail = _judge_config(parsed, t, r)
        domains = parsed.get("domains") or []
        if domains and t.domain not in domains:
            detail += (f"\n\n注意：XML 里 <domain> 声明的是 {', '.join(domains)}，"
                       f"不是你的邮箱域名 {t.domain}。Poste.io 是按请求主机名渲染这个字段的，"
                       "Thunderbird / Spark 都能容忍，但严格按规范做域名匹配的客户端"
                       "（BlueMail 的云端解析就是）可能因此判定「配置不适用于该域」。")
        if status == model.PASS:
            col.ok(cid, "endpoint", title, summary,
                   f"来源：{url}\n{detail}", weight=weight,
                   data={"url": url, "config": parsed})
        else:
            col.fail(cid, "endpoint", title, summary,
                     f"来源：{url}\n{detail}",
                     "Poste.io 生成的配置依赖请求的 Host 头；如果是反代导致主机名错误，"
                     "检查 proxy_set_header Host $host 是否配置。",
                     weight=weight, data={"url": url, "config": parsed})


# ---------------------------------------------------------------- Microsoft Autodiscover

AUTODISCOVER_BODY = """<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request>
    <EMailAddress>{email}</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
  </Request>
</Autodiscover>"""


def parse_autodiscover(text: str) -> dict:
    out = {"protocols": [], "error": "", "action": ""}
    raw = text.strip().lstrip("\ufeff")
    start = raw.find("<")
    if start > 0:
        raw = raw[start:]
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        out["error"] = f"XML 解析失败：{exc}"
        return out

    action = root.find(".//{*}Action")
    if action is not None and action.text:
        out["action"] = action.text.strip()

    for proto in root.findall(".//{*}Protocol"):
        out["protocols"].append({
            "type": (proto.findtext("{*}Type") or "").strip(),
            "server": (proto.findtext("{*}Server") or "").strip(),
            "port": (proto.findtext("{*}Port") or "").strip(),
            "ssl": (proto.findtext("{*}SSL") or "").strip(),
            "login": (proto.findtext("{*}LoginName") or "").strip(),
            "encryption": (proto.findtext("{*}Encryption") or "").strip(),
        })
    if not out["protocols"] and not out["error"]:
        out["error"] = "响应里没有 Protocol 节点"
    return out


def check_autodiscover(t: Target, r: Resolver, col: Collector):
    body = AUTODISCOVER_BODY.format(email=t.email).encode("utf-8")
    urls = [
        f"https://autodiscover.{t.domain}/autodiscover/autodiscover.xml",
        f"https://autodiscover.{t.domain}/Autodiscover/Autodiscover.xml",
        f"https://{t.domain}/autodiscover/autodiscover.xml",
    ]
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(
            lambda u: http_fetch(u, method="POST", body=body, timeout=10,
                                 headers={"Content-Type": "text/xml; charset=utf-8"},
                                 resolver=r),
            urls))

    # 取第一个成功的；若都失败，报告最有信息量的那个
    good = None
    for url, res in zip(urls, results):
        if res.status == 200 and not res.error:
            good = (url, res)
            break

    title = "Outlook Autodiscover"
    if good is None:
        primary_url, primary = urls[0], results[0]
        if primary.error and "证书" in primary.error:
            err = (primary.tls.verify_error if primary.tls else "") or primary.error
            sans = primary.tls.cert.sans if primary.tls and primary.tls.cert else []
            col.fail("autodiscover_xml", "endpoint", title,
                     f"TLS 校验失败：{err[:90]}",
                     f"请求 {primary_url} 时证书不被信任。Outlook 会直接放弃 Autodiscover。\n"
                     + (f"证书域名列表：{', '.join(sans)}" if sans else ""),
                     f"证书需要包含 autodiscover.{t.domain}，或把该域名改成 CNAME 指向 "
                     f"{t.mail_host} 复用同一张证书。",
                     weight=9, data={"url": primary_url, "error": err, "sans": sans})
        else:
            reason = human_err(primary.error) if primary.error else f"HTTP {primary.status}"
            host = primary_url.split("/")[2]
            if primary.error and is_tls_reject(primary.error):
                fix = (f"服务器端问题，不是 DNS：{host} 的解析是对的，"
                       "但 Web 服务器没有为它配置站点或证书，握手阶段就被拒绝。\n"
                       f"Caddy：{host} {{\n    reverse_proxy 127.0.0.1:8080\n}}\n"
                       "证书需包含该域名；Poste.io 默认会把 autodiscover 路径挂在自己的 443 上。")
                recs: list[str] = []
            elif r.cname(host):
                fix = (f"{host} 已经能解析，但没有返回可用的 XML。"
                       "检查 Web 服务器是否把 /autodiscover/ 路径转发到了 Poste.io。")
                recs = []
            else:
                fix = (f"添加 CNAME：{host} → {t.mail_host}，"
                       "并确保 443 端口把该请求转发到 Poste.io。")
                recs = [f"{host}. 3600 IN CNAME {t.mail_host}."]
            col.fail("autodiscover_xml", "endpoint", title,
                     reason,
                     f"POST {primary_url} → {reason}\n"
                     f"（{len(urls)} 个候选路径均未返回可用的 XML）\n"
                     "Outlook 只认 Microsoft Autodiscover，这条不通就只能手工配置。",
                     fix, recs, weight=9, data={"url": primary_url})
        return

    url, res = good
    parsed = parse_autodiscover(res.body)
    if parsed["error"]:
        col.fail("autodiscover_xml", "endpoint", title, parsed["error"],
                 f"{url} 返回 200 但内容不可解析：\n{res.body[:300]}",
                 "确认反代没有把该路径重写为登录页。", weight=9)
        return

    imap = next((p for p in parsed["protocols"] if p["type"].upper() == "IMAP"), None)
    smtp = next((p for p in parsed["protocols"] if p["type"].upper() == "SMTP"), None)
    if not imap or not smtp:
        col.warn("autodiscover_xml", "endpoint", title,
                 "响应里缺少 IMAP 或 SMTP 定义",
                 f"来源：{url}\n返回的协议：{', '.join(p['type'] for p in parsed['protocols'])}",
                 "Poste.io 在 Host 头正确时会同时给出 IMAP 与 SMTP。",
                 weight=9, data={"url": url})
        return

    problems, notes = [], []
    for label, p in (("IMAP", imap), ("SMTP", smtp)):
        host = p["server"]
        if _looks_internal(host):
            problems.append(f"{label} 服务器是内网名「{host}」")
            continue
        resolved = r.resolve_any_address(host)
        if not resolved["ipv4"] and not resolved["ipv6"]:
            problems.append(f"{label} 服务器 {host} 无法解析")
        notes.append(f"{label}：{host}:{p['port']} SSL={p['ssl'] or '未声明'}")

    detail = f"来源：{url}\n" + "\n".join(notes + problems)
    if problems:
        col.fail("autodiscover_xml", "endpoint", title, problems[0], detail,
                 "检查反代的 Host 头透传。", weight=9,
                 data={"url": url, "config": parsed})
    else:
        col.ok("autodiscover_xml", "endpoint", title,
               "；".join(notes), detail, weight=9,
               data={"url": url, "config": parsed})


# ---------------------------------------------------------------- Autodiscover 命名空间

POX_NS = "autodiscover/outlook/responseschema/2006a"


def check_autodiscover_schema(t: Target, r: Resolver, col: Collector):
    """POX 响应的 <Response> 必须用 .../autodiscover/outlook/responseschema/2006a。

    Poste.io 在 <Response> 上少写了 /outlook/ 和末尾的 a，用的是根元素那个命名空间。
    按命名空间解析 XML 的客户端（BlueMail 就是）会找不到 Account/Protocol 节点，
    判定响应无效，转去试 ActiveSync、EWS，最后报「服务器错误」——症状表现为
    「同一个账号 Spark/Thunderbird 能配，BlueMail 不能」。
    """
    title = "Autodiscover 命名空间"
    url = f"https://autodiscover.{t.domain}/autodiscover/autodiscover.xml"
    res = http_fetch(url, timeout=9, resolver=r)  # 用 GET，与 BlueMail 的探测方式一致
    if res.error or res.status != 200:
        col.skip("autodiscover_schema", "endpoint", title,
                 f"端点不可用（{human_err(res.error) if res.error else 'HTTP %d' % res.status}），跳过")
        return

    body = res.body
    if POX_NS in body:
        col.ok("autodiscover_schema", "endpoint", title,
               "符合 POX 规范", f"{url}\n<Response> 命名空间正确。", weight=3)
        return

    declared = re.search(r"<Response[^>]*xmlns=\"([^\"]+)\"", body)
    ns = declared.group(1) if declared else "（未声明）"
    col.warn("autodiscover_schema", "endpoint", title,
             "命名空间不合规，部分客户端会解析失败",
             f"{url}\n实际声明的命名空间：{ns}\n规范要求的命名空间："
             f"http://schemas.microsoft.com/exchange/{POX_NS}\n"
             "严格按命名空间取节点的客户端（BlueMail 这类）会读不到 Account/Protocol，"
             "把响应判成无效，随后转去试 ActiveSync / EWS，最终只报「服务器错误」。",
             "在反代里用一段静态响应覆盖该路径（Caddy：handle + respond），"
             "内容与 Poste.io 一致但把 <Response> 的 xmlns 改成本表要求的值。",
             weight=4, data={"url": url, "namespace": ns})


# ---------------------------------------------------------------- Exchange ActiveSync

def check_eas(t: Target, r: Resolver, col: Collector):
    """探测 EAS 端点。

    Poste.io 内置 Z-Push。有些客户端（BlueMail 尤其明显）在云端配置探测拿不到
    协议时，会把「自建域名」当成 Exchange，直接去打 EAS 端点。若 Z-Push 的策略
    协商不被它接受，它只会报「服务器错误」，而不会回退到 IMAP——这是纯客户端
    行为，服务器这边通常没有配置错误。
    """
    url = f"https://{t.mail_host}/Microsoft-Server-ActiveSync"
    res = http_fetch(url, method="OPTIONS", timeout=8, resolver=r)

    if res.status in (401, 403):
        col.info("eas", "endpoint", "Exchange ActiveSync 端点",
                 "存在（Z-Push），会诱使 BlueMail 走 Exchange 分支",
                 f"{url} 返回 {res.status} + WWW-Authenticate，客户端会由此判定"
                 "「这是一台 Exchange 服务器」。\n"
                 "BlueMail 添加自建域名账号时，先查自家云端的服务商库；查不到就继续"
                 "按默认参数猜（143 明文 → 被 LOGINDISABLED 拒绝 → 改试 EAS）。"
                 "而 Z-Push 在带凭据的首次请求上回 449（设备策略协商），响应里不带"
                 "X-MS-PolicyKey，客户端无法继续，直接报告「服务器错误」。\n"
                 "实测结论：把 EAS 改成 404 也不能让它回退到 IMAP——它同样报错，"
                 "只是失败得更快。所以这类客户端在自动配置上无解，手动填一次即可。",
                 weight=0, data={"status": res.status})
    elif res.status == 404:
        col.info("eas", "endpoint", "Exchange ActiveSync 端点", "未启用（404）",
                 "没有 EAS 服务时，客户端不会往 Exchange 方向尝试，"
                 "反而更容易直接走 IMAP。", weight=0)
    else:
        col.info("eas", "endpoint", "Exchange ActiveSync 端点",
                 f"响应异常（{res.error or 'HTTP %d' % res.status}）",
                 f"{url} 未返回预期的认证响应。", weight=0)


# ---------------------------------------------------------------- 路径覆盖矩阵

# 不同客户端请求的路径不完全相同。只覆盖其中一部分时，就会出现
# 「Thunderbird 能配、BlueMail 不能」这种割裂现象，而配置文件本身是好的。
PATH_MATRIX = [
    ("thunderbird", "autoconfig 子域（Thunderbird / Spark 主路径）",
     "https://autoconfig.{d}/mail/config-v1.1.xml", True, False),
    ("wellknown", ".well-known 备选（部分客户端只试这条）",
     "https://{d}/.well-known/autoconfig/mail/config-v1.1.xml", True, True),
    ("outlook_lower", "autodiscover 小写路径（Outlook 标准）",
     "https://autodiscover.{d}/autodiscover/autodiscover.xml", True, False),
    ("outlook_upper", "Autodiscover 大写路径（BlueMail 等会试）",
     "https://autodiscover.{d}/Autodiscover/Autodiscover.xml", True, False),
    ("outlook_apex", "域名根下的 autodiscover（Outlook 第二顺位）",
     "https://{d}/autodiscover/autodiscover.xml", False, True),
]


def check_path_matrix(t: Target, r: Resolver, col: Collector):
    entries = [(k, label, url.format(d=t.domain), critical, apex)
               for k, label, url, critical, apex in PATH_MATRIX]

    # 顶点域名上的路径，只有在「顶点域名本身指向邮件服务器」时才可能被满足。
    # 自建邮箱常把 apex 留给官网、甚至撤掉 A 记录，此时这两条路径改多少反代都不通，
    # 属于「不适用」，不该算作缺失——否则会指导用户去修一个永远修不上的东西。
    _mail = r.resolve_any_address(t.mail_host)
    _apex = r.resolve_any_address(t.domain)
    apex_is_mail = bool((set(_mail["ipv4"]) | set(_mail["ipv6"]))
                        & (set(_apex["ipv4"]) | set(_apex["ipv6"])))

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(
            lambda e: (e, http_fetch(e[2], timeout=9, resolver=r)), entries))

    rows, missing, na = [], [], []
    for (key, label, url, critical, apex), res in results:
        if apex and not apex_is_mail:
            rows.append({"key": key, "label": label, "url": url, "ok": None,
                         "critical": critical,
                         "status": "顶点域名未指向邮件服务器，此路径不适用"})
            na.append(rows[-1])
            continue
        ok = (res.status == 200 and not res.error
              and len(res.body.strip()) > 40)
        rows.append({"key": key, "label": label, "url": url, "ok": ok,
                     "critical": critical,
                     "status": res.error or f"HTTP {res.status}"})
        if not ok:
            missing.append(rows[-1])

    def _mark(x):
        return "✓" if x["ok"] else ("–" if x["ok"] is None else "✗")

    title = "配置路径覆盖"
    if not missing:
        usable = len(rows) - len(na)
        note = f"{usable} 条适用路径全部可用"
        if na:
            note += f"（另有 {len(na)} 条位于顶点域名，而顶点域名不指向邮件服务器，不适用）"
        col.ok("path_matrix", "endpoint", title, note,
               "\n".join(f"  {_mark(x)} {x['label']}" for x in rows), weight=4,
               data={"paths": rows})
        return

    critical_missing = [x for x in missing if x["critical"]]
    detail = "客户端各试各的路径，缺一条就可能有一批客户端配不上：\n" + \
             "\n".join(f"  {_mark(x)} {x['label']}" for x in rows)

    fixes = []
    if any(x["key"] == "wellknown" for x in missing):
        fixes.append("把 /.well-known/autoconfig/mail/config-v1.1.xml 转发到 "
                     "/mail/config-v1.1.xml（Caddy 用 rewrite）")
    if any(x["key"] == "outlook_upper" for x in missing):
        fixes.append("把 /Autodiscover/Autodiscover.xml 转发到 "
                     "/autodiscover/autodiscover.xml（Caddy 用 rewrite）")

    if critical_missing:
        col.fail("path_matrix", "endpoint", title,
                 f"{len(missing)} 条路径不可用，部分客户端会配不上",
                 detail, "；\n".join(fixes) or "检查反代是否只转发了部分路径",
                 weight=4, data={"paths": rows})
    else:
        col.warn("path_matrix", "endpoint", title,
                 f"标准路径可用，但有 {len(missing)} 条变体路径缺失",
                 detail + "\n\n主路径正常，所以多数客户端没问题；"
                 "但 BlueMail 这类会去试大写路径或 .well-known 的客户端可能失败。",
                 "；\n".join(fixes), weight=3, data={"paths": rows})


# ---------------------------------------------------------------- Apple / iOS

def check_mobileconfig(t: Target, r: Resolver, col: Collector):
    urls = [
        f"https://{t.domain}/.well-known/mobileconfig",
        f"https://autoconfig.{t.domain}/email/mobileconfig.xml?email={t.email}",
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda u: http_fetch(u, timeout=8, resolver=r), urls))

    for url, res in zip(urls, results):
        if res.status == 200 and not res.error and res.body.strip():
            col.ok("mobileconfig", "endpoint", "iOS 配置描述文件",
                   f"可用（{url.split('//')[1].split('/')[0]}）",
                   f"Apple 设备可以通过 {url} 拿到配置。", weight=4,
                   data={"url": url})
            return
    col.info("mobileconfig", "endpoint", "iOS 配置描述文件",
             "未提供（非必需）",
             "iOS 14+ 主要依靠 SRV 记录与 autoconfig，mobileconfig 只是备选，缺失不影响 iPhone 自动配置。",
             weight=0)


# ---------------------------------------------------------------- MTA-STS 策略文件

def check_mta_sts_policy(t: Target, r: Resolver, col: Collector,
                         mx_hosts: list[str] | None = None):
    txts = r.txt(f"_mta-sts.{t.domain}")
    published = [x for x in txts if x.upper().startswith("V=STSV1")]
    if not published:
        col.skip("mta_sts_policy", "endpoint", "MTA-STS 策略文件", "未启用 MTA-STS")
        return

    url = f"https://mta-sts.{t.domain}/.well-known/mta-sts.txt"
    res = http_fetch(url, timeout=8, resolver=r)
    if res.error or res.status != 200:
        col.warn("mta_sts_policy", "endpoint", "MTA-STS 策略文件",
                 f"DNS 已发布但策略文件取不到（{res.error or 'HTTP %d' % res.status}）",
                 f"请求 {url} 失败。DNS 声明了 MTA-STS 却没有对应的 HTTPS 策略文件时，"
                 "严格校验的收件方会拒收你的邮件。",
                 f"在 mta-sts.{t.domain} 上提供 /.well-known/mta-sts.txt，或删掉 _mta-sts 的 TXT 记录。",
                 weight=5, data={"url": url})
        return

    body = res.body
    mx_lines = re.findall(r"^mx:\s*(\S+)", body, re.M | re.I)
    mode = (re.search(r"^mode:\s*(\w+)", body, re.M | re.I) or [None, ""])[1]
    expected = {h.lower().rstrip(".") for h in (mx_hosts or [t.mail_host])}
    declared = {m.lower().rstrip(".") for m in mx_lines}

    def _matches() -> bool:
        # MTA-STS 允许 mx 写成通配符，例如 mx: *.example.com
        for d in declared:
            for e in expected:
                if d == e:
                    return True
                if d.startswith("*.") and e.endswith(d[1:]):
                    return True
        return False

    if not _matches():
        col.warn("mta_sts_policy", "endpoint", "MTA-STS 策略文件",
                 f"策略里的 mx 不含你的 MX 目标",
                 f"来源：{url}\nmode={mode}\nmx={', '.join(mx_lines) or '（无）'}\n"
                 f"你的 MX 指向：{', '.join(sorted(expected))}\n"
                 "声明错误的 MX 会让严格校验的收件方拒绝对你服务器的投递。",
                 f"把 mx: 改为 {t.mail_host}", weight=5)
    else:
        col.ok("mta_sts_policy", "endpoint", "MTA-STS 策略文件",
               f"mode={mode}，mx 匹配", f"来源：{url}", weight=5)
