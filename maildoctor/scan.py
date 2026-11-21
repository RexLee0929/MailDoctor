"""一次完整扫描的编排。"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from . import checks_auth as AUTH
from . import checks_autoconf as CONF
from . import checks_dns as DNS
from . import checks_tls as TLS
from . import model
from .dnsq import Resolver
from .model import Collector, GROUPS, Target, score_items
from .report import build_summary


def _group_payload(items: list[model.Check]) -> dict:
    stats = score_items(items)
    return {"items": [c.to_dict() for c in items],
            "percent": stats["percent"],
            "counts": stats["counts"]}


def _emit_group(col: Collector, group: str, emit, done_groups: list[str]) -> None:
    items = col.by_group(group)
    if not items:
        return
    done_groups.append(group)
    if emit:
        payload = _group_payload(items)
        payload.update({
            "type": "group",
            "group": group,
            "title": model.GROUP_TITLE[group],
            "desc": model.GROUP_DESC[group],
            "progress": round(len(done_groups) / len(GROUPS), 3),
        })
        emit(payload)


def run_scan(target: Target, emit=None, with_account: bool = False) -> dict:
    """执行全链路扫描。emit 会以事件形式陆续推送每个分组的结果。"""
    started = time.time()
    resolver = Resolver(timeout=6)
    col = Collector()
    done: list[str] = []

    # 没指定邮件主机时：优先 mail.<域名>，解析不到就回退到 MX 目标
    notice = ""
    if target.auto_host:
        probe = resolver.resolve_any_address(target.mail_host)
        if not probe["ipv4"] and not probe["ipv6"]:
            mx_pre = resolver.mx(target.domain)
            if mx_pre:
                target.mail_host = mx_pre[0][1]
                notice = (f"mail.{target.domain} 没有 A 记录，"
                          f"已自动改用 MX 指向的 {target.mail_host}")

    if emit:
        emit({"type": "start", "domain": target.domain, "mail_host": target.mail_host,
              "total_groups": len(GROUPS), "notice": notice})

    # ---- 1. 收信与投递
    mx = DNS.check_mx(target, resolver, col)
    mailinfo = DNS.check_mail_host_a(target, resolver, col)
    DNS.check_ptr(target, mx, resolver, col)
    mail_ips = mailinfo.get("ips") or []
    _emit_group(col, "delivery", emit, done)

    # ---- 2. 发信认证
    DNS.check_spf(target, resolver, col, mail_ips)
    DNS.check_dkim(target, resolver, col)
    DNS.check_dmarc(target, resolver, col)
    DNS.check_extra_auth(target, resolver, col)
    _emit_group(col, "auth", emit, done)

    # ---- 3. 服务发现
    DNS.check_srv(target, resolver, col)
    DNS.check_autodiscover_dns(target, resolver, col, mail_ips)
    _emit_group(col, "discovery", emit, done)

    # ---- 4/5. 端点与传输并行（这两个都要联网握手，最慢）
    mx_hosts = [h for _, h in mx]
    col_conf = Collector()
    col_tls = Collector()

    def run_endpoints():
        CONF.check_mozilla(target, resolver, col_conf)
        CONF.check_autodiscover(target, resolver, col_conf)
        CONF.check_autodiscover_schema(target, resolver, col_conf)
        CONF.check_path_matrix(target, resolver, col_conf)
        CONF.check_eas(target, resolver, col_conf)
        CONF.check_mobileconfig(target, resolver, col_conf)
        CONF.check_mta_sts_policy(target, resolver, col_conf, mx_hosts)

    def run_transport():
        by_port = TLS.check_ports(target, col_tls, mail_ips)
        TLS.check_certs(target, resolver, col_tls, by_port)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_conf = pool.submit(run_endpoints)
        fut_tls = pool.submit(run_transport)
        fut_conf.result()
        fut_tls.result()

    # 按固定顺序合并，避免并发导致报告顺序跳动
    for c in col_conf.items:
        col.add(c)
    _emit_group(col, "endpoint", emit, done)
    for c in col_tls.items:
        col.add(c)
    _emit_group(col, "transport", emit, done)

    # ---- 6. 账号实测
    if with_account:
        AUTH.check_account(target, col)
    else:
        col.skip("imap_login", "account", "IMAP 登录", "未提供账号密码")
        col.skip("smtp_auth", "account", "SMTP 认证", "未提供账号密码")
    _emit_group(col, "account", emit, done)

    summary = build_summary(target, col, round(time.time() - started, 1))
    if emit:
        emit({"type": "done", **summary})
    return summary
