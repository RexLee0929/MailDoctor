"""报告汇总：评分、客户端矩阵、可复制的 DNS 记录清单。"""
from __future__ import annotations

from . import model
from .model import Collector, GROUPS, Target, client_matrix, score_items

STATUS_LABEL = {model.PASS: "已就绪", model.WARN: "建议改进", model.FAIL: "需要修复",
                model.INFO: "提示", model.SKIP: "未检查"}
STATUS_MARK = {model.PASS: "✓", model.WARN: "!", model.FAIL: "✗", model.INFO: "i", model.SKIP: "-"}


def _dedup(records: list[str]) -> list[str]:
    seen, out = set(), []
    for rec in records:
        key = " ".join(rec.split()).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


def _zone_text(target: Target, col: Collector) -> str:
    """生成可直接对照的 zone 片段，标注每条的当前状态。"""
    lines = [
        f"; ── MailDoctor 诊断结果 ── {target.domain}",
        f"; 邮件服务器：{target.mail_host}",
        "; 标注：✓=已正确配置   ✗=需要添加/修正",
    ]
    seen: set[str] = set()
    for gid, gtitle, _ in GROUPS:
        items = [c for c in col.by_group(gid) if c.records]
        if not items:
            continue
        block: list[str] = []
        for c in items:
            mark = "✓" if c.status == model.PASS else "✗"
            for rec in c.records:
                key = " ".join(rec.split()).lower()
                if key in seen:  # 同一条记录可能被多个检查项引用，只保留一次
                    continue
                seen.add(key)
                block.append(f"{rec:<62} ; {mark} {c.title}")
        if block:
            lines.append("")
            lines.append(f"; ══ {gtitle} ══")
            lines.extend(block)
    lines.append("")
    lines.append("; 注意：PTR 反向解析不在 DNS 解析商处配置，")
    lines.append(f"; 需在云服务器/VPS 控制台把公网 IP 的反向解析设为 {target.mail_host}。")
    return "\n".join(lines)


def _verdict(clients: list[dict], score: int, fail_count: int = 0,
             guess: dict | None = None) -> tuple[str, str]:
    ok = [c for c in clients if c["status"] == model.PASS]
    warn = [c for c in clients if c["status"] == model.WARN]
    bad = [c for c in clients if c["status"] == model.FAIL]
    guessed = [c["name"] for c in clients if c.get("guessed")]

    if not bad and len(ok) == len(clients):
        if fail_count:
            return ("主流客户端就绪",
                    f"六类客户端的主路径都通，另有 {fail_count} 项细节问题——"
                    "通常不影响 Thunderbird / Outlook / Spark，但像 BlueMail 这种"
                    "探测方式特殊的客户端可能因此失败，建议一并处理。")
        return ("全链路就绪",
                "所有主流客户端的自动配置通道都能走通，BlueMail、Spark、Apple Mail、"
                "Outlook、Thunderbird 只需输入邮箱和密码即可完成配置。")
    if not ok and guessed:
        host = (guess or {}).get("host", "mail.<域名>")
        return ("可凭惯例配置，标准链路缺失",
                f"autoconfig / autodiscover / SRV 这三条标准发现链路都不通，"
                f"但 {host} 能解析、端口与证书正常，多数客户端会直接按 "
                f"「mail.域名 + 993/587」的惯例猜中并配置成功——"
                f"BlueMail、Spark 这类就是这样，实测可用。\n"
                "它影响的是两类客户端：一类完全不猜、只认标准发现（部分 Outlook 配置、"
                "企业策略管控的设备），另一类是猜错端口的（例如默认 143 明文）。"
                "补齐下面几条记录后，这两类也能自动配置。")
    if len(ok) + len(warn) >= len(clients) - 1:
        names = "、".join(c["name"] for c in ok) or "部分客户端"
        return ("基本可用",
                f"{names} 可以自动配置，但还有 {len(bad)} 个客户端会失败："
                + "、".join(c["name"] for c in bad) + "。按下面的清单补齐即可。")
    if not ok:
        return ("自动配置不可用",
                "目前没有客户端能自动发现服务器配置，且邮件主机名不遵循可被推断的惯例，"
                "所有客户端都会退回到手动填写。核心问题在 autoconfig/autodiscover 域名、"
                "SRV 记录或证书。")
    return ("部分可用",
            f"只有 {len(ok)} 个客户端能自动配置（{'、'.join(c['name'] for c in ok)}），"
            "其余需要补齐相应记录。")


def build_summary(target: Target, col: Collector, elapsed: float) -> dict:
    overall = col.score()
    groups = []
    for gid, gtitle, gdesc in GROUPS:
        items = col.by_group(gid)
        stats = score_items(items)
        groups.append({
            "id": gid,
            "title": gtitle,
            "desc": gdesc,
            "percent": stats["percent"],
            "counts": stats["counts"],
        })

    status_map = {c.id: c.status for c in col.items}
    # 惯例猜测：邮件主机名可解析 + 关键端口开放 + 证书有效 → 多数客户端会直接猜中
    guess = {
        "ok": all(status_map.get(k) == model.PASS
                  for k in ("a_record", "ports", "tls_mail")),
        "host": target.mail_host,
    }
    clients = client_matrix(status_map, guess)

    todo = _dedup([r for c in col.items
                   if c.status in (model.FAIL, model.WARN) for r in c.records])

    issues = sorted(
        [c for c in col.items if c.status in (model.FAIL, model.WARN)],
        key=lambda c: (c.status != model.FAIL, -c.weight))

    top = [{
        "id": c.id,
        "title": c.title,
        "status": c.status,
        "summary": c.summary,
        "fix": c.fix,
    } for c in issues[:4]]

    title, desc = _verdict(clients, overall["percent"],
                           overall["counts"].get(model.FAIL, 0), guess)

    return {
        "target": {
            "domain": target.domain,
            "mail_host": target.mail_host,
            "email": target.email if target.password else "",
        },
        "elapsed": elapsed,
        "score": overall,
        "groups": groups,
        "clients": clients,
        "items": [c.to_dict() for c in col.items],
        "todo_records": todo,
        "zone": _zone_text(target, col),
        "verdict": {"title": title, "desc": desc},
        "top_issues": top,
    }
