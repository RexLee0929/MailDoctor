"""检查项的数据模型、目标上下文与评分。"""
from __future__ import annotations

from dataclasses import dataclass, field

PASS = "pass"
WARN = "warn"
FAIL = "fail"
INFO = "info"
SKIP = "skip"

SCORE = {PASS: 1.0, WARN: 0.5, FAIL: 0.0}
RANK = {FAIL: 0, WARN: 1, PASS: 2, INFO: 3, SKIP: 4}

GROUPS = [
    ("delivery", "收信与投递", "MX、A、PTR——决定别人能不能把信送到你的服务器"),
    ("auth", "发信认证", "SPF、DKIM、DMARC——决定你的信会不会进垃圾箱"),
    ("discovery", "服务发现", "SRV 与 autoconfig/autodiscover 记录——决定客户端能否找到服务器"),
    ("endpoint", "自动配置端点", "实际抓取 XML 配置文件并校验内容"),
    ("transport", "端口与证书", "客户端要连的端口是否开放、证书是否覆盖这些域名"),
    ("account", "账号实测", "用真实账号走一遍登录流程"),
]

GROUP_TITLE = {g: t for g, t, _ in GROUPS}
GROUP_DESC = {g: d for g, _, d in GROUPS}


@dataclass
class Target:
    """一次扫描的目标。mail_host 留空时自动推导。"""
    domain: str
    mail_host: str = ""
    dkim_selector: str = ""
    email: str = ""
    password: str = ""
    auto_host: bool = False   # 用户没指定邮件主机，允许扫描时回退到 MX

    def __post_init__(self):
        self.domain = self.domain.strip().strip(".").lower()
        if not self.mail_host:
            self.mail_host = f"mail.{self.domain}"
            self.auto_host = True
        else:
            self.mail_host = self.mail_host.strip().strip(".").lower()
            self.auto_host = False
        self.dkim_selector = self.dkim_selector.strip().strip(".")
        if not self.email:
            self.email = f"postmaster@{self.domain}"


@dataclass
class Check:
    id: str
    group: str
    title: str
    status: str
    summary: str = ""
    detail: str = ""
    fix: str = ""
    records: list[str] = field(default_factory=list)
    weight: float = 1.0
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "group": self.group,
            "title": self.title,
            "status": self.status,
            "summary": self.summary,
            "detail": self.detail,
            "fix": self.fix,
            "records": self.records,
            "weight": self.weight,
            "data": self.data,
        }


def score_items(items: list[Check]) -> dict:
    """按权重计算完成度。INFO / SKIP 不计入分母。"""
    total = 0.0
    got = 0.0
    counts = {PASS: 0, WARN: 0, FAIL: 0, INFO: 0, SKIP: 0}
    for c in items:
        counts[c.status] = counts.get(c.status, 0) + 1
        if c.status in (INFO, SKIP) or c.weight <= 0:
            continue
        total += c.weight
        got += c.weight * SCORE.get(c.status, 0.0)
    pct = round(100 * got / total) if total else 100
    return {"percent": pct, "counts": counts, "weight": round(total, 1)}


class Collector:
    """收集检查结果。"""
    def __init__(self):
        self.items: list[Check] = []

    def add(self, check: Check) -> Check:
        self.items.append(check)
        return check

    def ok(self, cid, group, title, summary="", detail="", records=None, weight=1.0, data=None):
        return self.add(Check(cid, group, title, PASS, summary, detail, "",
                              records or [], weight, data or {}))

    def warn(self, cid, group, title, summary="", detail="", fix="", records=None,
             weight=1.0, data=None):
        return self.add(Check(cid, group, title, WARN, summary, detail, fix,
                              records or [], weight, data or {}))

    def fail(self, cid, group, title, summary="", detail="", fix="", records=None,
             weight=1.0, data=None):
        return self.add(Check(cid, group, title, FAIL, summary, detail, fix,
                              records or [], weight, data or {}))

    def info(self, cid, group, title, summary="", detail="", records=None, weight=0.0,
             data=None):
        return self.add(Check(cid, group, title, INFO, summary, detail, "",
                              records or [], weight, data or {}))

    def skip(self, cid, group, title, summary="", weight=0.0):
        return self.add(Check(cid, group, title, SKIP, summary, "", "", [], weight, {}))

    def by_group(self, group: str) -> list[Check]:
        return [c for c in self.items if c.group == group]

    def score(self) -> dict:
        return score_items(self.items)


# ---------------------------------------------------------------- 客户端能力矩阵

# 每个客户端支持哪些自动发现通道。
# 语义：内层列表 = 必须同时满足的一组；外层列表 = 任一组满足即可。
# 例：[["srv_imap","srv_submission"]] 表示 SRV 必须同时给出收信与发信服务。
CLIENTS = [
    {
        "id": "thunderbird",
        "name": "Thunderbird",
        "channels": [["autoconfig_xml"], ["autoconfig_wellknown"]],
        "note": "读 Mozilla autoconfig XML，两个路径任一可用即可",
    },
    {
        "id": "bluemail",
        "name": "BlueMail",
        "channels": [["autodiscover_xml"], ["autoconfig_xml"], ["autoconfig_wellknown"],
                     ["srv_imap", "srv_submission"]],
        "note": "按 Autodiscover → autoconfig → SRV 的顺序回退",
    },
    {
        "id": "spark",
        "name": "Spark Mail",
        "channels": [["autodiscover_xml"], ["autoconfig_xml"], ["autoconfig_wellknown"],
                     ["srv_imap", "srv_submission"]],
        "note": "与 BlueMail 同源策略，依赖 Autodiscover/autoconfig",
    },
    {
        "id": "apple",
        "name": "Apple Mail / iOS",
        "channels": [["srv_imap", "srv_submission"], ["mobileconfig"]],
        "note": "优先 RFC 6186 SRV 记录",
    },
    {
        "id": "outlook",
        "name": "Outlook",
        "channels": [["autodiscover_xml"], ["srv_autodiscover"]],
        "note": "只认 Microsoft Autodiscover",
    },
    {
        "id": "k9",
        "name": "K-9 / FairEmail",
        "channels": [["srv_imap", "srv_submission"]],
        "note": "依赖 RFC 6186 SRV 记录",
    },
]


def client_matrix(status_map: dict[str, str], guess: dict | None = None) -> list[dict]:
    """根据各通道状态计算客户端可用性。

    status_map: check_id -> status
    每个客户端列出多条可用通道，命中任意一条即可自动配置。

    guess: 惯例猜测的可用性 {"ok": bool, "host": str}。当标准发现链路全断、但
    邮件主机名符合 mail.<域名> 惯例且端口/证书正常时，多数客户端会靠内置猜测
    直接连上——这种情况下判 FAIL 会与实际体验矛盾（BlueMail/Spark 就是这样）。
    """
    out = []
    guess_ok = bool(guess and guess.get("ok"))
    for cli in CLIENTS:
        best = FAIL
        matched: list[str] = []
        failed_at = None
        for channel in cli["channels"]:
            states = [(c, status_map.get(c, SKIP)) for c in channel]
            if all(s == PASS for _, s in states):
                best, matched, failed_at = PASS, list(channel), None
                break
            if all(s in (PASS, WARN) for _, s in states):
                if best != PASS:
                    best, matched = WARN, list(channel)
                continue
            if failed_at is None:
                failed_at = next((c for c, s in states if s not in (PASS, WARN)), channel[0])
        if best == FAIL and guess_ok:
            best, matched = WARN, ["guess"]
        out.append({
            "id": cli["id"],
            "name": cli["name"],
            "note": cli["note"],
            "status": best,
            "via": matched,
            "failed_at": failed_at if best == FAIL else None,
            "guessed": best == WARN and matched == ["guess"],
        })
    return out
