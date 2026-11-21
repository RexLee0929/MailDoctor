"""真实账号登录验证。

只做「登录 + 选收件箱」，绝不发信——避免把诊断变成一次真实的投递，
也避免被人拿来当群发通道。
"""
from __future__ import annotations

import imaplib
import smtplib
import ssl

from . import model
from .model import Collector, Target
from .netutil import human_err

TIMEOUT = 12


def _imap_login(t: Target) -> tuple[bool, str]:
    ctx = ssl.create_default_context()
    attempts = [
        (t.mail_host, 993, True),
        (t.mail_host, 143, False),
    ]
    errors: list[str] = []
    for host, port, implicit in attempts:
        try:
            if implicit:
                conn = imaplib.IMAP4_SSL(host, port, ssl_context=ctx, timeout=TIMEOUT)
            else:
                conn = imaplib.IMAP4(host, port, timeout=TIMEOUT)
                try:
                    conn.starttls(ssl_context=ctx)
                except Exception:  # noqa: BLE001
                    conn.shutdown()
                    continue
            try:
                conn.login(t.email, t.password)
                typ, data = conn.select("INBOX", readonly=True)
                if typ != "OK":
                    return True, f"登录成功，但无法打开 INBOX（{typ}）"
                n = 0
                try:
                    n = int(data[0]) if data and data[0] else 0
                except (TypeError, ValueError):
                    n = 0
                return True, f"端口 {port} 登录成功，INBOX 可读（{n} 封）"
            finally:
                try:
                    conn.logout()
                except Exception:  # noqa: BLE001
                    pass
        except imaplib.IMAP4.error as exc:
            msg = exc.args[0] if exc.args else str(exc)
            text = msg.decode("utf-8", "replace") if isinstance(msg, bytes) else str(msg)
            errors.append(f"{port} 端口：{text[:90]}")
        except (OSError, ssl.SSLError) as exc:
            errors.append(f"{port} 端口：{human_err(str(exc))}")
    return False, "；".join(errors) or "993 / 143 均不可用"


def _smtp_auth(t: Target) -> tuple[bool, str]:
    """只测 587 / 465。

    25 端口是收信端口，多数云厂商封禁、Poste.io 也不鼓励用它提交，
    把它混进来只会让报错信息失真。
    """
    ctx = ssl.create_default_context()
    attempts = [(587, "starttls"), (465, "ssl")]
    errors: list[str] = []
    for port, mode in attempts:
        try:
            if mode == "ssl":
                conn = smtplib.SMTP_SSL(t.mail_host, port, timeout=TIMEOUT, context=ctx)
            else:
                conn = smtplib.SMTP(t.mail_host, port, timeout=TIMEOUT)
                conn.ehlo()
                conn.starttls(context=ctx)
                conn.ehlo()
            try:
                conn.login(t.email, t.password)
                mechs = ""
                try:
                    mechs = " ".join(sorted(conn.esmtp_features.get("auth", "").split()))
                except Exception:  # noqa: BLE001
                    pass
                return True, f"端口 {port} 认证成功" + (f"（可用机制：{mechs}）" if mechs else "")
            finally:
                try:
                    conn.quit()
                except Exception:  # noqa: BLE001
                    pass
        except smtplib.SMTPAuthenticationError as exc:
            detail = exc.smtp_error
            if isinstance(detail, bytes):
                detail = detail.decode("utf-8", "replace")
            errors.append(f"{port} 端口认证被拒（{str(detail)[:80]}）")
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            errors.append(f"{port} 端口：{human_err(str(exc))}")
    return False, "；".join(errors) or "587 / 465 均不可用"


def check_account(t: Target, col: Collector):
    if not t.password:
        col.skip("imap_login", "account", "IMAP 登录", "未填写密码，跳过实测")
        col.skip("smtp_auth", "account", "SMTP 认证", "未填写密码，跳过实测")
        return

    ok, msg = _imap_login(t)
    if ok:
        col.ok("imap_login", "account", "IMAP 登录", msg,
               f"账号 {t.email} 在 {t.mail_host} 上认证通过。", weight=6)
    else:
        hint = ("Poste.io 默认允许密码认证；如果这里被拒但手工能登，"
                "多半是客户端用了不支持的认证机制。")
        col.fail("imap_login", "account", "IMAP 登录", msg,
                 f"账号 {t.email} 登录失败：{msg}",
                 "确认邮箱地址与密码正确。若账号启用了额外保护，需要在 Poste.io 后台检查。\n" + hint,
                 weight=6)

    ok2, msg2 = _smtp_auth(t)
    if ok2:
        col.ok("smtp_auth", "account", "SMTP 认证", msg2,
               f"账号 {t.email} 可以通过 SMTP 提交邮件（未实际发送）。", weight=6)
    elif ok and "超时" in msg2 and "拒绝" not in msg2:
        # 同一台服务器：IMAP 通、SMTP 超时 —— 服务器防火墙不会只挑端口丢包
        col.fail("smtp_auth", "account", "SMTP 认证",
                 "IMAP 通但 SMTP 超时，问题在你本地网络，不在服务器",
                 f"同一台 {t.mail_host}：993 端口能登录，587/465 却超时。\n"
                 "服务器的防火墙要么全通要么全不通，不会精准地只丢 SMTP 端口——"
                 "这种「按端口选择性超时」几乎都发生在客户端这一侧的链路上。\n"
                 "最常见的原因：代理软件的 TUN / 全局模式把邮件流量交给了代理节点，"
                 "而节点所在的 VPS 商普遍封禁 SMTP 出站端口（25/465/587 是垃圾邮件重灾区）。\n"
                 f"实测结果：{msg2}",
                 "先关掉 TUN / 全局代理再测一次——如果立刻通过，就坐实了本地链路问题。\n"
                 "根治办法是让邮件服务器绕开代理：\n"
                 f"  规则加 DOMAIN-SUFFIX,{t.domain},DIRECT\n"
                 f"  或 IP-CIDR,<邮件服务器公网IP>/32,DIRECT\n"
                 "Clash 用户也可以把 Spark / BlueMail 的进程规则设为 DIRECT。",
                 weight=6)
    else:
        col.fail("smtp_auth", "account", "SMTP 认证", msg2,
                 f"账号 {t.email} 的 SMTP 认证失败：{msg2}\n"
                 "自动配置即使成功，发信还是会卡在这一步。",
                 "检查 587/465 是否开放，以及 Poste.io 是否允许该账号通过 SMTP 发信。",
                 weight=6)
