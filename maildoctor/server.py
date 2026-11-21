"""本地 / 公网 Web 服务。

- 静态资源：web/ 目录
- POST /api/scan：请求体 JSON，响应 text/event-stream，逐个分组推送结果
- 公网模式（--public）启用限流与内网目标拦截，避免被当成 DNS/端口扫描代理
"""
from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .dnsq import Resolver
from .model import Target
from .netutil import is_public_ip
from .scan import run_scan

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

# 「关于」的文案唯一来源是根目录 ABOUT.md，这里只做占位符替换。
# 版本号同理只有一处：maildoctor/__init__.py 的 __version__。
ABOUT_FILE = WEB_DIR.parent / "ABOUT.md"
APP_NAME = "MailDoctor"
AUTHOR = "Rex Lee"
AUTHOR_EMAIL = "rexlee@rexleepro.com"
TAGLINE = "自建邮箱 · DNS 与自动配置体检"

DOMAIN_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
    ".woff2": "font/woff2",
}


class ClientGone(Exception):
    """浏览器断开连接。"""


def about_payload() -> dict:
    """返回「关于」文案。md 原文 + 元数据，渲染交给前端，避免文案散落在代码里。"""
    try:
        text = ABOUT_FILE.read_text(encoding="utf-8")
    except OSError:
        text = (f"## **{APP_NAME}** **{__version__}**\n\n{TAGLINE}\n\n"
                f"免费软件，依据 MIT License 分发。\n© 2026 {AUTHOR}　保留所有权利。")
    for key, val in (("{NAME}", APP_NAME), ("{VERSION}", __version__),
                     ("{AUTHOR}", AUTHOR), ("{TAGLINE}", TAGLINE)):
        text = text.replace(key, val)
    return {"markdown": text, "name": APP_NAME, "version": __version__,
            "author": AUTHOR, "email": AUTHOR_EMAIL, "tagline": TAGLINE}


class RateLimiter:
    def __init__(self, per_ip: int = 6, window: int = 60):
        self.per_ip = per_ip
        self.window = window
        self.hits: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.time()
        with self.lock:
            stamps = [t for t in self.hits.get(ip, []) if now - t < self.window]
            if len(stamps) >= self.per_ip:
                self.hits[ip] = stamps
                return False
            stamps.append(now)
            self.hits[ip] = stamps
            return True


class App:
    def __init__(self, public: bool = False, max_concurrent: int = 6):
        self.public = public
        self.limiter = RateLimiter(per_ip=4 if public else 60, window=60)
        self.sem = threading.Semaphore(max_concurrent)


APP: App = App()


class Handler(BaseHTTPRequestHandler):
    server_version = f"MailDoctor/{__version__}"
    protocol_version = "HTTP/1.1"

    # ---------------- 基础响应
    def log_message(self, fmt, *args):  # 精简访问日志
        if APP.public:
            return
        print(f"  {self.address_string()} {fmt % args}")

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, payload: dict):
        self._send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _serve_static(self, rel: str):
        if not rel or rel == "/":
            rel = "index.html"
        rel = rel.lstrip("/")
        target = (WEB_DIR / rel).resolve()
        try:
            target.relative_to(WEB_DIR)
        except ValueError:
            self._json(403, {"error": "forbidden"})
            return
        if not target.is_file():
            self._json(404, {"error": "not found"})
            return
        ctype = MIME.get(target.suffix.lower(), "application/octet-stream")
        self._send(200, target.read_bytes(), ctype,
                   {"Cache-Control": "no-cache"})

    # ---------------- 路由
    def do_GET(self):  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/api/health":
            self._json(200, {"ok": True, "version": __version__, "public": APP.public})
            return
        if path == "/api/about":
            self._json(200, about_payload())
            return
        if path.startswith("/api/"):
            self._json(404, {"error": "unknown api"})
            return
        self._serve_static(path)

    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def do_POST(self):  # noqa: N802
        path = urlsplit(self.path).path
        if path != "/api/scan":
            self._json(404, {"error": "unknown api"})
            return

        ip = self.client_address[0]
        if not APP.limiter.allow(ip):
            self._json(429, {"error": "请求太频繁，请稍后再试"})
            return

        try:
            length = int(self.headers.get("content-length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 32 * 1024:
            self._json(400, {"error": "请求体为空或过大"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._json(400, {"error": "请求体不是合法 JSON"})
            return

        domain = str(payload.get("domain") or "").strip().lower()
        if not DOMAIN_RE.match(domain):
            self._json(400, {"error": "域名格式不正确，例如 example.com"})
            return

        target = Target(
            domain=domain,
            mail_host=str(payload.get("mail_host") or "").strip(),
            dkim_selector=str(payload.get("dkim_selector") or "").strip(),
            email=str(payload.get("email") or "").strip(),
            password=str(payload.get("password") or ""),
        )

        if APP.public:
            problem = self._blocked_target(target)
            if problem:
                self._json(403, {"error": problem})
                return

        if not APP.sem.acquire(blocking=False):
            self._json(503, {"error": "当前排队任务较多，请稍后再试"})
            return
        try:
            self._stream_scan(target)
        finally:
            APP.sem.release()

    # ---------------- 安全
    def _blocked_target(self, t: Target) -> str:
        """公网模式：拒绝指向内网的扫描目标。"""
        r = Resolver(timeout=5)
        for host in {t.domain, t.mail_host}:
            res = r.resolve_any_address(host)
            for ip in res["ipv4"] + res["ipv6"]:
                if not is_public_ip(ip):
                    return f"{host} 解析到内网地址 {ip}，公网实例不允许扫描。"
        return ""

    # ---------------- SSE
    def _stream_scan(self, target: Target):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(event: dict):
            data = "data: " + json.dumps(event, ensure_ascii=False) + "\n\n"
            try:
                self.wfile.write(data.encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError) as exc:
                raise ClientGone() from exc

        try:
            run_scan(target, emit=emit, with_account=bool(target.password))
        except ClientGone:
            pass
        except Exception as exc:  # noqa: BLE001
            try:
                emit({"type": "error", "message": f"扫描中断：{exc}"})
            except ClientGone:
                pass
        finally:
            try:
                self.wfile.write(b"data: {\"type\":\"eof\"}\n\n")
                self.wfile.flush()
            except Exception:  # noqa: BLE001
                pass
            self.close_connection = True


def serve(host: str = "127.0.0.1", port: int = 8787, public: bool = False,
          max_concurrent: int = 6, open_browser: bool = False):
    global APP
    APP = App(public=public, max_concurrent=max_concurrent)
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{shown}:{port}/"
    print(f"MailDoctor {__version__}")
    print(f"  → {url}")
    if public:
        print("  公网模式：已启用限流与内网目标拦截")
    print("  Ctrl+C 停止")

    if open_browser:
        import webbrowser
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        httpd.server_close()
