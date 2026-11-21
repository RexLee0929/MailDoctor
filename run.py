#!/usr/bin/env python3
"""MailDoctor 启动入口。

    python run.py                       # 本地打开 http://127.0.0.1:8787
    python run.py --host 0.0.0.0 --port 8080 --public
                                        # 部署到服务器，启用限流与内网拦截
    python run.py --cli example.com     # 命令行输出纯文本报告

只用标准库，不需要 pip install 任何东西。
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:  # Windows 控制台默认 GBK，中文输出会炸；line_buffering 保证重定向到文件时也能实时看到
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:  # noqa: BLE001
    pass

ICON = {"pass": "✓", "warn": "!", "fail": "✗", "info": "i", "skip": "-"}


class Tee:
    """stdout 同时写控制台和文件。

    Docker 的 json-file 驱动由守护进程持有，没法映射到宿主机目录；
    要在 ./logs 里看到日志，只能由程序自己落盘。默认不启用，行为不变。
    超过 max_bytes 时把当前文件改名成 .1（只留一份），避免无限增长。
    """

    def __init__(self, stream, path: str, max_bytes: int = 10 * 1024 * 1024):
        self._stream = stream
        self._path = path
        self._max = max_bytes
        self._fh = None
        try:
            folder = os.path.dirname(os.path.abspath(path))
            if folder:
                os.makedirs(folder, exist_ok=True)
            self._fh = open(path, "a", encoding="utf-8", buffering=1)
        except OSError as e:
            # 日志写不进去不该让服务起不来：容器以非 root 运行时，宿主机挂上来的目录
            # 往往还是 root 所有（PermissionError: [Errno 13]）。退化为只写控制台。
            stream.write(
                f"警告：日志文件 {path} 无法写入（{e}），本次只输出到控制台。\n"
                f"      容器部署请先在宿主机执行 chown -R 10001:10001 <日志目录>。\n"
            )

    def _rotate_if_needed(self) -> None:
        try:
            if os.path.getsize(self._path) <= self._max:
                return
            self._fh.close()
            os.replace(self._path, self._path + ".1")
            self._fh = open(self._path, "a", encoding="utf-8", buffering=1)
        except OSError:
            pass

    def write(self, data: str) -> int:
        self._stream.write(data)
        if self._fh is None:
            return len(data)
        try:
            self._rotate_if_needed()
            self._fh.write(data)
        except OSError:
            pass
        return len(data)

    def flush(self) -> None:
        self._stream.flush()
        if self._fh is None:
            return
        try:
            self._fh.flush()
        except OSError:
            pass

    def isatty(self) -> bool:
        return False

    def close(self) -> None:
        if self._fh is None:
            return
        try:
            self._fh.close()
        except OSError:
            pass

    def __getattr__(self, name):          # encoding / reconfigure 等一律代理给真实流
        return getattr(self._stream, name)


def run_cli(domain: str, mail_host: str, dkim: str, email: str, password: str) -> int:
    from maildoctor.model import GROUPS, Target
    from maildoctor.scan import run_scan

    target = Target(domain=domain, mail_host=mail_host, dkim_selector=dkim,
                    email=email, password=password)

    def emit(ev):
        kind = ev.get("type")
        if kind == "start":
            print(f"\n扫描 {ev['domain']}  (邮件主机 {ev['mail_host']})")
            if ev.get("notice"):
                print(f"  注意：{ev['notice']}")
        elif kind == "group":
            print(f"\n── {ev['title']}  {ev['percent']}%")
            for it in ev["items"]:
                print(f"   {ICON[it['status']]} {it['title']:<26} {it['summary'][:66]}")
                if it["status"] in ("fail", "warn") and it["fix"]:
                    print(f"      → {it['fix'].splitlines()[0][:88]}")

    res = run_scan(target, emit=emit, with_account=bool(password))

    print(f"\n{'=' * 62}")
    print(f"总分 {res['score']['percent']}%  ·  {res['verdict']['title']}")
    print(res["verdict"]["desc"])

    print("\n客户端自动配置能力：")
    for c in res["clients"]:
        way = " + ".join(c["via"]) if c["via"] else (f"卡在 {c['failed_at']}" if c["failed_at"] else "")
        print(f"  {ICON[c['status']]} {c['name']:<18} {way}")

    if res["todo_records"]:
        print("\n需要补充的 DNS 记录：")
        for r in res["todo_records"]:
            print(f"  {r}")

    print("\n完整对照清单：")
    print(res["zone"])
    return 0 if res["score"]["percent"] >= 70 else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="MailDoctor —— 自建邮箱 DNS 与自动配置体检",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n  python run.py\n  python run.py --host 0.0.0.0 --port 8080 --public\n"
               "  python run.py --cli example.com --dkim s20240101")
    ap.add_argument("--host", default="127.0.0.1", help="监听地址，公网部署用 0.0.0.0")
    ap.add_argument("--port", type=int, default=8787, help="监听端口，默认 8787")
    ap.add_argument("--public", action="store_true",
                    help="公网模式：启用限流并拒绝指向内网的目标")
    ap.add_argument("--max-concurrent", type=int, default=6, help="同时进行的扫描数")
    ap.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    ap.add_argument("--cli", metavar="DOMAIN", help="不开服务，直接对域名输出文本报告")
    ap.add_argument("--mail-host", default="", help="邮件服务器主机名，默认 mail.<域名>")
    ap.add_argument("--dkim", default="", help="DKIM selector")
    ap.add_argument("--email", default="", help="用于登录实测的邮箱地址")
    ap.add_argument("--password", default="", help="配合 --email 使用")
    ap.add_argument("--log-file", default="",
                    help="同时把输出写入该文件（容器部署用，超过 10MB 轮转一份）")
    args = ap.parse_args()

    if args.log_file:
        tee = Tee(sys.stdout, args.log_file)
        sys.stdout = tee
        sys.stderr = tee

    if args.cli:
        return run_cli(args.cli, args.mail_host, args.dkim, args.email, args.password)

    from maildoctor.server import serve
    serve(host=args.host, port=args.port, public=args.public,
          max_concurrent=args.max_concurrent, open_browser=args.open)
    return 0


if __name__ == "__main__":
    sys.exit(main())
