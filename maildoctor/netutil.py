"""网络探测工具：HTTP 抓取、TLS 握手与证书解析、TCP 连通性。

全部基于标准库。任何异常都转成结构化结果，绝不让调用方崩。
"""
from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import ssl
import tempfile
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

MAX_BODY = 256 * 1024
USER_AGENT = "MailDoctor/1.0 (mail-autoconfiguration-diagnostics)"


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    sans: list[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    days_left: int | None = None
    serial: str = ""

    def covers(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        for raw in self.sans:
            san = raw.lower().strip()
            if san.startswith("dns:"):
                san = san[4:]
            if san == host:
                return True
            if san.startswith("*."):
                base = san[2:]
                if host.endswith("." + base) and host.count(".") == base.count(".") + 1:
                    return True
        return False

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "sans": self.sans,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_left": self.days_left,
        }


@dataclass
class TlsResult:
    ok: bool = False                 # 握手成功（不论证书是否可信）
    trusted: bool = False            # 证书链通过系统 CA 且主机名匹配
    error: str = ""
    verify_error: str = ""
    cert: CertInfo | None = None
    proto: str = ""
    elapsed: float = 0.0


@dataclass
class HttpResult:
    url: str = ""
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    error: str = ""
    tls: TlsResult | None = None
    redirects: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status == 200 and not self.error

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type") or "").lower()


def _decode_cert(der: bytes) -> CertInfo:
    """用标准库把 DER 证书解码成结构化信息。"""
    info = CertInfo()
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(pem)
        decoded = ssl._ssl._test_decode_cert(path)  # noqa: SLF001
    except Exception:  # noqa: BLE001
        return info
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    def flatten(items) -> str:
        out = []
        for tup in items or []:
            for key, val in tup:
                if key in ("commonName",):
                    out.append(val)
        return ", ".join(out)

    info.subject = flatten(decoded.get("subject"))
    info.issuer = flatten(decoded.get("issuer"))
    info.serial = decoded.get("serialNumber", "")
    info.not_before = decoded.get("notBefore", "")
    info.not_after = decoded.get("notAfter", "")
    for key, val in decoded.get("subjectAltName", ()):
        if key.lower() == "dns":
            info.sans.append(val)
        elif key.lower() == "ip address":
            info.sans.append(val)

    if info.not_after:
        try:
            exp = ssl.cert_time_to_seconds(info.not_after)
            info.days_left = int((exp - time.time()) // 86400)
        except (ValueError, OSError):
            info.days_left = None
    return info


def probe_tls(host: str, port: int, sni: str | None = None,
              starttls: str | None = None, timeout: float = 8.0,
              ip: str | None = None) -> TlsResult:
    """握手一次并取回证书。

    先按「严格模式」验证（链可信 + 主机名匹配），失败后再用宽松模式拿证书内容，
    这样既知道客户端会不会报错，也知道证书里到底有什么。

    ip 给定时直连该地址，SNI 仍用 host —— 绕过系统 DNS（代理 fake-ip 环境下必需）。
    """
    sni = sni or host
    target = ip or host
    res = TlsResult()
    started = time.time()

    # --- 严格模式
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        raw = socket.create_connection((target, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            if starttls:
                raw = _do_starttls(raw, starttls, host)
            with ctx.wrap_socket(raw, server_hostname=sni) as ss:
                res.ok = True
                res.trusted = True
                res.proto = ss.version() or ""
                res.cert = _decode_cert(ss.getpeercert(binary_form=True))
        finally:
            try:
                raw.close()
            except Exception:  # noqa: BLE001
                pass
        res.elapsed = round(time.time() - started, 2)
        return res
    except ssl.SSLCertVerificationError as exc:
        res.verify_error = getattr(exc, "verify_message", str(exc))
    except ssl.SSLError as exc:
        res.verify_error = str(exc)
    except (socket.timeout, TimeoutError):
        res.error = "连接超时"
        res.elapsed = round(time.time() - started, 2)
        return res
    except OSError as exc:
        res.error = str(exc)
        res.elapsed = round(time.time() - started, 2)
        return res

    # --- 宽松模式：拿证书内容
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((target, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            if starttls:
                raw = _do_starttls(raw, starttls, host)
            with ctx.wrap_socket(raw, server_hostname=sni) as ss:
                res.ok = True
                res.proto = ss.version() or ""
                res.cert = _decode_cert(ss.getpeercert(binary_form=True))
        finally:
            try:
                raw.close()
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001
        if not res.error:
            res.error = str(exc)

    res.elapsed = round(time.time() - started, 2)
    return res


def _do_starttls(sock: socket.socket, kind: str, host: str) -> socket.socket:
    """在明文连接上完成 STARTTLS 协商，返回可继续 wrap 的 socket。"""
    sock.settimeout(8.0)
    if kind == "smtp":
        _recv_until(sock, b"\r\n")
        sock.sendall(b"EHLO maildoctor.local\r\n")
        _read_smtp_reply(sock)
        sock.sendall(b"STARTTLS\r\n")
        code, text = _read_smtp_reply(sock)
        if not text.startswith(b"220"):
            raise ssl.SSLError(f"STARTTLS 被拒绝: {text[:80]!r}")
    elif kind == "imap":
        _recv_until(sock, b"\r\n")
        sock.sendall(b"a0 STARTTLS\r\n")
        _recv_until(sock, b"a0 ")
    elif kind == "pop3":
        _recv_until(sock, b"\r\n")
        sock.sendall(b"STLS\r\n")
        line = _recv_until(sock, b"\r\n")
        if not line.upper().startswith(b"+OK"):
            raise ssl.SSLError(f"STLS 被拒绝: {line[:80]!r}")
    return sock


def _recv_until(sock: socket.socket, marker: bytes, limit: int = 8192) -> bytes:
    buf = b""
    while marker not in buf and len(buf) < limit:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    return buf


def _read_smtp_reply(sock: socket.socket, limit: int = 16384) -> tuple[int, bytes]:
    buf = b""
    while len(buf) < limit:
        line = sock.recv(1024)
        if not line:
            break
        buf += line
        if b"\n" in line:
            last = line.rstrip(b"\r\n").split(b"\n")[-1]
            if len(last) >= 4 and last[3:4] == b" ":
                break
    if len(buf) < 3:
        return 0, buf
    try:
        code = int(buf[:3])
    except ValueError:
        code = 0
    return code, buf


class _PinnedMixin:
    """让 http.client 连到指定 IP，但仍用原主机名做 Host / SNI。

    必须这么做：开着代理或 fake-ip 的环境里，系统解析会把任意域名指到
    198.18.x.x 之类的本地地址，导致「每个端口都通」这种假阳性。
    """
    _pin_ip: str | None = None

    def _create_connection(self, address, timeout=None, source_address=None):
        host, port = address
        return socket.create_connection((self._pin_ip or host, port), timeout, source_address)


class _PinnedHTTP(_PinnedMixin, http.client.HTTPConnection):
    pass


class _PinnedHTTPS(_PinnedMixin, http.client.HTTPSConnection):
    pass


def tcp_open(host: str, port: int, timeout: float = 5.0,
             ip: str | None = None) -> tuple[bool, float, str]:
    """TCP 连通性。ip 给定时直连该地址，不做系统域名解析。"""
    started = time.time()
    target = ip or host
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True, round(time.time() - started, 2), ""
    except (socket.timeout, TimeoutError):
        return False, round(time.time() - started, 2), "超时（可能被防火墙丢弃）"
    except ConnectionRefusedError:
        return False, round(time.time() - started, 2), "连接被拒绝（端口未监听）"
    except socket.gaierror as exc:
        return False, round(time.time() - started, 2), f"域名解析失败：{exc}"
    except OSError as exc:
        return False, round(time.time() - started, 2), str(exc)


def http_fetch(url: str, method: str = "GET", body: bytes | None = None,
               headers: dict | None = None, timeout: float = 8.0,
               follow: bool = True, max_hops: int = 4,
               resolver=None) -> HttpResult:
    """发起 HTTP(S) 请求，跟随重定向，并把 TLS 结果一并带回。

    传入 resolver 时，连接目标 IP 取自该解析器（而不是系统 DNS），
    这样报告里的「DNS 结论」和「实际连的是谁」是一致的。
    """
    result = HttpResult(url=url)
    started = time.time()
    current = url
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}
    if headers:
        hdrs.update(headers)

    for _hop in range(max_hops + 1):
        parts = urlsplit(current)
        if parts.scheme not in ("http", "https"):
            result.error = f"不支持的协议 {parts.scheme}"
            break
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        if not host:
            result.error = "URL 缺少主机名"
            break

        pin_ip = None
        if resolver is not None:
            resolved = resolver.resolve_any_address(host)
            ips = resolved["ipv4"] or resolved["ipv6"]
            if not ips:
                result.error = "域名无法解析"
                result.status = 0
                break
            pin_ip = ips[0]

        try:
            if parts.scheme == "https":
                ctx = ssl.create_default_context()
                conn = _PinnedHTTPS(host, port, timeout=timeout, context=ctx)
            else:
                conn = _PinnedHTTP(host, port, timeout=timeout)
            conn._pin_ip = pin_ip
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read(MAX_BODY)
            result.status = resp.status
            result.headers = {k.lower(): v for k, v in resp.getheaders()}
            result.body = data.decode("utf-8", "replace")
            if parts.scheme == "https":
                tls = TlsResult(ok=True, trusted=True)
                try:
                    der = conn.sock.getpeercert(binary_form=True) if conn.sock else None
                    if der:
                        tls.cert = _decode_cert(der)
                    tls.proto = conn.sock.version() if conn.sock else ""
                except Exception:  # noqa: BLE001
                    pass
                result.tls = tls
            location = result.headers.get("location")
            conn.close()
            if follow and result.status in (301, 302, 303, 307, 308) and location:
                if location.startswith("/"):
                    current = f"{parts.scheme}://{parts.netloc}{location}"
                elif location.startswith("http"):
                    current = location
                else:
                    current = f"{parts.scheme}://{parts.netloc}/{location}"
                result.redirects.append(current)
                if result.status == 303:
                    method, body = "GET", None
                continue
            break
        except ssl.SSLCertVerificationError as exc:
            result.error = "TLS 证书校验失败"
            tls = TlsResult(ok=False, trusted=False,
                            verify_error=getattr(exc, "verify_message", str(exc)))
            alt = probe_tls(host, port, sni=host, timeout=timeout, ip=pin_ip)
            tls.cert = alt.cert
            tls.error = alt.error
            tls.ok = alt.ok
            result.tls = tls
            break
        except ssl.SSLError as exc:
            result.error = f"TLS 握手失败：{exc}"
            alt = probe_tls(host, port, sni=host, timeout=timeout, ip=pin_ip)
            result.tls = TlsResult(ok=alt.ok, cert=alt.cert, verify_error=str(exc))
            break
        except (socket.timeout, TimeoutError):
            result.error = "请求超时"
            break
        except (ConnectionRefusedError, http.client.HTTPException, OSError) as exc:
            result.error = f"连接失败：{exc}"
            break

    result.elapsed = round(time.time() - started, 2)
    return result


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


# ---------------------------------------------------------------- 错误翻译

# TLS alert 说明是「服务端主动拒绝」，此时 DNS 通常是好的，问题在 Web 服务器
_TLS_ALERTS = {
    "internal_error": "服务器拒绝为这个域名完成 TLS 握手——没有为它配置站点，或证书签发失败",
    "unrecognized_name": "服务器不认识这个域名（没有配置对应站点）",
    "handshake_failure": "握手失败：服务器没有为该域名提供匹配的证书",
    "certificate_unknown": "服务器没有可用于该域名的证书",
    "access_denied": "服务器拒绝了这个域名的连接",
    "protocol_version": "TLS 协议版本不匹配（客户端与服务器没有共同支持的版本）",
}


def is_tls_reject(err: str) -> bool:
    """错误是否表示「服务器端拒绝握手」，而非网络不通或证书内容问题。"""
    e = (err or "").lower()
    return ("alert" in e and "tls" in e) or "handshake_failure" in e


def human_err(err: str) -> str:
    """把 OpenSSL / socket 的原始报错翻译成人话。"""
    if not err:
        return "未知错误"
    e = err.lower()
    for key, text in _TLS_ALERTS.items():
        if f"alert {key}" in e or f"_alert_{key}" in e:
            return text
    if "unexpected_eof" in e or "eof occurred in violation" in e:
        return "连接被对端直接关闭——该地址上没有 HTTPS 服务"
    if "10054" in e or "强迫关闭" in err or "forcibly closed" in e or "connection reset" in e:
        return "连接被服务器强制关闭——该端口可能没有提供 TLS 服务"
    if "timed out" in e or "timeout" in e:
        return "连接超时（端口可能被防火墙丢弃）"
    if "refused" in e:
        return "连接被拒绝（端口未监听）"
    if "getaddrinfo" in e or "name or service not known" in e or "nodename nor servname" in e:
        return "域名无法解析"
    if "local issuer" in e:
        return "证书链不完整（缺少中间证书或为自签证书）"
    if "self signed" in e or "self-signed" in e:
        return "使用了自签证书"
    if "hostname mismatch" in e or "doesn't match" in e:
        return "证书域名与访问的地址不匹配"
    if err.startswith("TLS 握手失败："):
        return human_err(err[len("TLS 握手失败："):])
    if err.startswith("连接失败："):
        return err[len("连接失败："):]
    return err
