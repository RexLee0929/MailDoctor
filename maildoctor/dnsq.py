"""
零依赖 DNS 查询层。

主通道: DNS over HTTPS (Cloudflare -> Google -> 阿里)，JSON 接口，抗污染抗封锁。
兜底通道: 原生 UDP 53 报文 (自建编码/解码，含 name compression 与 TCP fallback)。

对外统一返回 Record(name, rtype, ttl, data)，data 为人类可读字符串，
格式与 DoH JSON 保持一致，便于上层复用同一套解析逻辑。
"""
from __future__ import annotations

import ipaddress
import json
import random
import re
import socket
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------- 常量

TYPE_CODE = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "NAPTR": 35, "DS": 43, "SSHFP": 44, "DNSKEY": 48,
    "TLSA": 52, "CAA": 257,
}
CODE_TYPE = {v: k for k, v in TYPE_CODE.items()}

DOH_ENDPOINTS = [
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("google", "https://dns.google/resolve"),
    ("aliyun", "https://dns.alidns.com/resolve"),
]

UDP_SERVERS = ["223.5.5.5", "119.29.29.29", "1.1.1.1", "8.8.8.8"]

STATUS_NOERROR = "NOERROR"
STATUS_NXDOMAIN = "NXDOMAIN"
STATUS_SERVFAIL = "SERVFAIL"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_ERROR = "ERROR"

_RCODE = {0: STATUS_NOERROR, 1: "FORMERR", 2: STATUS_SERVFAIL, 3: STATUS_NXDOMAIN,
          4: "NOTIMP", 5: "REFUSED"}


class Record:
    """一条资源记录。data 为规范化字符串。"""

    __slots__ = ("name", "rtype", "ttl", "data")

    def __init__(self, name: str, rtype: str, ttl: int, data: str):
        self.name = name
        self.rtype = rtype
        self.ttl = ttl
        self.data = data

    def __repr__(self) -> str:
        return f"<{self.name} {self.rtype} {self.ttl} {self.data!r}>"

    def as_dict(self) -> dict:
        return {"name": self.name, "type": self.rtype, "ttl": self.ttl, "data": self.data}


class QueryResult:
    """一次查询的结果。status 遵循 DNS rcode 语义。"""

    __slots__ = ("name", "rtype", "status", "answers", "via", "error", "ad")

    def __init__(self, name, rtype, status, answers=None, via="", error="", ad=False):
        self.name = name
        self.rtype = rtype
        self.status = status
        self.answers = answers or []
        self.via = via
        self.error = error
        self.ad = ad  # DNSSEC Authenticated Data 标志

    @property
    def ok(self) -> bool:
        return self.status == STATUS_NOERROR

    @property
    def exists(self) -> bool:
        """域名存在（哪怕是 NODATA，也说明域名本身在）。"""
        return self.status == STATUS_NOERROR

    def first(self) -> str | None:
        return self.answers[0].data if self.answers else None

    def __repr__(self) -> str:
        return f"<{self.name}/{self.rtype} {self.status} n={len(self.answers)} via={self.via}>"


# ---------------------------------------------------------------- 文本归一化

_QUOTED = re.compile(r'"([^"]*)"')


def _txt_join(data: str) -> str:
    """TXT 的 data 可能是 '"a" "b"' 多段，需要拼接成一条。"""
    if '"' in data:
        parts = _QUOTED.findall(data)
        if parts:
            return "".join(parts)
        return data.strip('"')
    return data


def _strip_dot(s: str) -> str:
    return s[:-1] if s.endswith(".") else s


# ---------------------------------------------------------------- 原生 UDP 解析

def _enc_name(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        try:
            raw = label.encode("idna")
        except UnicodeError:
            raw = label.encode("utf-8", "replace")
        if len(raw) > 63:
            raise ValueError(f"label too long: {label[:20]}...")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def _dec_name(buf: bytes, off: int) -> tuple[str, int]:
    """解析域名，处理 0xC0 压缩指针。返回 (name, 下一个读取位置)。"""
    labels: list[str] = []
    jumped = False
    end = off
    hops = 0
    while True:
        if off >= len(buf):
            raise ValueError("name runs past end of packet")
        length = buf[off]
        if length == 0:
            off += 1
            if not jumped:
                end = off
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
                jumped = True
            off = ptr
            hops += 1
            if hops > 64:
                raise ValueError("compression loop")
            continue
        off += 1
        labels.append(buf[off:off + length].decode("utf-8", "replace"))
        off += length
        if not jumped:
            end = off
    return ".".join(labels), end


def _decode_rdata(buf: bytes, rtype: int, rdata: bytes, rdata_off: int) -> str:
    if rtype == 1 and len(rdata) == 4:
        return socket.inet_ntoa(rdata)
    if rtype == 28 and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (2, 5, 12):  # NS / CNAME / PTR
        name, _ = _dec_name(buf, rdata_off)
        return name + "."
    if rtype == 15 and len(rdata) >= 3:  # MX
        pref = struct.unpack("!H", rdata[:2])[0]
        name, _ = _dec_name(buf, rdata_off + 2)
        return f"{pref} {name}."
    if rtype == 16:  # TXT
        parts, i = [], 0
        while i < len(rdata):
            ln = rdata[i]
            i += 1
            parts.append(rdata[i:i + ln].decode("utf-8", "replace"))
            i += ln
        return '"' + "".join(parts) + '"'
    if rtype == 33 and len(rdata) >= 7:  # SRV
        prio, weight, port = struct.unpack("!HHH", rdata[:6])
        name, _ = _dec_name(buf, rdata_off + 6)
        return f"{prio} {weight} {port} {name}."
    if rtype == 257:  # CAA
        flags = rdata[0]
        taglen = rdata[1]
        tag = rdata[2:2 + taglen].decode("ascii", "replace")
        value = rdata[2 + taglen:].decode("utf-8", "replace")
        return f'{flags} {tag} "{value}"'
    if rtype == 52:  # TLSA
        usage, selector, matching = rdata[0], rdata[1], rdata[2]
        return f"{usage} {selector} {matching} {rdata[3:].hex()}"
    if rtype == 43 and len(rdata) >= 4:  # DS
        keytag, alg, digest = struct.unpack("!HBB", rdata[:4])
        return f"{keytag} {alg} {digest} {rdata[4:].hex()}"
    if rtype == 6:  # SOA
        mname, o = _dec_name(buf, rdata_off)
        rname, o = _dec_name(buf, o)
        serial = struct.unpack("!I", buf[o:o + 4])[0]
        return f"{mname}. {rname}. {serial}"
    return rdata.hex()


def _udp_query(name: str, rtype: str, server: str, timeout: float) -> QueryResult:
    qtype = TYPE_CODE[rtype]
    qid = random.randint(0, 0xFFFF)
    packet = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _enc_name(name) + struct.pack("!HH", qtype, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        buf, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(buf) < 12:
        return QueryResult(name, rtype, STATUS_ERROR, via=f"udp:{server}", error="short packet")
    rid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
    if rid != qid:
        return QueryResult(name, rtype, STATUS_ERROR, via=f"udp:{server}", error="id mismatch")
    rcode = flags & 0xF
    truncated = bool((flags >> 9) & 1)

    if truncated:
        # TCP 重查
        try:
            with socket.create_connection((server, 53), timeout=timeout) as ts:
                ts.sendall(struct.pack("!H", len(packet)) + packet)
                head = ts.recv(2)
                if len(head) < 2:
                    raise ValueError("tcp short header")
                need = struct.unpack("!H", head)[0]
                chunks, got = [], 0
                while got < need:
                    part = ts.recv(need - got)
                    if not part:
                        break
                    chunks.append(part)
                    got += len(part)
                buf = b"".join(chunks)
                rid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
                rcode = flags & 0xF
        except Exception as exc:  # noqa: BLE001
            return QueryResult(name, rtype, STATUS_TIMEOUT, via=f"tcp:{server}", error=str(exc))

    off = 12
    for _ in range(qd):
        _, off = _dec_name(buf, off)
        off += 4

    answers: list[Record] = []
    for _ in range(an):
        rname, off = _dec_name(buf, off)
        if off + 10 > len(buf):
            break
        rt, rc, ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        rdata = buf[off:off + rdlen]
        rdata_off = off
        off += rdlen
        answers.append(Record(rname + ".", CODE_TYPE.get(rt, str(rt)), ttl,
                              _decode_rdata(buf, rt, rdata, rdata_off)))

    return QueryResult(name, rtype, _RCODE.get(rcode, STATUS_ERROR), answers,
                       via=f"udp:{server}", ad=bool((flags >> 5) & 1))


# ---------------------------------------------------------------- DoH

class _DohClient:
    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout
        self._lock = threading.Lock()
        # 记住上一个成功的端点，减少无谓重试
        self._preferred = 0

    def query(self, name: str, rtype: str) -> QueryResult | None:
        order = list(range(len(DOH_ENDPOINTS)))
        with self._lock:
            if self._preferred:
                order.remove(self._preferred)
                order.insert(0, self._preferred)
        for idx in order:
            label, base = DOH_ENDPOINTS[idx]
            try:
                res = self._one(base, label, name, rtype)
            except Exception:  # noqa: BLE001
                continue
            if res is not None:
                with self._lock:
                    self._preferred = idx
                return res
        return None

    def _one(self, base: str, label: str, name: str, rtype: str) -> QueryResult | None:
        url = f"{base}?{urllib.parse.urlencode({'name': name, 'type': rtype, 'ct': 'application/dns-json'})}"
        req = urllib.request.Request(url, headers={
            "accept": "application/dns-json",
            "user-agent": "MailDoctor/1.0 (+dns-diagnostics)",
        })
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        status = _RCODE.get(payload.get("Status", 0), STATUS_ERROR)
        answers = []
        for item in payload.get("Answer") or []:
            code = item.get("type")
            rname = item.get("name", name)
            data = item.get("data", "")
            rt = CODE_TYPE.get(code, str(code))
            if rt == "TXT":
                data = '"' + _txt_join(data) + '"'
            answers.append(Record(rname, rt, int(item.get("TTL") or 0), data))
        return QueryResult(name, rtype, status, answers, via=f"doh:{label}",
                           ad=bool(payload.get("AD")))


# ---------------------------------------------------------------- 对外接口

class Resolver:
    """带缓存的 DNS 解析器。线程安全。"""

    def __init__(self, timeout: float = 6.0, use_doh: bool = True,
                 udp_servers: list[str] | None = None):
        self.timeout = timeout
        self.use_doh = use_doh
        self.udp_servers = udp_servers or UDP_SERVERS
        self._doh = _DohClient(timeout)
        self._cache: dict[tuple[str, str], tuple[float, QueryResult]] = {}
        self._lock = threading.Lock()
        self.cache_ttl = 120.0

    # -- 原始查询
    def query(self, name: str, rtype: str, use_cache: bool = True) -> QueryResult:
        name = name.rstrip(".")
        rtype = rtype.upper()
        key = (name.lower(), rtype)
        now = time.time()
        if use_cache:
            with self._lock:
                hit = self._cache.get(key)
            if hit and now - hit[0] < self.cache_ttl:
                return hit[1]

        result = None
        if self.use_doh:
            result = self._doh.query(name, rtype)
        if result is None:
            for server in self.udp_servers:
                try:
                    result = _udp_query(name, rtype, server, self.timeout)
                    break
                except Exception:  # noqa: BLE001
                    continue
        if result is None:
            result = QueryResult(name, rtype, STATUS_TIMEOUT, error="所有 DNS 通道均无响应")

        with self._lock:
            self._cache[key] = (now, result)
        return result

    # -- 便捷方法
    def a(self, name: str) -> list[str]:
        return [r.data for r in self.query(name, "A").answers if r.rtype == "A"]

    def aaaa(self, name: str) -> list[str]:
        return [r.data for r in self.query(name, "AAAA").answers if r.rtype == "AAAA"]

    def txt(self, name: str) -> list[str]:
        return [_txt_join(r.data) for r in self.query(name, "TXT").answers if r.rtype == "TXT"]

    def mx(self, name: str) -> list[tuple[int, str]]:
        out = []
        for r in self.query(name, "MX").answers:
            if r.rtype != "MX":
                continue
            pref, _, host = r.data.partition(" ")
            target = _strip_dot(host)
            if not target:
                continue  # RFC 7505 null MX（"0 ."）表示该域不收信
            try:
                out.append((int(pref), target))
            except ValueError:
                continue
        return sorted(out)

    def srv(self, name: str) -> list[tuple[int, int, int, str]]:
        out = []
        for r in self.query(name, "SRV").answers:
            if r.rtype != "SRV":
                continue
            bits = r.data.split()
            if len(bits) < 4:
                continue
            try:
                out.append((int(bits[0]), int(bits[1]), int(bits[2]), _strip_dot(bits[3])))
            except ValueError:
                continue
        return sorted(out)

    def cname(self, name: str) -> str | None:
        for r in self.query(name, "CNAME").answers:
            if r.rtype == "CNAME":
                return _strip_dot(r.data)
        return None

    def ptr(self, ip: str) -> list[str]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return []
        if addr.version == 4:
            rev = ".".join(reversed(str(addr).split("."))) + ".in-addr.arpa"
        else:
            rev = addr.reverse_pointer
        return [_strip_dot(r.data) for r in self.query(rev, "PTR").answers if r.rtype == "PTR"]

    def caa(self, name: str) -> list[tuple[str, str]]:
        out = []
        for r in self.query(name, "CAA").answers:
            if r.rtype != "CAA":
                continue
            m = re.match(r'^\d+\s+(\S+)\s+"(.*)"$', r.data)
            if m:
                out.append((m.group(1), m.group(2)))
        return out

    def has_dnssec(self, name: str) -> bool | None:
        """通过 DS 记录是否被上游认可来粗略判断。None = 无法判断。"""
        res = self.query(name, "DS")
        if res.status == STATUS_NXDOMAIN:
            return False
        if res.answers:
            return True
        return None

    # -- CNAME 链解析
    def resolve(self, name: str, rtype: str = "A", max_depth: int = 10) -> dict:
        """跟随 CNAME 链解析，返回 {ipv4, ipv6, chain, final, status, via}。"""
        chain: list[str] = []
        current = name.rstrip(".")
        seen = set()
        for _ in range(max_depth):
            if current.lower() in seen:
                break
            seen.add(current.lower())
            res = self.query(current, rtype)
            if not res.ok:
                return {"ipv4": [], "ipv6": [], "chain": chain, "final": current,
                        "status": res.status, "via": res.via}
            want = "AAAA" if rtype == "AAAA" else "A"
            ips = [r.data for r in res.answers if r.rtype == want]
            cnames = [r.data for r in res.answers if r.rtype == "CNAME"]
            if ips:
                return {"ipv4": ips, "ipv6": [], "chain": chain, "final": current,
                        "status": res.status, "via": res.via}
            if cnames:
                nxt = _strip_dot(cnames[0])
                chain.append(nxt)
                current = nxt
                continue
            # NODATA：域名存在但无该类型
            return {"ipv4": [], "ipv6": [], "chain": chain, "final": current,
                    "status": res.status, "via": res.via}
        return {"ipv4": [], "ipv6": [], "chain": chain, "final": current,
                "status": STATUS_ERROR, "via": ""}

    def resolve_any_address(self, name: str) -> dict:
        """同时拿 A 与 AAAA，返回合并结果。"""
        v4 = self.resolve(name, "A")
        v6 = self.resolve(name, "AAAA")
        chain = v4["chain"] or v6["chain"]
        return {
            "ipv4": v4["ipv4"],
            "ipv6": v6["ipv4"],
            "chain": chain,
            "final": v4["final"] if v4["ipv4"] else v6["final"],
            "status": v4["status"] if v4["ipv4"] else v6["status"],
        }

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
