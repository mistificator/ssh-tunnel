import configparser
import gzip
import http.client
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
from urllib.parse import urljoin, urlparse
from urllib.request import url2pathname
import zlib

# Platform checks
IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

# Conditional imports for Windows APIs
if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes
    import winreg
else:
    ctypes = None
    wintypes = None
    winreg = None

# Cross-platform config path: ~/.socks5tunnel/config.ini
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".socks5tunnel")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.ini")

# Default AdGuard DNS Filter & well-known presets
DEFAULT_ADBLOCK_FILTER = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
KNOWN_ADBLOCK_FILTERS = [
    DEFAULT_ADBLOCK_FILTER,
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://big.oisd.nl/domainswild",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "https://someonewhocares.org/hosts/zero/hosts",
]

# Windows Internet Settings Constants
REG_INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


def normalize_bypass_items(raw_bypass: str) -> list[str]:
    """Splits a raw bypass string (separated by newlines, semicolons, or commas) into clean items."""
    if not raw_bypass:
        return []
    normalized = raw_bypass.replace("\r", "\n").replace(";", "\n").replace(",", "\n")
    items = []
    for line in normalized.splitlines():
        clean = line.strip()
        if clean and clean.lower() not in ("<local>", "localhost", "127.0.0.1", "127.0.0.0/8", "::1"):
            if clean not in items:
                items.append(clean)
    return items


# ----------------- Askpass Helper Mode (Subprocess Entry) -----------------
def run_askpass_client():
    """
    Executed by OpenSSH via SSH_ASKPASS.
    Forwards the SSH prompt to the GUI's local AskpassServer
    and prints the response to stdout.
    """
    if len(sys.argv) < 3:
        sys.exit(1)
    try:
        port = int(sys.argv[2])
        prompt_text = " ".join(sys.argv[3:]) if len(sys.argv) > 3 else ""
        with socket.create_connection(("127.0.0.1", port), timeout=30.0) as s:
            payload = json.dumps({"prompt": prompt_text}).encode("utf-8")
            s.sendall(struct.pack("!I", len(payload)) + payload)
            hdr = s.recv(4)
            if len(hdr) < 4:
                sys.exit(1)
            resp_len = struct.unpack("!I", hdr)[0]
            data = bytearray()
            while len(data) < resp_len:
                chunk = s.recv(resp_len - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            resp = json.loads(data.decode("utf-8", errors="ignore"))
            if not resp.get("ok", True):
                sys.exit(1)
            sys.stdout.write(resp.get("answer", "") + "\n")
            sys.stdout.flush()
    except Exception:
        sys.exit(1)


# ----------------- DNS & Host Helpers -----------------
def sanitize_host(raw_host: str) -> str:
    """Cleans up user input in the SSH Host field."""
    h = raw_host.strip()
    if "://" in h:
        parsed = urlparse(h)
        h = parsed.hostname or h
    if "@" in h:
        h = h.split("@")[-1]
    if "/" in h:
        h = h.split("/")[0]
    if h.count(":") == 1:
        h = h.split(":")[0]
    return h.strip()


def is_ipv4_address(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def build_dns_query(domain: str, tx_id: bytes = b"\x42\x42") -> bytes:
    """Builds a standard DNS A-record (IPv4) query packet."""
    qname = bytearray()
    for part in domain.strip(".").split("."):
        if not part:
            continue
        encoded = part.encode("idna")
        qname.append(len(encoded))
        qname.extend(encoded)
    qname.append(0)
    return tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + bytes(qname) + b"\x00\x01\x00\x01"


def _skip_dns_name(data: bytes, offset: int) -> int:
    """Safely skips a DNS name in a packet, handling label sequences and 0xC0 compression pointers."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def parse_dns_question_domain(data: bytes) -> tuple[str | None, int, int]:
    """
    Extracts (domain, qtype, question_end_offset) from the first Question of a raw DNS packet.
    """
    if len(data) < 12:
        return None, 0, 0
    qdcount = struct.unpack("!H", data[4:6])[0]
    if qdcount < 1:
        return None, 0, 0

    offset = 12
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            offset += 2
            break
        offset += 1
        if offset + length > len(data):
            return None, 0, 0
        labels.append(data[offset:offset + length].decode("ascii", errors="ignore"))
        offset += length

    if offset + 4 > len(data) or not labels:
        return None, 0, 0
    qtype, _ = struct.unpack("!HH", data[offset:offset + 4])
    offset += 4
    return ".".join(labels).lower().strip("."), qtype, offset


def build_dns_sinkhole_response(query_data: bytes) -> bytes | None:
    """Builds a synthetic DNS response (0.0.0.0 for A queries, empty NOERROR for others)."""
    domain, qtype, q_end = parse_dns_question_domain(query_data)
    if not domain or q_end == 0:
        return None

    tx_id = query_data[:2]
    req_flags = struct.unpack("!H", query_data[2:4])[0]
    rd_bit = req_flags & 0x0100
    resp_flags = 0x8000 | rd_bit | 0x0080  # QR=1, RA=1, RCODE=0 (NOERROR)
    question_section = query_data[12:q_end]

    if qtype == 1:  # A record -> 0.0.0.0
        header = tx_id + struct.pack("!HHHHH", resp_flags, 1, 1, 0, 0)
        # Name pointer to 0x000c, Type A (1), Class IN (1), TTL 300s, Len 4, IP 0.0.0.0
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + b"\x00\x00\x00\x00"
        return header + question_section + answer
    else:
        header = tx_id + struct.pack("!HHHHH", resp_flags, 1, 0, 0, 0)
        return header + question_section


def parse_dns_a_response(data: bytes, tx_id: bytes = b"\x42\x42") -> str | None:
    """Extracts the first IPv4 A-record from a raw DNS response packet (supports CNAME chains)."""
    if len(data) < 12 or data[:2] != tx_id:
        return None
    flags = struct.unpack("!H", data[2:4])[0]
    if (flags & 0x000F) != 0:
        return None

    qdcount = struct.unpack("!H", data[4:6])[0]
    ancount = struct.unpack("!H", data[6:8])[0]
    if ancount == 0:
        return None

    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(data, offset)
        offset += 4  # QTYPE (2B) + QCLASS (2B)

    for _ in range(ancount):
        if offset >= len(data):
            break
        offset = _skip_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, _, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == 1 and rclass == 1 and rdlength == 4 and offset + 4 <= len(data):
            return socket.inet_ntoa(data[offset:offset + 4])
        offset += rdlength
    return None


def resolve_host_ipv4(host: str) -> tuple[str | None, bool]:
    """
    Resolves hostname to IPv4.
    Returns (ip, used_fallback_dns).
    First tries system DNS; if that fails, queries 1.1.1.1 / 8.8.8.8 directly.
    """
    if is_ipv4_address(host):
        return host, False

    try:
        ip = socket.gethostbyname(host)
        if ip:
            return ip, False
    except OSError:
        pass

    tx_id = os.urandom(2)
    query = build_dns_query(host, tx_id)
    for dns_srv in ("1.1.1.1", "8.8.8.8"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2.5)
                s.sendto(query, (dns_srv, 53))
                resp, _ = s.recvfrom(2048)
                ip = parse_dns_a_response(resp, tx_id)
                if ip:
                    return ip, True
        except Exception:
            continue

    return None, False


# ----------------- DNS AdBlock Filter Engine -----------------
class AdBlockEngine:
    """
    Parses and evaluates DNS adblock filter lists:
    - AdGuard DNS / Adblock syntax (||domain.com^, @@||domain.com^, $important, etc.)
    - Standard /etc/hosts syntax (0.0.0.0 domain.com, 127.0.0.1 domain.com)
    - Dnsmasq / SmartDNS syntax (address=/domain.com/0.0.0.0, server=/domain.com/)
    - Plain domain / wildcard domain lists (domain.com, *.domain.com)
    Supports loading from local files and downloading via the SSH SOCKS5 tunnel.
    """
    IGNORE_HOSTS = {
        "localhost", "localhost.localdomain", "local", "broadcasthost",
        "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
        "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0", "127.0.0.1", "::1"
    }
    ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789.-_")

    def __init__(self, log_cb):
        self.log_cb = log_cb
        self.lock = threading.Lock()
        self.blocked_domains: set[str] = set()
        self.allowed_domains: set[str] = set()
        self.blocked_hits: int = 0
        self._recent_logged: dict[str, float] = {}
        self.last_source_loaded: str = ""

    @property
    def rule_count(self) -> int:
        with self.lock:
            return len(self.blocked_domains)

    @property
    def exception_count(self) -> int:
        with self.lock:
            return len(self.allowed_domains)

    @classmethod
    def _clean_valid_domain(cls, raw: str) -> str | None:
        d = raw.strip().lower().strip(".")
        if d.startswith("*."):
            d = d[2:].strip(".")
        if not d or "." not in d or len(d) > 253:
            return None
        if d in cls.IGNORE_HOSTS or is_ipv4_address(d):
            return None
        if not all(ch in cls.ALLOWED_CHARS for ch in d):
            return None
        if ".." in d or d.startswith("-") or d.endswith("-"):
            return None
        return d

    @classmethod
    def parse_filter_text(cls, text: str) -> tuple[set[str], set[str]]:
        blocked: set[str] = set()
        allowed: set[str] = set()

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("!") or line.startswith("#") or line.startswith("["):
                continue
            if line.startswith("/") and line.endswith("/"):
                continue  # Skip regex rules

            # 1. AdGuard / Adblock Exception rules: @@||example.com^
            if line.startswith("@@"):
                rule = line[2:].strip()
                rule, has_mod, modifiers = rule.partition("$")
                if has_mod and "badfilter" in modifiers.lower():
                    continue
                for prefix in ("||", "|http://", "|https://", "|", "http://", "https://", "://"):
                    if rule.startswith(prefix):
                        rule = rule[len(prefix):]
                        break
                if "^" in rule:
                    rule, _, rest = rule.partition("^")
                    if rest and rest != "/":
                        continue
                rule = rule.rstrip("/")
                if "/" in rule:
                    continue
                d = cls._clean_valid_domain(rule)
                if d:
                    allowed.add(d)
                continue

            # 2. Dnsmasq / Unbound syntax: address=/example.com/0.0.0.0 or server=/example.com/
            if line.startswith(("address=/", "server=/", "local=/")):
                parts = line.split("/")
                if len(parts) >= 2:
                    d = cls._clean_valid_domain(parts[1])
                    if d:
                        blocked.add(d)
                continue

            # 3. AdGuard / Adblock domain rules: ||example.com^ or example.com^
            if line.startswith("||") or "^" in line or "$" in line:
                rule, has_mod, modifiers = line.partition("$")
                if has_mod:
                    mod_lower = modifiers.lower()
                    if "badfilter" in mod_lower or "ctag=" in mod_lower or "client=" in mod_lower:
                        continue
                    # Skip non-blocking rewrite rules (unless rewriting to 0.0.0.0 / 127.0.0.1 / NXDOMAIN)
                    if "dnsrewrite=" in mod_lower:
                        if not any(x in mod_lower for x in ("0.0.0.0", "127.0.0.1", "nxdomain", "refused", "noerror")):
                            continue

                if rule.startswith("||"):
                    rule = rule[2:]
                elif rule.startswith("|"):
                    continue  # Skip URL-prefix rules like |http://...

                if "^" in rule:
                    rule, _, rest = rule.partition("^")
                    if rest and rest != "/":
                        continue  # URL path after ^, not a pure domain rule
                rule = rule.rstrip("/")
                if "/" in rule:
                    continue  # URL path rule (e.g. ||site.com/ads.js), do not block whole domain

                d = cls._clean_valid_domain(rule)
                if d:
                    blocked.add(d)
                continue

            # Strip inline comments for hosts / plain domain lines
            if "#" in line:
                line = line.split("#", 1)[0].strip()
            if not line:
                continue

            # 4. Hosts file format: 0.0.0.0 example.com / 127.0.0.1 example.com
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                for token in parts[1:]:
                    d = cls._clean_valid_domain(token)
                    if d:
                        blocked.add(d)
                continue

            # 5. Plain domain or wildcard domain list: example.com or *.example.com
            if len(parts) == 1:
                d = cls._clean_valid_domain(parts[0])
                if d:
                    blocked.add(d)

        return blocked, allowed

    def is_blocked(self, domain: str, log_hit: bool = True) -> bool:
        """
        Checks if domain (or any parent domain) is blocked, respecting @@ exception rules.
        Walks from most specific subdomain to least specific parent domain.
        """
        clean = domain.strip().lower().strip(".")
        if not clean or is_ipv4_address(clean):
            return False

        labels = clean.split(".")
        if len(labels) < 2:
            return False

        matched_rule = None
        now = time.time()
        should_log = False
        total_hits = 0

        with self.lock:
            if not self.blocked_domains:
                return False

            for i in range(len(labels) - 1):
                candidate = ".".join(labels[i:])
                if candidate in self.allowed_domains:
                    return False
                if candidate in self.blocked_domains:
                    matched_rule = candidate
                    break

            if matched_rule is None:
                return False

            self.blocked_hits += 1
            total_hits = self.blocked_hits
            if log_hit:
                last_t = self._recent_logged.get(clean, 0.0)
                if now - last_t >= 15.0:
                    self._recent_logged[clean] = now
                    if len(self._recent_logged) > 500:
                        self._recent_logged.clear()
                    should_log = True

        if should_log and self.log_cb:
            rule_info = f" (rule: {matched_rule})" if matched_rule != clean else ""
            self.log_cb(f"> [AdBlock] Blocked: {clean}{rule_info} [total: {total_hits}]")

        return True

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
        data = bytearray()
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    return None
                data.extend(chunk)
            except Exception:
                return None
        return bytes(data)

    def _download_via_ssh_socks5(
        self,
        url: str,
        internal_ssh_port: int,
        dns_resolver_fn,
        max_redirects: int = 5
    ) -> str:
        """Downloads an HTTP/HTTPS filter URL strictly through the local SSH SOCKS5 listener."""
        current_url = url
        for _ in range(max_redirects + 1):
            parsed = urlparse(current_url)
            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https"):
                raise ValueError(f"Unsupported URL scheme: {scheme}")

            host = parsed.hostname
            if not host:
                raise ValueError(f"Invalid URL hostname in: {current_url}")
            port = parsed.port or (443 if scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            # Resolve filter host via SSH tunnel DNS first
            resolved_ip_bytes = dns_resolver_fn(host) if dns_resolver_fn else None

            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw_sock.settimeout(15.0)
            sock = raw_sock
            try:
                raw_sock.connect(("127.0.0.1", internal_ssh_port))
                raw_sock.sendall(b"\x05\x01\x00")
                if self._recv_exact(raw_sock, 2) != b"\x05\x00":
                    raise RuntimeError("SSH SOCKS5 handshake failed while fetching filter")

                if resolved_ip_bytes:
                    req = b"\x05\x01\x00\x01" + resolved_ip_bytes + struct.pack("!H", port)
                else:
                    host_b = host.encode("idna")
                    req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", port)

                raw_sock.sendall(req)
                resp_hdr = self._recv_exact(raw_sock, 4)
                if not resp_hdr or resp_hdr[1] != 0:
                    code = resp_hdr[1] if resp_hdr and len(resp_hdr) > 1 else "?"
                    raise RuntimeError(f"SOCKS5 connect to {host}:{port} failed (code {code})")

                atyp = resp_hdr[3]
                if atyp == 1:
                    self._recv_exact(raw_sock, 6)
                elif atyp == 3:
                    dlen_b = self._recv_exact(raw_sock, 1)
                    if dlen_b:
                        self._recv_exact(raw_sock, dlen_b[0] + 2)
                elif atyp == 4:
                    self._recv_exact(raw_sock, 18)

                if scheme == "https":
                    ctx = ssl.create_default_context()
                    sock = ctx.wrap_socket(raw_sock, server_hostname=host)
                    sock.settimeout(20.0)

                host_hdr = f"{host}:{port}" if parsed.port else host
                http_req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host_hdr}\r\n"
                    "User-Agent: Mozilla/5.0 (compatible; SSHTunnel-AdBlock/1.0)\r\n"
                    "Accept: text/plain, */*\r\n"
                    "Accept-Encoding: gzip, deflate\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("utf-8")
                sock.sendall(http_req)

                http_resp = http.client.HTTPResponse(sock, method="GET")
                http_resp.begin()
                status = http_resp.status

                if status in (301, 302, 303, 307, 308):
                    location = http_resp.getheader("Location")
                    http_resp.close()
                    if not location:
                        raise RuntimeError(f"HTTP {status} redirect without Location header")
                    current_url = urljoin(current_url, location)
                    continue

                if status != 200:
                    reason = http_resp.reason
                    http_resp.close()
                    raise RuntimeError(f"HTTP {status} {reason}")

                body = http_resp.read(30 * 1024 * 1024)  # Up to 30 MB limit
                content_enc = (http_resp.getheader("Content-Encoding") or "").lower()
                http_resp.close()

                if "gzip" in content_enc:
                    body = gzip.decompress(body)
                elif "deflate" in content_enc:
                    try:
                        body = zlib.decompress(body)
                    except zlib.error:
                        body = zlib.decompress(body, -zlib.MAX_WBITS)

                return body.decode("utf-8", errors="ignore")
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        raise RuntimeError("Too many HTTP redirects while downloading AdBlock filter")

    def load_from_source(
        self,
        source_spec: str,
        internal_ssh_port: int | None = None,
        dns_resolver_fn=None
    ) -> tuple[bool, int, int]:
        """
        Loads one or multiple filter sources (separated by ';').
        Internet URLs (http://, https://) are downloaded via the SSH tunnel.
        Local paths (or file://) are read from disk.
        Returns (success, blocked_count, exception_count).
        """
        raw_sources = [s.strip() for s in source_spec.split(";") if s.strip()]
        if not raw_sources:
            with self.lock:
                self.blocked_domains.clear()
                self.allowed_domains.clear()
            return False, 0, 0

        total_blocked: set[str] = set()
        total_allowed: set[str] = set()
        any_loaded = False

        for src in raw_sources:
            try:
                if src.lower().startswith(("http://", "https://")):
                    if not internal_ssh_port:
                        self.log_cb(f"> [AdBlock] Waiting for SSH tunnel to download filter: {src}")
                        continue
                    self.log_cb(f"> [AdBlock] Downloading filter through SSH tunnel: {src} ...")
                    t0 = time.perf_counter()
                    content = self._download_via_ssh_socks5(src, internal_ssh_port, dns_resolver_fn)
                    dt = time.perf_counter() - t0
                    b_set, a_set = self.parse_filter_text(content)
                    total_blocked.update(b_set)
                    total_allowed.update(a_set)
                    any_loaded = True
                    size_kb = len(content.encode("utf-8", errors="ignore")) / 1024.0
                    self.log_cb(
                        f"> [AdBlock] Downloaded via tunnel ({size_kb:.0f} KB in {dt:.1f}s): "
                        f"{len(b_set):,} blocked domains, {len(a_set):,} exceptions."
                    )
                else:
                    local_path = src
                    if local_path.lower().startswith("file://"):
                        local_path = url2pathname(urlparse(local_path).path)
                    local_path = os.path.expandvars(os.path.expanduser(local_path))
                    if not os.path.isfile(local_path):
                        self.log_cb(f"> [AdBlock] Local filter file not found: {local_path}")
                        continue
                    with open(local_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    b_set, a_set = self.parse_filter_text(content)
                    total_blocked.update(b_set)
                    total_allowed.update(a_set)
                    any_loaded = True
                    self.log_cb(
                        f"> [AdBlock] Loaded local filter '{os.path.basename(local_path)}': "
                        f"{len(b_set):,} blocked domains, {len(a_set):,} exceptions."
                    )
            except Exception as e:
                self.log_cb(f"> [AdBlock] Error loading filter '{src}': {e}")

        if any_loaded:
            with self.lock:
                self.blocked_domains = total_blocked
                self.allowed_domains = total_allowed
                self.last_source_loaded = source_spec
            return True, len(total_blocked), len(total_allowed)

        return False, self.rule_count, self.exception_count


# ----------------- Windows Proxy Helpers -----------------
def notify_windows_proxy_change():
    """Notifies WinINet of proxy setting changes."""
    if not IS_WINDOWS or ctypes is None:
        return
    try:
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD]
        internet_set_option.restype = wintypes.BOOL
        internet_set_option(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
        internet_set_option(None, INTERNET_OPTION_REFRESH, None, 0)
    except Exception as e:
        print(f"Error updating WinINet: {e}")


def read_windows_proxy_settings():
    """Reads system proxy configuration from Windows Registry."""
    socks_port = "1080"
    bypass_list = ""
    if not IS_WINDOWS or winreg is None:
        return socks_port, bypass_list

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_INTERNET_SETTINGS, 0, winreg.KEY_READ) as key:
            try:
                proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                if proxy_server:
                    for part in proxy_server.split(";"):
                        part = part.strip()
                        if part.lower().startswith("socks="):
                            addr = part[6:]
                            if ":" in addr:
                                socks_port = addr.split(":")[-1]
                            break
                        elif ":" in part and "=" not in part:
                            socks_port = part.split(":")[-1]
            except FileNotFoundError:
                pass

            try:
                proxy_override, _ = winreg.QueryValueEx(key, "ProxyOverride")
                if proxy_override:
                    items = normalize_bypass_items(proxy_override)
                    bypass_list = "\n".join(items)
            except FileNotFoundError:
                pass
    except Exception as e:
        print(f"Error reading Windows registry: {e}")

    return socks_port, bypass_list


def set_windows_proxy(
    enabled: bool,
    socks_port: str = "1080",
    bypass_list: str = "",
    remote_dns: bool = True,
    extra_bypass: list[str] | None = None
):
    """
    Configures system proxy in Windows Registry.
    When remote_dns=True, sets AutoConfigURL to our local PAC endpoint so
    browsers send domain names via SOCKS5 instead of resolving locally via SOCKS4.
    """
    if not IS_WINDOWS or winreg is None:
        return

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                proxy_server_val = f"socks=127.0.0.1:{socks_port}"
                items = normalize_bypass_items(bypass_list)
                for loop_host in ("localhost", "127.0.0.1"):
                    if loop_host not in items:
                        items.append(loop_host)
                if extra_bypass:
                    for eb in extra_bypass:
                        if eb and eb not in items:
                            items.append(eb)
                items.append("<local>")
                reg_bypass_val = ";".join(items)

                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server_val)
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, reg_bypass_val)

                if remote_dns:
                    pac_url = f"http://127.0.0.1:{socks_port}/proxy.pac?t={int(time.time())}"
                    winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
                else:
                    try:
                        winreg.DeleteValue(key, "AutoConfigURL")
                    except FileNotFoundError:
                        pass
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                try:
                    winreg.DeleteValue(key, "AutoConfigURL")
                except FileNotFoundError:
                    pass
        notify_windows_proxy_change()
    except Exception as e:
        print(f"Error updating Windows registry proxy: {e}")


# ----------------- Linux Proxy Helpers -----------------
def read_linux_proxy_settings():
    """Reads desktop proxy settings using gsettings (GNOME, Cinnamon, MATE)."""
    socks_port = "1080"
    bypass_list = ""
    if not shutil.which("gsettings"):
        return socks_port, bypass_list

    try:
        res = subprocess.run(
            ["gsettings", "get", "org.gnome.system.proxy.socks", "port"],
            capture_output=True, text=True, check=False
        )
        port_val = res.stdout.strip()
        if port_val.isdigit() and int(port_val) > 0:
            socks_port = port_val

        res_ignore = subprocess.run(
            ["gsettings", "get", "org.gnome.system.proxy", "ignore-hosts"],
            capture_output=True, text=True, check=False
        )
        out = res_ignore.stdout.strip()
        if out.startswith("[") and out.endswith("]"):
            import ast
            try:
                raw_items = ast.literal_eval(out)
                items = normalize_bypass_items("\n".join(str(x) for x in raw_items))
                bypass_list = "\n".join(items)
            except Exception:
                pass
    except Exception as e:
        print(f"Error reading Linux proxy settings: {e}")

    return socks_port, bypass_list


def set_linux_proxy(
    enabled: bool,
    socks_port: str = "1080",
    bypass_list: str = "",
    remote_dns: bool = True,
    extra_bypass: list[str] | None = None
):
    """Sets desktop proxy settings using gsettings."""
    if not shutil.which("gsettings"):
        return

    try:
        if enabled:
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"], check=False)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(socks_port)], check=False)

            items = normalize_bypass_items(bypass_list)
            if extra_bypass:
                for eb in extra_bypass:
                    if eb and eb not in items:
                        items.append(eb)
            for default_host in ["localhost", "127.0.0.0/8", "::1"]:
                if default_host not in items:
                    items.append(default_host)
            formatted_items = "[" + ", ".join(f"'{item}'" for item in items) + "]"
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "ignore-hosts", formatted_items], check=False)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"], check=False)
        else:
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"], check=False)
    except Exception as e:
        print(f"Error setting Linux proxy: {e}")


# ----------------- Unified System Proxy Dispatcher -----------------
def read_system_proxy_settings():
    if IS_WINDOWS:
        return read_windows_proxy_settings()
    elif IS_LINUX:
        return read_linux_proxy_settings()
    return "1080", ""


def set_system_proxy(
    enabled: bool,
    socks_port: str = "1080",
    bypass_list: str = "",
    remote_dns: bool = True,
    extra_bypass: list[str] | None = None
):
    if IS_WINDOWS:
        set_windows_proxy(enabled, socks_port, bypass_list, remote_dns, extra_bypass)
    elif IS_LINUX:
        set_linux_proxy(enabled, socks_port, bypass_list, remote_dns, extra_bypass)


def get_free_port(preferred_port: int = 1081) -> int:
    """Finds an available TCP port for internal listeners."""
    for port in range(preferred_port, preferred_port + 500):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
    return 10888


# ----------------- Silent SSH Askpass Server -----------------
class AskpassServer:
    """
    Local TCP server that intercepts OpenSSH prompts from SSH_ASKPASS.
    Silently answers 'yes' to any host key / yes-no prompts and automatically
    supplies the user's password for authentication prompts.
    """
    def __init__(self, password_getter, log_cb):
        self.password_getter = password_getter
        self.log_cb = log_cb
        self.running = True

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(5)
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
                threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
            except Exception:
                break

    def _handle_client(self, conn: socket.socket):
        try:
            hdr = conn.recv(4)
            if len(hdr) < 4:
                conn.close()
                return
            msg_len = struct.unpack("!I", hdr)[0]
            data = bytearray()
            while len(data) < msg_len:
                chunk = conn.recv(msg_len - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            req = json.loads(data.decode("utf-8", errors="ignore"))
            prompt = req.get("prompt", "").strip()
            prompt_lower = prompt.lower()

            if (
                "yes/no" in prompt_lower
                or "authenticity of host" in prompt_lower
                or "continue connecting" in prompt_lower
                or "fingerprint" in prompt_lower
            ):
                resp_bytes = json.dumps({"ok": True, "answer": "yes"}).encode("utf-8")
            else:
                pwd = self.password_getter()
                resp_bytes = json.dumps({"ok": True, "answer": pwd}).encode("utf-8")

            conn.sendall(struct.pack("!I", len(resp_bytes)) + resp_bytes)
        except Exception as e:
            self.log_cb(f"> Askpass IPC error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass


# ----------------- badvpn-udpgw Client Bridge -----------------
class BadVpnClient:
    """Manages TCP connection to badvpn-udpgw daemon."""
    def __init__(self, udpgw_port: int, udp_sock: socket.socket, log_cb):
        self.udpgw_port = udpgw_port
        self.udp_sock = udp_sock
        self.log_cb = log_cb
        self.tcp_sock = None
        self.running = True
        self.lock = threading.Lock()
        self.conns = {}      # (client_addr, dest_ip_bytes, dest_port) -> conid
        self.conns_rev = {}  # conid -> (client_addr, dest_ip_bytes, dest_port)
        self.next_conid = 1

    def _ensure_connected(self) -> bool:
        with self.lock:
            if self.tcp_sock is not None:
                return True
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect(('127.0.0.1', self.udpgw_port))
                s.settimeout(None)
                self.tcp_sock = s
                self.conns.clear()
                self.conns_rev.clear()
                threading.Thread(target=self._recv_loop, daemon=True).start()
                self.log_cb(f"> Connected to badvpn-udpgw (:{self.udpgw_port}).")
                return True
            except Exception:
                return False

    def send_packet(self, client_addr, dest_ip_bytes, dest_port, payload):
        if not self._ensure_connected():
            return

        key = (client_addr, dest_ip_bytes, dest_port)
        with self.lock:
            if key in self.conns:
                conid = self.conns[key]
            else:
                conid = self.next_conid
                self.next_conid = (self.next_conid + 1) & 0xFFFF
                if self.next_conid == 0:
                    self.next_conid = 1
                self.conns[key] = conid
                self.conns_rev[conid] = (client_addr, dest_ip_bytes, dest_port)

        # badvpn frame: [Len 2B LE] + [Flags 1B] + [ConID 2B LE] + [IP 4B BE] + [Port 2B BE] + [Payload]
        flags = 0
        header = struct.pack("<HBH", 1 + 2 + 4 + 2 + len(payload), flags, conid)
        addr_part = dest_ip_bytes + struct.pack("!H", dest_port)
        frame = header + addr_part + payload

        try:
            with self.lock:
                if self.tcp_sock:
                    self.tcp_sock.sendall(frame)
        except Exception:
            self._close_sock()

    def _recv_exact(self, n):
        data = bytearray()
        while len(data) < n and self.running:
            try:
                chunk = self.tcp_sock.recv(n - len(data))
                if not chunk:
                    return None
                data.extend(chunk)
            except Exception:
                return None
        return bytes(data)

    def _recv_loop(self):
        while self.running:
            len_bytes = self._recv_exact(2)
            if not len_bytes:
                break
            pkt_len = struct.unpack("<H", len_bytes)[0]
            packet = self._recv_exact(pkt_len)
            if not packet or len(packet) < 9:
                break

            conid = struct.unpack("<H", packet[1:3])[0]
            src_ip_bytes = packet[3:7]       # Source IP (4 bytes)
            src_port_bytes = packet[7:9]     # Source Port (2 bytes)
            payload = packet[9:]             # Pure UDP payload

            with self.lock:
                info = self.conns_rev.get(conid)

            if info:
                client_addr, _, _ = info
                # SOCKS5 UDP reply: RSV (2B) + FRAG (1B) + ATYP=1 (1B) + IP (4B) + Port (2B) + Payload
                socks5_hdr = b"\x00\x00\x00\x01" + src_ip_bytes + src_port_bytes
                try:
                    self.udp_sock.sendto(socks5_hdr + payload, client_addr)
                except Exception:
                    pass
        self._close_sock()

    def _close_sock(self):
        with self.lock:
            if self.tcp_sock:
                try:
                    self.tcp_sock.close()
                except Exception:
                    pass
                self.tcp_sock = None

    def close(self):
        self.running = False
        self._close_sock()


# ----------------- SOCKS, PAC, AdBlock & UDP Bridge -----------------
class SocksUdpBridge:
    """
    Local SOCKS5/SOCKS4, PAC & AdBlock Bridge:
    - Serves /proxy.pac on HTTP GET so browsers use SOCKS5 with Remote DNS.
    - When remote_dns=True, checks domains against AdBlockEngine and resolves
      allowed domains to IPv4 (A-records) inside the SSH tunnel.
    - Handles SOCKS5 UDP ASSOCIATE and routes datagrams to badvpn-udpgw.
    """
    def __init__(
        self,
        socks_port: int,
        internal_ssh_port: int,
        udpgw_port: int,
        enable_udp: bool,
        remote_dns: bool,
        adblock_enabled: bool,
        adblock_engine: AdBlockEngine,
        bypass_list: str,
        extra_bypass: list[str],
        log_cb
    ):
        self.socks_port = socks_port
        self.internal_ssh_port = internal_ssh_port
        self.udpgw_port = udpgw_port
        self.enable_udp = enable_udp
        self.remote_dns = remote_dns
        self.adblock_enabled = adblock_enabled
        self.adblock_engine = adblock_engine
        self.bypass_list = bypass_list
        self.extra_bypass = extra_bypass or []
        self.log_cb = log_cb
        self.running = True

        # Thread-safe DNS cache & in-flight deduplication
        self.dns_cache = {}       # domain -> (ip_bytes, expire_ts)
        self.dns_inflight = {}    # domain -> threading.Event
        self.dns_lock = threading.Lock()

        self.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_server.bind(('127.0.0.1', socks_port))
        self.tcp_server.listen(256)

        self.udp_server = None
        self.badvpn_client = None
        if self.enable_udp:
            self.udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_server.bind(('127.0.0.1', socks_port))
            self.badvpn_client = BadVpnClient(udpgw_port, self.udp_server, log_cb)

    def clear_dns_cache(self):
        with self.dns_lock:
            self.dns_cache.clear()

    def is_domain_blocked(self, domain: str) -> bool:
        if not (self.remote_dns and self.adblock_enabled and self.adblock_engine):
            return False
        return self.adblock_engine.is_blocked(domain, log_hit=True)

    def start(self):
        threading.Thread(target=self._tcp_accept_loop, daemon=True).start()
        if self.enable_udp and self.udp_server:
            threading.Thread(target=self._udp_relay_loop, daemon=True).start()
        mode_str = "TCP/UDP" if self.enable_udp else "TCP"
        if self.remote_dns:
            dns_str = "Remote Tunnel DNS + AdBlock" if self.adblock_enabled else "Remote Tunnel DNS -> IPv4"
        else:
            dns_str = "Local DNS"
        self.log_cb(
            f"> SOCKS5 bridge ({mode_str} :{self.socks_port} -> SSH :{self.internal_ssh_port}, {dns_str}) started."
        )

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
        """Reads exactly n bytes from sock or returns None on EOF/error."""
        data = bytearray()
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    return None
                data.extend(chunk)
            except Exception:
                return None
        return bytes(data)

    def _generate_pac_script(self) -> bytes:
        raw_items = normalize_bypass_items(self.bypass_list)
        for eb in self.extra_bypass:
            if eb and eb not in raw_items:
                raw_items.append(eb)

        conditions = [
            'isPlainHostName(host)',
            'host === "localhost"',
            'shExpMatch(host, "127.*")',
            'shExpMatch(host, "::1")'
        ]
        for item in raw_items:
            safe_item = item.replace('"', '').replace("'", "")
            if safe_item:
                conditions.append(f'shExpMatch(host, "{safe_item}")')

        cond_expr = " ||\n        ".join(conditions)
        pac_body = (
            "function FindProxyForURL(url, host) {\n"
            f"    if (\n        {cond_expr}\n    ) {{\n"
            '        return "DIRECT";\n'
            "    }\n"
            f'    return "SOCKS5 127.0.0.1:{self.socks_port}; SOCKS 127.0.0.1:{self.socks_port}";\n'
            "}\n"
        ).encode("utf-8")

        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/x-ns-proxy-autoconfig\r\n"
            f"Content-Length: {len(pac_body)}\r\n"
            "Cache-Control: no-cache, no-store, must-revalidate\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        return headers + pac_body

    def _query_dns_over_ssh_single(self, domain: str, dns_server: str) -> bytes | None:
        """Performs a single DNS-over-TCP A-record lookup through the internal SSH SOCKS5 port."""
        ssh_sock = self._connect_to_ssh(timeout=3.5)
        if not ssh_sock:
            return None
        try:
            ssh_sock.settimeout(4.0)
            ssh_sock.sendall(b"\x05\x01\x00")
            if self._recv_exact(ssh_sock, 2) != b"\x05\x00":
                return None

            req = b"\x05\x01\x00\x01" + socket.inet_aton(dns_server) + struct.pack("!H", 53)
            ssh_sock.sendall(req)
            resp_hdr = self._recv_exact(ssh_sock, 4)
            if not resp_hdr or resp_hdr[1] != 0:
                return None
            atyp = resp_hdr[3]
            if atyp == 1:
                self._recv_exact(ssh_sock, 6)
            elif atyp == 3:
                dlen_b = self._recv_exact(ssh_sock, 1)
                if dlen_b:
                    self._recv_exact(ssh_sock, dlen_b[0] + 2)
            elif atyp == 4:
                self._recv_exact(ssh_sock, 18)

            tx_id = os.urandom(2)
            dns_pkt = build_dns_query(domain, tx_id)
            ssh_sock.sendall(struct.pack("!H", len(dns_pkt)) + dns_pkt)

            len_hdr = self._recv_exact(ssh_sock, 2)
            if not len_hdr:
                return None
            rlen = struct.unpack("!H", len_hdr)[0]
            rdata = self._recv_exact(ssh_sock, rlen)
            if not rdata:
                return None

            ip_str = parse_dns_a_response(rdata, tx_id)
            if ip_str:
                return socket.inet_aton(ip_str)
        except Exception:
            pass
        finally:
            try:
                ssh_sock.close()
            except Exception:
                pass
        return None

    def _resolve_via_ssh_tcp(self, domain: str, bypass_adblock: bool = False) -> bytes | None:
        """
        Resolves a domain name to an IPv4 address (4 bytes) inside the SSH tunnel.
        Includes AdBlock check, TTL caching, and in-flight request deduplication.
        """
        domain = domain.strip().lower().strip(".")
        if not domain:
            return None
        if is_ipv4_address(domain):
            return socket.inet_aton(domain)

        if not bypass_adblock and self.is_domain_blocked(domain):
            return b"\x00\x00\x00\x00"

        now = time.time()
        wait_event = None
        is_leader = False

        with self.dns_lock:
            cached = self.dns_cache.get(domain)
            if cached and cached[1] > now:
                return cached[0]
            if domain in self.dns_inflight:
                wait_event = self.dns_inflight[domain]
            else:
                wait_event = threading.Event()
                self.dns_inflight[domain] = wait_event
                is_leader = True

        if not is_leader:
            wait_event.wait(timeout=6.0)
            with self.dns_lock:
                cached = self.dns_cache.get(domain)
                return cached[0] if cached else None

        resolved_ip_bytes = None
        try:
            for dns_srv in ("1.1.1.1", "8.8.8.8"):
                resolved_ip_bytes = self._query_dns_over_ssh_single(domain, dns_srv)
                if resolved_ip_bytes:
                    break
        finally:
            with self.dns_lock:
                if resolved_ip_bytes:
                    self.dns_cache[domain] = (resolved_ip_bytes, time.time() + 600.0)
                self.dns_inflight.pop(domain, None)
                wait_event.set()

        return resolved_ip_bytes

    def _connect_to_ssh(self, timeout=6.0):
        start = time.time()
        while self.running and (time.time() - start < timeout):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.settimeout(2.5)
                s.connect(('127.0.0.1', self.internal_ssh_port))
                return s
            except (ConnectionRefusedError, socket.timeout, OSError):
                try:
                    s.close()
                except Exception:
                    pass
                time.sleep(0.08)
        return None

    def _bidirectional_pipe(self, sock1: socket.socket, sock2: socket.socket):
        sock1.settimeout(None)
        sock2.settimeout(None)
        closed = threading.Event()

        def close_both():
            if not closed.is_set():
                closed.set()
                for s in (sock1, sock2):
                    try:
                        s.close()
                    except Exception:
                        pass

        def forward(src, dst):
            try:
                while not closed.is_set() and self.running:
                    chunk = src.recv(65536)
                    if not chunk:
                        try:
                            dst.shutdown(socket.SHUT_WR)
                        except Exception:
                            pass
                        break
                    dst.sendall(chunk)
            except Exception:
                close_both()

        t1 = threading.Thread(target=forward, args=(sock1, sock2), daemon=True)
        t2 = threading.Thread(target=forward, args=(sock2, sock1), daemon=True)
        t1.start()
        t2.start()

    def _tcp_accept_loop(self):
        while self.running:
            try:
                client_sock, _ = self.tcp_server.accept()
                client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                threading.Thread(target=self._handle_tcp_client, args=(client_sock,), daemon=True).start()
            except Exception:
                break

    def _handle_tcp_client(self, client_sock: socket.socket):
        ssh_sock = None
        try:
            client_sock.settimeout(8.0)
            first_byte = self._recv_exact(client_sock, 1)
            if not first_byte:
                client_sock.close()
                return

            # 1. Serve PAC file if browser or WinHTTP requests HTTP GET / HEAD
            if first_byte in (b"G", b"H"):
                http_buf = bytearray(first_byte)
                while b"\r\n\r\n" not in http_buf and len(http_buf) < 8192:
                    chunk = client_sock.recv(1024)
                    if not chunk:
                        break
                    http_buf.extend(chunk)
                client_sock.sendall(self._generate_pac_script())
                try:
                    client_sock.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                client_sock.close()
                return

            # 2. SOCKS4 / SOCKS4a
            if first_byte == b"\x04":
                rest_hdr = self._recv_exact(client_sock, 7)
                if not rest_hdr:
                    client_sock.close()
                    return
                cmd = rest_hdr[0]
                port_bytes = rest_hdr[1:3]
                ip_bytes = rest_hdr[3:7]

                userid = bytearray()
                while True:
                    b_ch = self._recv_exact(client_sock, 1)
                    if not b_ch:
                        client_sock.close()
                        return
                    userid.extend(b_ch)
                    if b_ch == b"\x00":
                        break

                if ip_bytes[:3] == b"\x00\x00\x00" and ip_bytes[3] != 0:
                    domain_buf = bytearray()
                    while True:
                        b_ch = self._recv_exact(client_sock, 1)
                        if not b_ch:
                            client_sock.close()
                            return
                        if b_ch == b"\x00":
                            break
                        domain_buf.extend(b_ch)
                    domain = domain_buf.decode("utf-8", errors="ignore")
                    if self.is_domain_blocked(domain):
                        client_sock.sendall(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
                        client_sock.close()
                        return
                    resolved = self._resolve_via_ssh_tcp(domain) if self.remote_dns else None
                    if resolved == b"\x00\x00\x00\x00":
                        client_sock.sendall(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
                        client_sock.close()
                        return
                    if resolved:
                        out_packet = b"\x04" + bytes([cmd]) + port_bytes + resolved + bytes(userid)
                    else:
                        out_packet = (
                            b"\x04" + rest_hdr + bytes(userid) + bytes(domain_buf) + b"\x00"
                        )
                else:
                    out_packet = b"\x04" + rest_hdr + bytes(userid)

                ssh_sock = self._connect_to_ssh()
                if not ssh_sock:
                    client_sock.close()
                    return
                ssh_sock.sendall(out_packet)
                self._bidirectional_pipe(client_sock, ssh_sock)
                return

            # 3. SOCKS5
            if first_byte == b"\x05":
                nmethods_b = self._recv_exact(client_sock, 1)
                if not nmethods_b:
                    client_sock.close()
                    return
                if not self._recv_exact(client_sock, nmethods_b[0]):
                    client_sock.close()
                    return

                client_sock.sendall(b"\x05\x00")

                req_hdr = self._recv_exact(client_sock, 4)
                if not req_hdr or req_hdr[0] != 5:
                    client_sock.close()
                    return

                cmd = req_hdr[1]
                atyp = req_hdr[3]

                if atyp == 1:  # IPv4
                    dst_addr = self._recv_exact(client_sock, 4)
                    dst_port = self._recv_exact(client_sock, 2)
                    if not dst_addr or not dst_port:
                        client_sock.close()
                        return
                    out_req = req_hdr + dst_addr + dst_port

                elif atyp == 3:  # Domain Name (FQDN)
                    dlen_b = self._recv_exact(client_sock, 1)
                    if not dlen_b:
                        client_sock.close()
                        return
                    dlen = dlen_b[0]
                    domain_bytes = self._recv_exact(client_sock, dlen)
                    dst_port = self._recv_exact(client_sock, 2)
                    if not domain_bytes or not dst_port:
                        client_sock.close()
                        return

                    domain = domain_bytes.decode("utf-8", errors="ignore")
                    if self.is_domain_blocked(domain):
                        # Reply 0x02: Connection not allowed by ruleset
                        client_sock.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                        client_sock.close()
                        return

                    resolved_ipv4 = None
                    if self.remote_dns and cmd == 1:
                        resolved_ipv4 = self._resolve_via_ssh_tcp(domain)
                        if resolved_ipv4 == b"\x00\x00\x00\x00":
                            client_sock.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                            client_sock.close()
                            return

                    if resolved_ipv4:
                        out_req = b"\x05" + bytes([cmd]) + b"\x00\x01" + resolved_ipv4 + dst_port
                    else:
                        out_req = req_hdr + dlen_b + domain_bytes + dst_port

                elif atyp == 4:  # IPv6
                    dst_addr = self._recv_exact(client_sock, 16)
                    dst_port = self._recv_exact(client_sock, 2)
                    if not dst_addr or not dst_port:
                        client_sock.close()
                        return
                    out_req = req_hdr + dst_addr + dst_port
                else:
                    client_sock.close()
                    return

                if cmd == 3 and self.enable_udp:
                    bnd_resp = b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", self.socks_port)
                    client_sock.sendall(bnd_resp)
                    client_sock.settimeout(None)
                    while self.running:
                        chunk = client_sock.recv(1024)
                        if not chunk:
                            break
                    client_sock.close()
                    return

                ssh_sock = self._connect_to_ssh()
                if not ssh_sock:
                    client_sock.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                    client_sock.close()
                    return

                ssh_sock.settimeout(8.0)
                ssh_sock.sendall(b"\x05\x01\x00")
                if self._recv_exact(ssh_sock, 2) != b"\x05\x00":
                    client_sock.close()
                    ssh_sock.close()
                    return

                ssh_sock.sendall(out_req)
                self._bidirectional_pipe(client_sock, ssh_sock)
                return

            client_sock.close()

        except Exception:
            if client_sock:
                try:
                    client_sock.close()
                except Exception:
                    pass
            if ssh_sock:
                try:
                    ssh_sock.close()
                except Exception:
                    pass

    def _udp_relay_loop(self):
        while self.running:
            try:
                data, addr = self.udp_server.recvfrom(65535)
                if len(data) < 10 or data[2] != 0:
                    continue

                atyp = data[3]
                offset = 4
                if atyp == 1:  # IPv4
                    dest_ip_bytes = data[offset:offset + 4]
                    offset += 4
                elif atyp == 3:  # FQDN
                    d_len = data[offset]
                    offset += 1
                    domain = data[offset:offset + d_len].decode('utf-8', errors='ignore')
                    offset += d_len
                    if self.is_domain_blocked(domain):
                        continue
                    dest_ip_bytes = None
                    if self.remote_dns:
                        dest_ip_bytes = self._resolve_via_ssh_tcp(domain)
                        if dest_ip_bytes == b"\x00\x00\x00\x00":
                            continue
                    if not dest_ip_bytes:
                        dest_ip_bytes = socket.inet_aton(socket.gethostbyname(domain))
                else:
                    continue

                dest_port = struct.unpack("!H", data[offset:offset + 2])[0]
                payload = data[offset + 2:]

                # Intercept raw UDP DNS queries (port 53) for blocked domains
                if dest_port == 53 and self.remote_dns and self.adblock_enabled:
                    qdomain, _, _ = parse_dns_question_domain(payload)
                    if qdomain and self.is_domain_blocked(qdomain):
                        sinkhole_pkt = build_dns_sinkhole_response(payload)
                        if sinkhole_pkt:
                            socks5_hdr = b"\x00\x00\x00\x01" + dest_ip_bytes + struct.pack("!H", 53)
                            try:
                                self.udp_sock_send(socks5_hdr + sinkhole_pkt, addr)
                            except Exception:
                                pass
                        continue

                if self.badvpn_client:
                    self.badvpn_client.send_packet(addr, dest_ip_bytes, dest_port, payload)
            except Exception:
                if not self.running:
                    break

    def udp_sock_send(self, pkt: bytes, addr):
        if self.udp_server:
            self.udp_server.sendto(pkt, addr)

    def stop(self):
        self.running = False
        try:
            self.tcp_server.close()
        except Exception:
            pass
        if self.udp_server:
            try:
                self.udp_server.close()
            except Exception:
                pass
        if self.badvpn_client:
            self.badvpn_client.close()


# ----------------- GUI Application -----------------
class SSHTunnelApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SSH Tunnel")
        self.geometry("560x840")
        self.resizable(False, False)
        self.configure(bg="#1E1E24")

        self.is_connected = False
        self.ssh_process = None
        self.bridge = None
        self.askpass_server = None
        self._is_loading_config = False
        self._is_testing = False
        self._is_loading_adblock = False
        self._current_extra_bypass = []

        self.adblock_engine = AdBlockEngine(log_cb=lambda msg: self.after(0, self.log, msg))

        # Profile & Bypass state
        self.profiles: dict[str, dict] = {}
        self.current_profile: str = "Default"
        self._bypass_items: list[str] = []
        self._bypass_win: tk.Toplevel | None = None
        self._bypass_editor: scrolledtext.ScrolledText | None = None

        self._build_ui()
        self.load_config(CONFIG_FILE)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    @staticmethod
    def _default_profile_data(socks_port: str = "1080", bypass_list: str = "") -> dict:
        return {
            "host": "1.2.3.4",
            "port": "22",
            "user": "root",
            "password": "",
            "compression": True,
            "socks_port": socks_port,
            "remote_dns": True,
            "adblock_enabled": True,
            "adblock_filter": DEFAULT_ADBLOCK_FILTER,
            "bypass_list": "\n".join(normalize_bypass_items(bypass_list)),
            "gateway": "disabled",
            "udpgw_port": "7300"
        }

    def _build_ui(self):
        # 1. Main toggle button & status area
        btn_frame = tk.Frame(self, bg="#1E1E24", pady=6)
        btn_frame.pack(fill="x")

        self.canvas_size = 110
        self.canvas = tk.Canvas(
            btn_frame,
            width=self.canvas_size,
            height=self.canvas_size,
            bg="#1E1E24",
            highlightthickness=0,
            cursor="hand2"
        )
        self.canvas.pack()

        pad = 8
        self.circle_btn = self.canvas.create_oval(
            pad, pad, self.canvas_size - pad, self.canvas_size - pad,
            fill="#4A4E58", outline="#2B2D33", width=4
        )
        self.btn_text = self.canvas.create_text(
            self.canvas_size // 2, self.canvas_size // 2,
            text="OFF", fill="#FFFFFF", font=("Segoe UI", 15, "bold")
        )
        self.canvas.tag_bind(self.circle_btn, "<Button-1>", lambda e: self.toggle_connection())
        self.canvas.tag_bind(self.btn_text, "<Button-1>", lambda e: self.toggle_connection())

        # Connection status label
        self.status_lbl = tk.Label(
            btn_frame, text="Disconnected", fg="#8C93A4", bg="#1E1E24", font=("Segoe UI", 11, "bold")
        )
        self.status_lbl.pack(pady=(2, 0))

        # Ping status label
        self.ping_lbl = tk.Label(btn_frame, text="", fg="#10B981", bg="#1E1E24", font=("Segoe UI", 9, "bold"))
        self.ping_lbl.pack(pady=(1, 2))

        # 2. Settings frame
        settings_frame = tk.LabelFrame(
            self, text=" Connection Settings ", bg="#1E1E24", fg="#E0E0E0",
            font=("Segoe UI", 9, "bold"), padx=10, pady=5
        )
        settings_frame.pack(fill="x", padx=15, pady=2)
        settings_frame.grid_columnconfigure(1, weight=1)

        # Row 0: Connection Profiles
        self._add_label(settings_frame, "Profile:", 0, 0)
        profile_bar = tk.Frame(settings_frame, bg="#1E1E24")
        profile_bar.grid(row=0, column=1, columnspan=3, sticky="we", padx=3, pady=(2, 5))

        self.profile_var = tk.StringVar(value="Default")
        self.profile_combo = ttk.Combobox(
            profile_bar, textvariable=self.profile_var, state="readonly", width=22
        )
        self.profile_combo.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self.profile_combo.bind("<<ComboboxSelected>>", self._on_profile_selected)

        tk.Button(
            profile_bar, text="New", command=self.create_profile,
            bg="#32353E", fg="#E0E0E0", relief="flat", padx=8, font=("Segoe UI", 8), cursor="hand2"
        ).pack(side="left", padx=2)

        tk.Button(
            profile_bar, text="Rename", command=self.rename_profile,
            bg="#32353E", fg="#E0E0E0", relief="flat", padx=8, font=("Segoe UI", 8), cursor="hand2"
        ).pack(side="left", padx=2)

        tk.Button(
            profile_bar, text="Delete", command=self.delete_profile,
            bg="#32353E", fg="#E0E0E0", relief="flat", padx=8, font=("Segoe UI", 8), cursor="hand2"
        ).pack(side="left", padx=(2, 0))

        # Row 1: SSH Host & SSH Port
        self._add_label(settings_frame, "SSH Host:", 1, 0)
        self.host_entry = self._add_entry(settings_frame, "1.2.3.4", 1, 1, width=28)

        self._add_label(settings_frame, "SSH Port:", 1, 2)
        self.ssh_port_entry = self._add_entry(settings_frame, "22", 1, 3, width=7)

        # Row 2: Username & SOCKS5 Port
        self._add_label(settings_frame, "Username:", 2, 0)
        self.user_entry = self._add_entry(settings_frame, "root", 2, 1, width=28)

        self._add_label(settings_frame, "SOCKS5 Port:", 2, 2)
        self.socks_port_entry = self._add_entry(settings_frame, "1080", 2, 3, width=7)

        # Row 3: SSH Password & Compression
        self._add_label(settings_frame, "SSH Password:", 3, 0)
        self.pass_entry = self._add_entry(settings_frame, "", 3, 1, width=28, show="*")

        self.compress_var = tk.BooleanVar(value=True)
        self.compress_chk = tk.Checkbutton(
            settings_frame, text="Compression (-C)", variable=self.compress_var,
            bg="#1E1E24", fg="#FFFFFF", selectcolor="#2B2D33",
            activebackground="#1E1E24", activeforeground="#FFFFFF",
            command=self._on_setting_changed
        )
        self.compress_chk.grid(row=3, column=2, columnspan=2, sticky="w", padx=4)

        # Row 4: UDP Gateway & UDP Port
        self._add_label(settings_frame, "UDP Gateway:", 4, 0)
        self.udp_gw_var = tk.StringVar(value="disabled")
        self.udp_gw_combo = ttk.Combobox(
            settings_frame, textvariable=self.udp_gw_var,
            values=["disabled", "badvpn-udpgw"], state="readonly", width=16
        )
        self.udp_gw_combo.grid(row=4, column=1, sticky="w", padx=3, pady=2)
        self.udp_gw_combo.bind("<<ComboboxSelected>>", lambda e: self._on_setting_changed())

        self._add_label(settings_frame, "UDP Port:", 4, 2)
        self.udpgw_port_entry = self._add_entry(settings_frame, "7300", 4, 3, width=7)

        # Row 5: DNS routing option
        self._add_label(settings_frame, "DNS Routing:", 5, 0)
        self.remote_dns_var = tk.BooleanVar(value=True)
        self.remote_dns_chk = tk.Checkbutton(
            settings_frame,
            text="Route browser DNS inside tunnel (Remote DNS -> IPv4)",
            variable=self.remote_dns_var,
            bg="#1E1E24", fg="#FFFFFF", selectcolor="#2B2D33",
            activebackground="#1E1E24", activeforeground="#FFFFFF",
            command=self._on_dns_or_adblock_toggled
        )
        self.remote_dns_chk.grid(row=5, column=1, columnspan=3, sticky="w", padx=1, pady=1)

        # Row 6: DNS AdBlock option
        self._add_label(settings_frame, "DNS AdBlock:", 6, 0)
        adblock_top_bar = tk.Frame(settings_frame, bg="#1E1E24")
        adblock_top_bar.grid(row=6, column=1, columnspan=3, sticky="we", padx=1, pady=1)

        self.adblock_var = tk.BooleanVar(value=True)
        self.adblock_chk = tk.Checkbutton(
            adblock_top_bar,
            text="Block ads & trackers via DNS filter",
            variable=self.adblock_var,
            bg="#1E1E24", fg="#FFFFFF", selectcolor="#2B2D33",
            activebackground="#1E1E24", activeforeground="#FFFFFF",
            disabledforeground="#606575",
            command=self._on_dns_or_adblock_toggled
        )
        self.adblock_chk.pack(side="left")

        self.adblock_status_lbl = tk.Label(
            adblock_top_bar, text="(AdGuard DNS)", bg="#1E1E24", fg="#10B981", font=("Segoe UI", 8)
        )
        self.adblock_status_lbl.pack(side="left", padx=(6, 0))

        # Row 7: AdBlock Filter URL or Local Path
        self._add_label(settings_frame, "Filter Source:", 7, 0)
        adblock_src_bar = tk.Frame(settings_frame, bg="#1E1E24")
        adblock_src_bar.grid(row=7, column=1, columnspan=3, sticky="we", padx=3, pady=2)

        self.adblock_filter_var = tk.StringVar(value=DEFAULT_ADBLOCK_FILTER)
        self.adblock_filter_combo = ttk.Combobox(
            adblock_src_bar,
            textvariable=self.adblock_filter_var,
            values=KNOWN_ADBLOCK_FILTERS,
            width=28
        )
        self.adblock_filter_combo.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self.adblock_filter_combo.bind("<<ComboboxSelected>>", lambda e: self._on_adblock_source_changed(reload_now=True))
        self.adblock_filter_combo.bind("<KeyRelease>", lambda e: self._on_setting_changed())
        self._attach_editable_context_menu(self.adblock_filter_combo, is_text_widget=False)

        self.adblock_file_btn = tk.Button(
            adblock_src_bar, text="File...", command=self.browse_adblock_file,
            bg="#32353E", fg="#E0E0E0", relief="flat", padx=7, font=("Segoe UI", 8), cursor="hand2"
        )
        self.adblock_file_btn.pack(side="left", padx=2)

        self.adblock_reload_btn = tk.Button(
            adblock_src_bar, text="↻ Reload", command=self.reload_adblock_filter_async,
            bg="#32353E", fg="#E0E0E0", relief="flat", padx=7, font=("Segoe UI", 8), cursor="hand2"
        )
        self.adblock_reload_btn.pack(side="left", padx=(2, 0))

        # Row 8: Bypass List (opens in a separate window)
        self._add_label(settings_frame, "Bypass List:", 8, 0)
        bypass_frame = tk.Frame(settings_frame, bg="#1E1E24")
        bypass_frame.grid(row=8, column=1, columnspan=3, sticky="we", padx=3, pady=3)

        self.bypass_btn = tk.Button(
            bypass_frame, text="Edit Bypass List... (0 rules)", command=self.open_bypass_window,
            bg="#2A2C35", fg="#FFFFFF", activebackground="#3A3D4A", activeforeground="#FFFFFF",
            relief="flat", padx=12, pady=3, font=("Segoe UI", 8), cursor="hand2", anchor="w"
        )
        self.bypass_btn.pack(side="left", fill="x", expand=True)

        # Row 9: Action buttons
        io_btn_frame = tk.Frame(settings_frame, bg="#1E1E24")
        io_btn_frame.grid(row=9, column=0, columnspan=4, pady=(6, 2), sticky="e")

        self.test_btn = tk.Button(
            io_btn_frame, text="⚡ Test", command=self.run_test,
            bg="#2563EB", fg="#FFFFFF", activebackground="#1D4ED8", activeforeground="#FFFFFF",
            relief="flat", padx=10, font=("Segoe UI", 8, "bold"), cursor="hand2"
        )
        self.test_btn.pack(side="left", padx=4)

        import_btn = tk.Button(
            io_btn_frame, text="Import .ini...", command=self.import_config,
            bg="#32353E", fg="#E0E0E0", relief="flat", padx=8, font=("Segoe UI", 8), cursor="hand2"
        )
        import_btn.pack(side="left", padx=4)

        export_btn = tk.Button(
            io_btn_frame, text="Export .ini...", command=self.export_config,
            bg="#32353E", fg="#E0E0E0", relief="flat", padx=8, font=("Segoe UI", 8), cursor="hand2"
        )
        export_btn.pack(side="left", padx=4)

        # 3. Log console
        log_frame = tk.LabelFrame(
            self, text=" SSH & Bridge Log ", bg="#1E1E24", fg="#E0E0E0",
            font=("Segoe UI", 9, "bold"), padx=5, pady=5
        )
        log_frame.pack(fill="both", expand=True, padx=15, pady=4)

        self.log_area = scrolledtext.ScrolledText(
            log_frame, bg="#121316", fg="#00FF66", insertbackground="white",
            font=("Consolas", 8), state="disabled", wrap="word"
        )
        self.log_area.pack(fill="both", expand=True)
        self._attach_log_context_menu(self.log_area)

    def _add_label(self, parent, text, r, c):
        lbl = tk.Label(parent, text=text, bg="#1E1E24", fg="#A0A5B5", font=("Segoe UI", 8))
        lbl.grid(row=r, column=c, sticky="ne", padx=3, pady=2)
        return lbl

    def _add_entry(self, parent, default_val, r, c, columnspan=1, width=16, show=None):
        entry = tk.Entry(parent, width=width, bg="#2A2C35", fg="#FFFFFF", insertbackground="white", relief="flat")
        if show:
            entry.config(show=show)
        entry.insert(0, default_val)
        entry.grid(row=r, column=c, columnspan=columnspan, sticky="we", padx=3, pady=2)
        entry.bind("<KeyRelease>", lambda event: self._on_setting_changed())
        if show == "*":
            self._attach_password_context_menu(entry)
        else:
            self._attach_editable_context_menu(entry, is_text_widget=False)
        return entry

    # ----------------- AdBlock UI & Loader Helpers -----------------
    def _update_adblock_ui_state(self):
        remote_dns_on = bool(self.remote_dns_var.get())
        adblock_on = bool(self.adblock_var.get())

        if not remote_dns_on:
            self.adblock_chk.config(state="disabled")
            self.adblock_filter_combo.config(state="disabled")
            self.adblock_file_btn.config(state="disabled")
            self.adblock_reload_btn.config(state="disabled")
            self.adblock_status_lbl.config(text="(Requires Remote DNS)", fg="#8C93A4")
        else:
            self.adblock_chk.config(state="normal")
            sub_state = "normal" if adblock_on else "disabled"
            self.adblock_filter_combo.config(state=sub_state)
            self.adblock_file_btn.config(state=sub_state)
            self.adblock_reload_btn.config(state=sub_state)
            if not adblock_on:
                self.adblock_status_lbl.config(text="(Disabled)", fg="#8C93A4")
            else:
                rc = self.adblock_engine.rule_count
                if rc > 0:
                    self.adblock_status_lbl.config(text=f"({rc:,} rules active)", fg="#10B981")
                else:
                    self.adblock_status_lbl.config(text="(Loads via tunnel on connect)", fg="#F59E0B")

    def _on_dns_or_adblock_toggled(self):
        self._update_adblock_ui_state()
        self._on_setting_changed()
        if self.is_connected and self.remote_dns_var.get() and self.adblock_var.get():
            if self.adblock_engine.rule_count == 0:
                self.reload_adblock_filter_async()

    def _on_adblock_source_changed(self, reload_now: bool = False):
        self._on_setting_changed()
        if reload_now:
            self.reload_adblock_filter_async()

    def browse_adblock_file(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("Filter / Hosts files", "*.txt *.list *.hosts *.*"), ("All files", "*.*")],
            title="Select local DNS AdBlock filter file"
        )
        if filepath:
            self.adblock_filter_var.set(filepath)
            self._on_adblock_source_changed(reload_now=True)

    def reload_adblock_filter_async(self):
        if self._is_loading_adblock:
            return
        if not (self.remote_dns_var.get() and self.adblock_var.get()):
            return

        source = self.adblock_filter_var.get().strip()
        if not source:
            source = DEFAULT_ADBLOCK_FILTER
            self.adblock_filter_var.set(source)

        is_remote_url = any(
            s.strip().lower().startswith(("http://", "https://"))
            for s in source.split(";") if s.strip()
        )
        if is_remote_url and not (self.is_connected and self.bridge):
            self.log("> [AdBlock] Filter URL saved. It will be downloaded through the SSH tunnel upon connection.")
            self._update_adblock_ui_state()
            return

        self._is_loading_adblock = True
        self.adblock_status_lbl.config(text="(Loading filter...)", fg="#F59E0B")
        self.adblock_reload_btn.config(state="disabled")

        def worker():
            try:
                ssh_port = self.bridge.internal_ssh_port if self.bridge else None
                resolver_fn = (
                    (lambda d: self.bridge._resolve_via_ssh_tcp(d, bypass_adblock=True))
                    if self.bridge else None
                )
                ok, b_count, _ = self.adblock_engine.load_from_source(
                    source_spec=source,
                    internal_ssh_port=ssh_port,
                    dns_resolver_fn=resolver_fn
                )
                if self.bridge:
                    self.bridge.clear_dns_cache()

                def finish_ui():
                    self._is_loading_adblock = False
                    self._update_adblock_ui_state()
                    if not ok and b_count == 0:
                        self.adblock_status_lbl.config(text="(Load failed — check log)", fg="#EF4444")

                self.after(0, finish_ui)
            except Exception as e:
                def err_ui():
                    self._is_loading_adblock = False
                    self._update_adblock_ui_state()
                    self.log(f"> [AdBlock] Unexpected error: {e}")
                self.after(0, err_ui)

        threading.Thread(target=worker, daemon=True).start()

    # ----------------- Context Menus for Text Fields -----------------
    def _has_clipboard_text(self) -> bool:
        try:
            return bool(self.clipboard_get())
        except tk.TclError:
            return False

    def _attach_editable_context_menu(self, widget: tk.Widget, is_text_widget: bool = False):
        menu = tk.Menu(
            widget, tearoff=0, bg="#2A2C35", fg="#FFFFFF",
            activebackground="#2563EB", activeforeground="#FFFFFF", font=("Segoe UI", 9)
        )

        def has_selection() -> bool:
            try:
                if is_text_widget:
                    return bool(widget.tag_ranges(tk.SEL))
                return widget.selection_present()
            except tk.TclError:
                return False

        def has_any_text() -> bool:
            if is_text_widget:
                return bool(widget.get("1.0", "end-1c"))
            return bool(widget.get())

        def do_cut():
            widget.event_generate("<<Cut>>")
            self.after(10, self._on_setting_changed)

        def do_copy():
            widget.event_generate("<<Copy>>")

        def do_paste():
            widget.event_generate("<<Paste>>")
            self.after(10, self._on_setting_changed)

        def do_delete():
            try:
                if is_text_widget:
                    if widget.tag_ranges(tk.SEL):
                        widget.delete(tk.SEL_FIRST, tk.SEL_LAST)
                else:
                    if widget.selection_present():
                        widget.delete(tk.SEL_FIRST, tk.SEL_LAST)
                self._on_setting_changed()
            except tk.TclError:
                pass

        def do_select_all():
            widget.focus_set()
            if is_text_widget:
                widget.tag_add(tk.SEL, "1.0", "end-1c")
                widget.mark_set(tk.INSERT, "end-1c")
            else:
                widget.select_range(0, tk.END)
                widget.icursor(tk.END)

        menu.add_command(label="Cut", command=do_cut)
        menu.add_command(label="Copy", command=do_copy)
        menu.add_command(label="Paste", command=do_paste)
        menu.add_command(label="Delete", command=do_delete)
        menu.add_separator()
        menu.add_command(label="Select All", command=do_select_all)

        def show_menu(event):
            widget.focus_set()
            sel_state = "normal" if has_selection() else "disabled"
            paste_state = "normal" if self._has_clipboard_text() else "disabled"
            all_state = "normal" if has_any_text() else "disabled"

            menu.entryconfig("Cut", state=sel_state)
            menu.entryconfig("Copy", state=sel_state)
            menu.entryconfig("Paste", state=paste_state)
            menu.entryconfig("Delete", state=sel_state)
            menu.entryconfig("Select All", state=all_state)
            menu.tk_popup(event.x_root, event.y_root)

        widget.bind("<Button-3>", show_menu)

    def _attach_password_context_menu(self, entry: tk.Entry):
        menu = tk.Menu(
            entry, tearoff=0, bg="#2A2C35", fg="#FFFFFF",
            activebackground="#2563EB", activeforeground="#FFFFFF", font=("Segoe UI", 9)
        )

        def toggle_visibility():
            current_show = entry.cget("show")
            entry.config(show="" if current_show == "*" else "*")

        def do_copy():
            entry.event_generate("<<Copy>>")

        def do_paste():
            entry.event_generate("<<Paste>>")
            self.after(10, self._on_setting_changed)

        def do_clear():
            entry.delete(0, tk.END)
            self._on_setting_changed()

        def do_select_all():
            entry.focus_set()
            entry.select_range(0, tk.END)
            entry.icursor(tk.END)

        menu.add_command(label="Show Password", command=toggle_visibility)
        menu.add_separator()
        menu.add_command(label="Copy", command=do_copy)
        menu.add_command(label="Paste", command=do_paste)
        menu.add_command(label="Clear", command=do_clear)
        menu.add_separator()
        menu.add_command(label="Select All", command=do_select_all)

        def show_menu(event):
            entry.focus_set()
            is_hidden = (entry.cget("show") == "*")
            menu.entryconfig(0, label="Show Password" if is_hidden else "Hide Password")
            has_sel = entry.selection_present()
            has_text = bool(entry.get())
            menu.entryconfig("Copy", state="normal" if (has_sel and not is_hidden) else "disabled")
            menu.entryconfig("Paste", state="normal" if self._has_clipboard_text() else "disabled")
            menu.entryconfig("Clear", state="normal" if has_text else "disabled")
            menu.entryconfig("Select All", state="normal" if has_text else "disabled")
            menu.tk_popup(event.x_root, event.y_root)

        entry.bind("<Button-3>", show_menu)

    def _attach_log_context_menu(self, text_widget: scrolledtext.ScrolledText):
        menu = tk.Menu(
            text_widget, tearoff=0, bg="#2A2C35", fg="#FFFFFF",
            activebackground="#2563EB", activeforeground="#FFFFFF", font=("Segoe UI", 9)
        )

        def do_copy():
            try:
                selected = text_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
                self.clipboard_clear()
                self.clipboard_append(selected)
            except tk.TclError:
                pass

        def do_select_all():
            text_widget.focus_set()
            text_widget.tag_add(tk.SEL, "1.0", "end-1c")

        def do_clear_log():
            text_widget.config(state="normal")
            text_widget.delete("1.0", tk.END)
            text_widget.config(state="disabled")

        menu.add_command(label="Copy", command=do_copy)
        menu.add_command(label="Select All", command=do_select_all)
        menu.add_separator()
        menu.add_command(label="Clear Log", command=do_clear_log)

        def show_menu(event):
            text_widget.focus_set()
            has_sel = bool(text_widget.tag_ranges(tk.SEL))
            has_text = bool(text_widget.get("1.0", "end-1c").strip())
            menu.entryconfig("Copy", state="normal" if has_sel else "disabled")
            menu.entryconfig("Select All", state="normal" if has_text else "disabled")
            menu.entryconfig("Clear Log", state="normal" if has_text else "disabled")
            menu.tk_popup(event.x_root, event.y_root)

        text_widget.bind("<Button-3>", show_menu)

    # ----------------- Separate Bypass List Window -----------------
    def _get_bypass_val(self) -> str:
        return "\n".join(self._bypass_items)

    def _set_bypass_val(self, val: str):
        self._bypass_items = normalize_bypass_items(val)
        count = len(self._bypass_items)
        rule_word = "rule" if count == 1 else "rules"
        self.bypass_btn.config(text=f"Edit Bypass List... ({count} {rule_word})")

        if self._bypass_win is not None and self._bypass_win.winfo_exists() and self._bypass_editor is not None:
            current_editor_items = normalize_bypass_items(self._bypass_editor.get("1.0", "end-1c"))
            if current_editor_items != self._bypass_items:
                self._bypass_editor.delete("1.0", tk.END)
                self._bypass_editor.insert("1.0", "\n".join(self._bypass_items))

    def open_bypass_window(self):
        if self._bypass_win is not None and self._bypass_win.winfo_exists():
            self._bypass_win.lift()
            self._bypass_win.focus_force()
            return

        win = tk.Toplevel(self)
        win.title("Bypass List — SSH Tunnel")
        win.geometry("420x380")
        win.minsize(340, 260)
        win.configure(bg="#1E1E24")
        win.transient(self)
        self._bypass_win = win

        header_lbl = tk.Label(
            win,
            text="Enter hosts, domains, or subnets to bypass proxy (one entry per line):",
            bg="#1E1E24", fg="#A0A5B5", font=("Segoe UI", 8, "bold"), anchor="w"
        )
        header_lbl.pack(fill="x", padx=12, pady=(10, 4))

        editor = scrolledtext.ScrolledText(
            win, bg="#2A2C35", fg="#FFFFFF", insertbackground="white",
            relief="flat", font=("Consolas", 9), wrap="none"
        )
        editor.pack(fill="both", expand=True, padx=12, pady=4)
        editor.insert("1.0", "\n".join(self._bypass_items))
        self._bypass_editor = editor

        def sync_from_editor(event=None):
            raw_text = editor.get("1.0", "end-1c")
            self._bypass_items = normalize_bypass_items(raw_text)
            count = len(self._bypass_items)
            rule_word = "rule" if count == 1 else "rules"
            self.bypass_btn.config(text=f"Edit Bypass List... ({count} {rule_word})")
            self._on_setting_changed()

        editor.bind("<KeyRelease>", sync_from_editor)
        self._attach_editable_context_menu(editor, is_text_widget=True)

        btn_bar = tk.Frame(win, bg="#1E1E24")
        btn_bar.pack(fill="x", padx=12, pady=(4, 10))

        info_lbl = tk.Label(
            btn_bar, text="Localhost addresses are bypassed automatically.",
            bg="#1E1E24", fg="#8C93A4", font=("Segoe UI", 8)
        )
        info_lbl.pack(side="left")

        def save_and_close():
            sync_from_editor()
            win.destroy()

        close_btn = tk.Button(
            btn_bar, text="Done", command=save_and_close,
            bg="#2563EB", fg="#FFFFFF", activebackground="#1D4ED8", activeforeground="#FFFFFF",
            relief="flat", padx=14, pady=2, font=("Segoe UI", 8, "bold"), cursor="hand2"
        )
        close_btn.pack(side="right")

        win.protocol("WM_DELETE_WINDOW", save_and_close)
        editor.focus_set()

    # ----------------- Connection Profiles Management -----------------
    def _collect_ui_profile_data(self) -> dict:
        return {
            "host": self.host_entry.get().strip(),
            "port": self.ssh_port_entry.get().strip(),
            "user": self.user_entry.get().strip(),
            "password": self.pass_entry.get(),
            "compression": bool(self.compress_var.get()),
            "socks_port": self.socks_port_entry.get().strip(),
            "remote_dns": bool(self.remote_dns_var.get()),
            "adblock_enabled": bool(self.adblock_var.get()),
            "adblock_filter": self.adblock_filter_var.get().strip() or DEFAULT_ADBLOCK_FILTER,
            "bypass_list": self._get_bypass_val(),
            "gateway": self.udp_gw_var.get(),
            "udpgw_port": self.udpgw_port_entry.get().strip()
        }

    def _apply_profile_to_ui(self, profile_name: str):
        data = self.profiles.get(profile_name, self._default_profile_data())
        self._is_loading_config = True
        try:
            self.current_profile = profile_name
            self.profile_var.set(profile_name)
            self.profile_combo["values"] = list(self.profiles.keys())

            self._set_entry_val(self.host_entry, data.get("host", "1.2.3.4"))
            self._set_entry_val(self.ssh_port_entry, data.get("port", "22"))
            self._set_entry_val(self.user_entry, data.get("user", "root"))
            self._set_entry_val(self.pass_entry, data.get("password", ""))
            self.compress_var.set(bool(data.get("compression", True)))

            self._set_entry_val(self.socks_port_entry, data.get("socks_port", "1080"))
            self.remote_dns_var.set(bool(data.get("remote_dns", True)))
            self.adblock_var.set(bool(data.get("adblock_enabled", True)))
            self.adblock_filter_var.set(data.get("adblock_filter", DEFAULT_ADBLOCK_FILTER) or DEFAULT_ADBLOCK_FILTER)
            self._set_bypass_val(data.get("bypass_list", ""))

            self.udp_gw_var.set(data.get("gateway", "disabled"))
            self._set_entry_val(self.udpgw_port_entry, data.get("udpgw_port", "7300"))
            self._update_adblock_ui_state()
        finally:
            self._is_loading_config = False

    def _on_profile_selected(self, event=None):
        selected = self.profile_var.get().strip()
        if not selected or selected == self.current_profile:
            return
        self.profiles[self.current_profile] = self._collect_ui_profile_data()
        self._apply_profile_to_ui(selected)
        self.save_config(CONFIG_FILE)
        self.log(f"> Switched to profile: '{selected}'")

    def create_profile(self):
        name = simpledialog.askstring("New Profile", "Enter new profile name:", parent=self)
        if not name:
            return
        name = name.strip()
        if not name:
            return
        if name in self.profiles:
            messagebox.showwarning("Profile Exists", f"Profile '{name}' already exists!", parent=self)
            return

        self.profiles[self.current_profile] = self._collect_ui_profile_data()
        self.profiles[name] = dict(self.profiles[self.current_profile])
        self._apply_profile_to_ui(name)
        self.save_config(CONFIG_FILE)
        self.log(f"> Created profile: '{name}'")

    def rename_profile(self):
        old_name = self.current_profile
        new_name = simpledialog.askstring(
            "Rename Profile", f"Enter new name for profile '{old_name}':",
            initialvalue=old_name, parent=self
        )
        if not new_name:
            return
        new_name = new_name.strip()
        if not new_name or new_name == old_name:
            return
        if new_name in self.profiles:
            messagebox.showwarning("Profile Exists", f"Profile '{new_name}' already exists!", parent=self)
            return

        updated_profiles = {}
        for k, v in self.profiles.items():
            if k == old_name:
                updated_profiles[new_name] = self._collect_ui_profile_data()
            else:
                updated_profiles[k] = v
        self.profiles = updated_profiles
        self._apply_profile_to_ui(new_name)
        self.save_config(CONFIG_FILE)
        self.log(f"> Renamed profile '{old_name}' -> '{new_name}'")

    def delete_profile(self):
        if len(self.profiles) <= 1:
            messagebox.showwarning("Delete Profile", "Cannot delete the only remaining profile!", parent=self)
            return

        target = self.current_profile
        if not messagebox.askyesno("Delete Profile", f"Delete profile '{target}'?", parent=self):
            return

        self.profiles.pop(target, None)
        next_profile = next(iter(self.profiles.keys()))
        self._apply_profile_to_ui(next_profile)
        self.save_config(CONFIG_FILE)
        self.log(f"> Deleted profile '{target}'. Active profile: '{next_profile}'")

    def _on_setting_changed(self):
        if not self._is_loading_config:
            self.profiles[self.current_profile] = self._collect_ui_profile_data()
            self.save_config(CONFIG_FILE)
            if self.is_connected and self.bridge:
                remote_dns = self.remote_dns_var.get()
                adblock_enabled = self.adblock_var.get()
                socks_port = self.socks_port_entry.get().strip()
                bypass = self._get_bypass_val()
                self.bridge.remote_dns = remote_dns
                self.bridge.adblock_enabled = adblock_enabled
                self.bridge.bypass_list = bypass
                self.bridge.clear_dns_cache()
                set_system_proxy(
                    True,
                    socks_port=socks_port,
                    bypass_list=bypass,
                    remote_dns=remote_dns,
                    extra_bypass=self._current_extra_bypass
                )

    @staticmethod
    def _format_bypass_for_ini(bypass_str: str) -> str:
        items = normalize_bypass_items(bypass_str)
        return ("\n" + "\n".join(f"    {item}" for item in items)) if items else ""

    def save_config(self, filepath: str, single_profile_only: bool = False):
        self.profiles[self.current_profile] = self._collect_ui_profile_data()
        config = configparser.ConfigParser(comment_prefixes=('#',), inline_comment_prefixes=None)

        cur_data = self.profiles[self.current_profile]

        # Keep standard [SSH], [PROXY], [UDP] sections for single-profile compatibility
        config["SSH"] = {
            "host": cur_data["host"],
            "port": cur_data["port"],
            "user": cur_data["user"],
            "password": cur_data["password"],
            "compression": str(cur_data["compression"])
        }
        config["PROXY"] = {
            "socks_port": cur_data["socks_port"],
            "remote_dns": str(cur_data["remote_dns"]),
            "adblock_enabled": str(cur_data["adblock_enabled"]),
            "adblock_filter": cur_data["adblock_filter"],
            "bypass_list": self._format_bypass_for_ini(cur_data["bypass_list"])
        }
        config["UDP"] = {
            "gateway": cur_data["gateway"],
            "udpgw_port": cur_data["udpgw_port"]
        }

        if not single_profile_only:
            config["GENERAL"] = {
                "active_profile": self.current_profile
            }
            for prof_name, pdata in self.profiles.items():
                sec_name = f"PROFILE:{prof_name}"
                config[sec_name] = {
                    "host": pdata.get("host", "1.2.3.4"),
                    "port": pdata.get("port", "22"),
                    "user": pdata.get("user", "root"),
                    "password": pdata.get("password", ""),
                    "compression": str(pdata.get("compression", True)),
                    "socks_port": pdata.get("socks_port", "1080"),
                    "remote_dns": str(pdata.get("remote_dns", True)),
                    "adblock_enabled": str(pdata.get("adblock_enabled", True)),
                    "adblock_filter": pdata.get("adblock_filter", DEFAULT_ADBLOCK_FILTER),
                    "bypass_list": self._format_bypass_for_ini(pdata.get("bypass_list", "")),
                    "gateway": pdata.get("gateway", "disabled"),
                    "udpgw_port": pdata.get("udpgw_port", "7300")
                }

        try:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                config.write(f)
        except Exception as e:
            self.log(f"> Error saving configuration: {e}")

    def load_config(self, filepath: str):
        self._is_loading_config = True

        if not os.path.exists(filepath):
            self.log("> Config file not found. Reading settings from system proxy...")
            sys_port, sys_bypass = read_system_proxy_settings()
            self.profiles = {"Default": self._default_profile_data(sys_port, sys_bypass)}
            self._apply_profile_to_ui("Default")
            self._is_loading_config = False
            self.save_config(filepath)
            return

        config = configparser.ConfigParser(comment_prefixes=('#',), inline_comment_prefixes=None)
        try:
            config.read(filepath, encoding="utf-8")
            loaded_profiles = {}

            for sec in config.sections():
                if sec.startswith("PROFILE:"):
                    prof_name = sec[len("PROFILE:"):].strip()
                    if not prof_name:
                        continue
                    s = config[sec]
                    loaded_profiles[prof_name] = {
                        "host": s.get("host", "1.2.3.4"),
                        "port": s.get("port", "22"),
                        "user": s.get("user", "root"),
                        "password": s.get("password", ""),
                        "compression": s.getboolean("compression", fallback=True),
                        "socks_port": s.get("socks_port", "1080"),
                        "remote_dns": s.getboolean("remote_dns", fallback=True),
                        "adblock_enabled": s.getboolean("adblock_enabled", fallback=True),
                        "adblock_filter": s.get("adblock_filter", DEFAULT_ADBLOCK_FILTER),
                        "bypass_list": "\n".join(normalize_bypass_items(s.get("bypass_list", ""))),
                        "gateway": s.get("gateway", "disabled"),
                        "udpgw_port": s.get("udpgw_port", "7300")
                    }

            # Fallback for legacy single-profile .ini files
            if not loaded_profiles:
                ssh_sec = config["SSH"] if "SSH" in config else {}
                proxy_sec = config["PROXY"] if "PROXY" in config else {}
                udp_sec = config["UDP"] if "UDP" in config else {}
                loaded_profiles["Default"] = {
                    "host": ssh_sec.get("host", "1.2.3.4"),
                    "port": ssh_sec.get("port", "22"),
                    "user": ssh_sec.get("user", "root"),
                    "password": ssh_sec.get("password", ""),
                    "compression": ssh_sec.getboolean("compression", fallback=True) if hasattr(ssh_sec, "getboolean") else True,
                    "socks_port": proxy_sec.get("socks_port", "1080"),
                    "remote_dns": proxy_sec.getboolean("remote_dns", fallback=True) if hasattr(proxy_sec, "getboolean") else True,
                    "adblock_enabled": proxy_sec.getboolean("adblock_enabled", fallback=True) if hasattr(proxy_sec, "getboolean") else True,
                    "adblock_filter": proxy_sec.get("adblock_filter", DEFAULT_ADBLOCK_FILTER),
                    "bypass_list": "\n".join(normalize_bypass_items(proxy_sec.get("bypass_list", ""))),
                    "gateway": udp_sec.get("gateway", "disabled"),
                    "udpgw_port": udp_sec.get("udpgw_port", "7300")
                }

            active_prof = "Default"
            if "GENERAL" in config:
                active_prof = config["GENERAL"].get("active_profile", "Default")
            if active_prof not in loaded_profiles:
                active_prof = next(iter(loaded_profiles.keys()))

            self.profiles = loaded_profiles
            self._apply_profile_to_ui(active_prof)
            self.log(f"> Settings loaded from: {os.path.basename(filepath)} (Profile: {active_prof})")
        except Exception as e:
            self.log(f"> Error reading {filepath}: {e}")
        finally:
            self._is_loading_config = False

    def _set_entry_val(self, entry: tk.Entry, val: str):
        entry.delete(0, tk.END)
        entry.insert(0, val)

    def export_config(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".ini",
            initialfile=f"{self.current_profile}.ini",
            filetypes=[("INI files", "*.ini"), ("All files", "*.*")],
            title="Export profile to file"
        )
        if filepath:
            self.save_config(filepath, single_profile_only=True)
            messagebox.showinfo("Export", f"Profile '{self.current_profile}' exported successfully to:\n{filepath}")

    def import_config(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("INI files", "*.ini"), ("All files", "*.*")],
            title="Import profile from file"
        )
        if not filepath:
            return

        config = configparser.ConfigParser(comment_prefixes=('#',), inline_comment_prefixes=None)
        try:
            config.read(filepath, encoding="utf-8")
            ssh_sec = config["SSH"] if "SSH" in config else {}
            proxy_sec = config["PROXY"] if "PROXY" in config else {}
            udp_sec = config["UDP"] if "UDP" in config else {}

            imported_data = {
                "host": ssh_sec.get("host", "1.2.3.4"),
                "port": ssh_sec.get("port", "22"),
                "user": ssh_sec.get("user", "root"),
                "password": ssh_sec.get("password", ""),
                "compression": ssh_sec.getboolean("compression", fallback=True) if hasattr(ssh_sec, "getboolean") else True,
                "socks_port": proxy_sec.get("socks_port", "1080"),
                "remote_dns": proxy_sec.getboolean("remote_dns", fallback=True) if hasattr(proxy_sec, "getboolean") else True,
                "adblock_enabled": proxy_sec.getboolean("adblock_enabled", fallback=True) if hasattr(proxy_sec, "getboolean") else True,
                "adblock_filter": proxy_sec.get("adblock_filter", DEFAULT_ADBLOCK_FILTER),
                "bypass_list": "\n".join(normalize_bypass_items(proxy_sec.get("bypass_list", ""))),
                "gateway": udp_sec.get("gateway", "disabled"),
                "udpgw_port": udp_sec.get("udpgw_port", "7300")
            }

            base_name = os.path.splitext(os.path.basename(filepath))[0].strip() or "Imported"
            prof_name = base_name
            if prof_name in self.profiles:
                ans = messagebox.askyesno(
                    "Import Profile",
                    f"Overwrite existing profile '{prof_name}'?\n"
                    f"(Click 'No' to import as a new profile)",
                    parent=self
                )
                if not ans:
                    idx = 2
                    while f"{base_name} ({idx})" in self.profiles:
                        idx += 1
                    prof_name = f"{base_name} ({idx})"

            self.profiles[self.current_profile] = self._collect_ui_profile_data()
            self.profiles[prof_name] = imported_data
            self._apply_profile_to_ui(prof_name)
            self.save_config(CONFIG_FILE)
            self.log(f"> Imported profile '{prof_name}' from {os.path.basename(filepath)}")
            messagebox.showinfo("Import", f"Profile '{prof_name}' loaded successfully from:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import {filepath}:\n{e}")

    def log(self, text: str):
        self.log_area.config(state="normal")
        self.log_area.insert("end", text + "\n")
        self.log_area.see("end")
        self.log_area.config(state="disabled")

    # ----------------- Connection Diagnostics (TCP & UDP) -----------------
    def run_test(self):
        if self._is_testing:
            return
        if not self.is_connected:
            self.log("> [Test] Tunnel is OFF. Please connect first (press ON)!")
            return

        self._is_testing = True
        self.test_btn.config(state="disabled")
        threading.Thread(target=self._test_worker, daemon=True).start()

    def _test_worker(self):
        socks_port_str = self.socks_port_entry.get().strip()
        socks_port = int(socks_port_str) if socks_port_str.isdigit() else 1080
        udp_gw_mode = self.udp_gw_var.get()

        self.after(0, lambda: self.ping_lbl.config(text="Testing...", fg="#8C93A4"))
        self.log("> ========================================")
        self.log(f"> [Test] Starting diagnostics via SOCKS5 :{socks_port}...")

        tcp_ok = False
        tcp_ms = 0.0
        tcp_status = ""

        # 1. Test TCP connection + Remote DNS via google.com:80 (ATYP=0x03)
        try:
            t0 = time.perf_counter()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_sock:
                tcp_sock.settimeout(6.0)
                tcp_sock.connect(('127.0.0.1', socks_port))

                tcp_sock.sendall(b"\x05\x01\x00")
                hs_resp = tcp_sock.recv(2)
                if hs_resp != b"\x05\x00":
                    raise Exception("SOCKS5 Handshake rejected")

                target_host = b"google.com"
                req = b"\x05\x01\x00\x03" + bytes([len(target_host)]) + target_host + struct.pack("!H", 80)
                tcp_sock.sendall(req)

                conn_resp = tcp_sock.recv(1024)
                if len(conn_resp) < 4 or conn_resp[1] != 0:
                    raise Exception(
                        f"SOCKS5 CONNECT failed (code: {conn_resp[1] if len(conn_resp) > 1 else 'unknown'})"
                    )

                http_req = (
                    b"HEAD / HTTP/1.1\r\nHost: google.com\r\n"
                    b"User-Agent: SSH-Tunnel-Tester\r\nConnection: close\r\n\r\n"
                )
                tcp_sock.sendall(http_req)

                http_resp = tcp_sock.recv(512)
                tcp_ms = (time.perf_counter() - t0) * 1000.0
                tcp_ok = True

                if http_resp:
                    first_line = http_resp.split(b"\r\n")[0].decode('utf-8', errors='ignore')
                    self.log(f"> [TCP + Remote DNS Test] SUCCESS: google.com:80 -> {first_line} ({tcp_ms:.1f} ms)")
                else:
                    self.log(f"> [TCP + Remote DNS Test] SUCCESS: Connection established ({tcp_ms:.1f} ms)")
        except Exception as e:
            tcp_status = "Error"
            self.log(f"> [TCP Test] ERROR: {e}")

        # 2. Test AdBlock status if enabled
        if self.remote_dns_var.get() and self.adblock_var.get():
            rc = self.adblock_engine.rule_count
            ec = self.adblock_engine.exception_count
            if rc > 0:
                self.log(f"> [AdBlock Test] ACTIVE: {rc:,} blocked domains, {ec:,} exceptions loaded.")
            else:
                self.log("> [AdBlock Test] Filter is currently loading or has 0 rules.")

        # 3. Test UDP via DNS request to 8.8.8.8:53
        udp_ok = False
        udp_ms = 0.0
        udp_status = ""

        if udp_gw_mode == "badvpn-udpgw":
            try:
                t0 = time.perf_counter()
                tcp_ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp_ctrl.settimeout(6.0)
                tcp_ctrl.connect(('127.0.0.1', socks_port))

                tcp_ctrl.sendall(b"\x05\x01\x00")
                if tcp_ctrl.recv(2) != b"\x05\x00":
                    raise Exception("Handshake rejected")

                tcp_ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
                reply = tcp_ctrl.recv(1024)
                if len(reply) < 10 or reply[1] != 0:
                    raise Exception(f"UDP ASSOCIATE rejected (code {reply[1] if len(reply) > 1 else '?'})")

                relay_port = struct.unpack("!H", reply[8:10])[0]

                tx_id = b"\x24\x42"
                dns_req = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
                socks5_udp_hdr = b"\x00\x00\x00\x01" + socket.inet_aton("8.8.8.8") + struct.pack("!H", 53)

                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                    udp_sock.settimeout(5.0)
                    udp_sock.sendto(socks5_udp_hdr + dns_req, ('127.0.0.1', relay_port))
                    data, _ = udp_sock.recvfrom(4096)
                    udp_ms = (time.perf_counter() - t0) * 1000.0

                    if len(data) >= 12 and data[10:12] == tx_id:
                        udp_ok = True
                        self.log(f"> [UDP Test] SUCCESS: 8.8.8.8:53 -> DNS response received ({udp_ms:.1f} ms)")
                    else:
                        udp_status = "ID mismatch"
                        self.log(f"> [UDP Test] Packet received, but transaction ID mismatch ({udp_ms:.1f} ms)")

                tcp_ctrl.close()
            except socket.timeout:
                udp_status = "Timeout"
                self.log("> [UDP Test] TIMEOUT: No response from 8.8.8.8 within 5 sec.")
            except Exception as e:
                udp_status = "Error"
                self.log(f"> [UDP Test] ERROR: {e}")
        else:
            self.log("> [UDP Test] SKIPPED: UDP Gateway is set to disabled.")

        self.log("> ========================================")

        parts = []
        if tcp_ok:
            parts.append(f"TCP: {tcp_ms:.0f} ms")
        else:
            parts.append(f"TCP: {tcp_status or 'Error'}")

        if udp_gw_mode == "badvpn-udpgw":
            if udp_ok:
                parts.append(f"UDP: {udp_ms:.0f} ms")
            else:
                parts.append(f"UDP: {udp_status or 'Error'}")

        ping_summary = "  •  ".join(parts)
        all_ok = tcp_ok and (udp_ok if udp_gw_mode == "badvpn-udpgw" else True)
        color = "#10B981" if all_ok else "#F59E0B"

        self.after(0, lambda: self.ping_lbl.config(text=ping_summary, fg=color))
        self._is_testing = False
        self.after(0, lambda: self.test_btn.config(state="normal"))

    # ----------------- Tunnel Lifecycle Management -----------------
    def toggle_connection(self):
        if not self.is_connected:
            self.start_tunnel()
        else:
            self.stop_tunnel()

    def _cleanup_askpass(self):
        if self.askpass_server:
            self.askpass_server.close()
            self.askpass_server = None
        for fname in ("askpass_temp.bat", "askpass_temp.sh", "known_hosts_temp"):
            path = os.path.join(CONFIG_DIR, fname)
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

    def _create_askpass_wrapper(self, askpass_port: int) -> str:
        """Creates a cross-platform wrapper script for SSH_ASKPASS."""
        os.makedirs(CONFIG_DIR, exist_ok=True)
        script_path = os.path.abspath(sys.argv[0])

        if getattr(sys, "frozen", False):
            base_cmd = f'"{sys.executable}" --askpass-client {askpass_port}'
        else:
            base_cmd = f'"{sys.executable}" "{script_path}" --askpass-client {askpass_port}'

        if IS_WINDOWS:
            askpass_path = os.path.join(CONFIG_DIR, "askpass_temp.bat")
            with open(askpass_path, "w", encoding="utf-8") as f:
                f.write(f"@echo off\n{base_cmd} %*\n")
        else:
            askpass_path = os.path.join(CONFIG_DIR, "askpass_temp.sh")
            with open(askpass_path, "w", encoding="utf-8") as f:
                f.write(f"#!/bin/sh\nexec {base_cmd} \"$@\"\n")
            os.chmod(askpass_path, 0o700)

        return askpass_path

    def start_tunnel(self):
        raw_host = self.host_entry.get().strip()
        host = sanitize_host(raw_host)
        if host != raw_host:
            self._set_entry_val(self.host_entry, host)

        user = self.user_entry.get().strip()
        ssh_port = self.ssh_port_entry.get().strip()
        socks_port = self.socks_port_entry.get().strip()
        bypass = self._get_bypass_val()
        use_compression = self.compress_var.get()
        remote_dns = self.remote_dns_var.get()
        adblock_enabled = self.adblock_var.get()
        udp_gw = self.udp_gw_var.get()
        udpgw_port = self.udpgw_port_entry.get().strip()

        if not host or not user:
            messagebox.showwarning("Warning", "Please provide SSH host and username!")
            return

        set_system_proxy(False)

        resolved_ip, used_fallback = resolve_host_ipv4(host)
        self._current_extra_bypass = [host]
        if resolved_ip:
            if resolved_ip not in self._current_extra_bypass:
                self._current_extra_bypass.append(resolved_ip)
            if not is_ipv4_address(host):
                src = "fallback DNS 1.1.1.1/8.8.8.8" if used_fallback else "system DNS"
                self.log(f"> DNS resolved '{host}' -> {resolved_ip} ({src})")
        else:
            self.log(f"> Warning: Could not pre-resolve '{host}' via IPv4 DNS; passing hostname to OpenSSH.")

        internal_ssh_port = get_free_port(int(socks_port) + 1)
        enable_udp = (udp_gw == "badvpn-udpgw")

        try:
            self.bridge = SocksUdpBridge(
                socks_port=int(socks_port),
                internal_ssh_port=internal_ssh_port,
                udpgw_port=int(udpgw_port) if udpgw_port.isdigit() else 7300,
                enable_udp=enable_udp,
                remote_dns=remote_dns,
                adblock_enabled=adblock_enabled,
                adblock_engine=self.adblock_engine,
                bypass_list=bypass,
                extra_bypass=self._current_extra_bypass,
                log_cb=lambda msg: self.after(0, self.log, msg)
            )
            self.bridge.start()
        except Exception as e:
            self.log(f"> Local SOCKS5 bridge error: {e}")
            return

        self.askpass_server = AskpassServer(
            password_getter=lambda: self.pass_entry.get(),
            log_cb=lambda msg: self.after(0, self.log, msg)
        )
        askpass_path = self._create_askpass_wrapper(self.askpass_server.port)

        # Reset temporary known_hosts to 0 bytes so OpenSSH never sees key conflicts
        os.makedirs(CONFIG_DIR, exist_ok=True)
        temp_kh = os.path.join(CONFIG_DIR, "known_hosts_temp")
        try:
            with open(temp_kh, "w", encoding="utf-8"):
                pass
        except OSError:
            pass

        ssh_cmd = [
            "ssh",
            "-4",
            "-D", f"127.0.0.1:{internal_ssh_port}",
            "-p", ssh_port,
            "-N",
            "-v",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=~/.socks5tunnel/known_hosts_temp",
            "-o", "GlobalKnownHostsFile=~/.socks5tunnel/known_hosts_temp",
            "-o", "CheckHostIP=no",
            "-o", "ConnectTimeout=12",
            "-o", "ServerAliveInterval=30"
        ]

        if enable_udp:
            ssh_cmd.extend(["-L", f"{udpgw_port}:127.0.0.1:{udpgw_port}"])

        if use_compression:
            ssh_cmd.append("-C")

        target_host = resolved_ip if resolved_ip else host
        ssh_cmd.append(f"{user}@{target_host}")

        env = os.environ.copy()
        home_dir = os.path.expanduser("~")
        env["HOME"] = home_dir
        env["USERPROFILE"] = home_dir
        env["SSH_ASKPASS"] = askpass_path
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["DISPLAY"] = "dummy:0"

        self.log(f"> Starting SSH ({self.current_profile}): {' '.join(ssh_cmd)}")

        try:
            startupinfo = None
            if IS_WINDOWS:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            self.ssh_process = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                universal_newlines=True,
                env=env,
                startupinfo=startupinfo,
                bufsize=1
            )
        except Exception as e:
            self.log(f"> Error starting SSH: {e}")
            if self.bridge:
                self.bridge.stop()
                self.bridge = None
            self._cleanup_askpass()
            return

        threading.Thread(
            target=self._monitor_ssh,
            args=(socks_port, bypass, internal_ssh_port),
            daemon=True
        ).start()

    def _monitor_ssh(self, socks_port, bypass, check_port):
        def stream_reader():
            for line in iter(self.ssh_process.stdout.readline, ''):
                if line:
                    self.after(0, self.log, line.strip())
            try:
                self.ssh_process.stdout.close()
            except Exception:
                pass

        reader_thread = threading.Thread(target=stream_reader, daemon=True)
        reader_thread.start()

        connected_ok = False
        elapsed = 0.0
        while elapsed < 20.0:
            if self.ssh_process.poll() is not None:
                break
            try:
                with socket.create_connection(('127.0.0.1', check_port), timeout=0.3):
                    connected_ok = True
                    break
            except OSError:
                time.sleep(0.2)
                elapsed += 0.2

        if connected_ok:
            self.after(0, lambda: self._set_ui_state(True, socks_port, bypass))
        else:
            self.after(
                0, self.log,
                f"> Warning: SSH port (:{check_port}) did not respond in time. Please check the log."
            )

        self.ssh_process.wait()

        self.after(0, self._set_ui_state, False, socks_port, bypass)
        self.after(0, self.log, "> SSH process exited.")

    def _set_ui_state(self, connected: bool, socks_port="1080", bypass=""):
        if self.is_connected == connected:
            return
        self.is_connected = connected

        if connected:
            self.canvas.itemconfig(self.circle_btn, fill="#10B981", outline="#059669")
            self.canvas.itemconfig(self.btn_text, text="ON")
            self.status_lbl.config(text="Connected", fg="#10B981")
            remote_dns = self.remote_dns_var.get()
            set_system_proxy(
                True,
                socks_port=socks_port,
                bypass_list=bypass,
                remote_dns=remote_dns,
                extra_bypass=self._current_extra_bypass
            )
            dns_mode = "Remote Tunnel DNS -> IPv4" if remote_dns else "Local DNS"
            self.log(f"> System proxy enabled ({dns_mode}).")

            # Load / download AdBlock filter through the active SSH tunnel
            if remote_dns and self.adblock_var.get():
                self.reload_adblock_filter_async()

            self.after(600, self.run_test)
        else:
            self.canvas.itemconfig(self.circle_btn, fill="#4A4E58", outline="#2B2D33")
            self.canvas.itemconfig(self.btn_text, text="OFF")
            self.status_lbl.config(text="Disconnected", fg="#8C93A4")
            self.ping_lbl.config(text="")
            set_system_proxy(False)
            self.log("> System proxy disabled.")

    def stop_tunnel(self):
        if self.ssh_process and self.ssh_process.poll() is None:
            self.ssh_process.terminate()

        if self.bridge:
            self.bridge.stop()
            self.bridge = None

        self._set_ui_state(False)
        self._cleanup_askpass()

    def on_close(self):
        self.stop_tunnel()
        self.destroy()


# Backward-compatible alias
SOCKSProxyApp = SSHTunnelApp


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--askpass-client":
        run_askpass_client()
        sys.exit(0)

    app = SSHTunnelApp()
    app.mainloop()
