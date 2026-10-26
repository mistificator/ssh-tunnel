import configparser
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

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

# Windows Internet Settings Constants
REG_INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


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
                    items = [x.strip() for x in proxy_override.split(";") if x.strip() and x.lower() != "<local>"]
                    bypass_list = ";".join(items)
            except FileNotFoundError:
                pass
    except Exception as e:
        print(f"Error reading Windows registry: {e}")

    return socks_port, bypass_list


def set_windows_proxy(enabled: bool, socks_port: str = "1080", bypass_list: str = ""):
    """Configures system proxy in Windows Registry."""
    if not IS_WINDOWS or winreg is None:
        return

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                proxy_server_val = f"socks=127.0.0.1:{socks_port}"
                items = [x.strip() for x in bypass_list.replace("\n", ";").split(";") if x.strip() and x.lower() != "<local>"]
                items.append("<local>")
                reg_bypass_val = ";".join(items)

                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server_val)
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, reg_bypass_val)
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
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
                items = [x for x in raw_items if x not in ("localhost", "127.0.0.0/8", "::1")]
                bypass_list = ";".join(items)
            except Exception:
                pass
    except Exception as e:
        print(f"Error reading Linux proxy settings: {e}")

    return socks_port, bypass_list


def set_linux_proxy(enabled: bool, socks_port: str = "1080", bypass_list: str = ""):
    """Sets desktop proxy settings using gsettings."""
    if not shutil.which("gsettings"):
        return

    try:
        if enabled:
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"], check=False)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"], check=False)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(socks_port)], check=False)

            items = [x.strip() for x in bypass_list.replace("\n", ";").replace(",", ";").split(";") if x.strip()]
            for default_host in ["localhost", "127.0.0.0/8", "::1"]:
                if default_host not in items:
                    items.append(default_host)
            formatted_items = "[" + ", ".join(f"'{item}'" for item in items) + "]"
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "ignore-hosts", formatted_items], check=False)
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


def set_system_proxy(enabled: bool, socks_port: str = "1080", bypass_list: str = ""):
    if IS_WINDOWS:
        set_windows_proxy(enabled, socks_port, bypass_list)
    elif IS_LINUX:
        set_linux_proxy(enabled, socks_port, bypass_list)


def get_free_port(preferred_port: int = 1081) -> int:
    """Finds an available TCP port for the internal OpenSSH SOCKS listener."""
    for port in range(preferred_port, preferred_port + 500):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
    return 10888


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


# ----------------- SOCKS & UDP Bridge -----------------
class SocksUdpBridge:
    """
    SOCKS Bridge:
    - Forwards SOCKS4/SOCKS5 TCP CONNECT to internal SSH listener.
    - Handles SOCKS5 UDP ASSOCIATE and routes datagrams to badvpn-udpgw.
    """
    def __init__(self, socks_port: int, internal_ssh_port: int, udpgw_port: int, log_cb):
        self.socks_port = socks_port
        self.internal_ssh_port = internal_ssh_port
        self.udpgw_port = udpgw_port
        self.log_cb = log_cb
        self.running = True
        self.dns_cache = {}

        self.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_server.bind(('127.0.0.1', socks_port))
        self.tcp_server.listen(128)

        self.udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_server.bind(('127.0.0.1', socks_port))

        self.badvpn_client = BadVpnClient(udpgw_port, self.udp_server, log_cb)

    def start(self):
        threading.Thread(target=self._tcp_accept_loop, daemon=True).start()
        threading.Thread(target=self._udp_relay_loop, daemon=True).start()
        self.log_cb(f"> SOCKS bridge (TCP/UDP :{self.socks_port} -> SSH :{self.internal_ssh_port}) started.")

    def _connect_to_ssh(self, timeout=5.0):
        start = time.time()
        while self.running and (time.time() - start < timeout):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect(('127.0.0.1', self.internal_ssh_port))
                return s
            except (ConnectionRefusedError, socket.timeout, OSError):
                try:
                    s.close()
                except Exception:
                    pass
                time.sleep(0.1)
        return None

    def _bidirectional_pipe(self, sock1, sock2):
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
                threading.Thread(target=self._handle_tcp_client, args=(client_sock,), daemon=True).start()
            except Exception:
                break

    def _handle_tcp_client(self, client_sock):
        ssh_sock = None
        try:
            client_sock.settimeout(6.0)
            data = client_sock.recv(1024)
            if not data:
                client_sock.close()
                return

            ssh_sock = self._connect_to_ssh()
            if not ssh_sock:
                client_sock.close()
                return

            # SOCKS4 / SOCKS4a
            if data[0] == 4:
                ssh_sock.sendall(data)
                self._bidirectional_pipe(client_sock, ssh_sock)
                return

            # SOCKS5
            if data[0] == 5:
                ssh_sock.sendall(data)
                ssh_sock.settimeout(4.0)
                auth_resp = ssh_sock.recv(512)
                if not auth_resp:
                    client_sock.close()
                    ssh_sock.close()
                    return
                client_sock.sendall(auth_resp)

                req = client_sock.recv(1024)
                if len(req) < 4 or req[0] != 5:
                    client_sock.close()
                    ssh_sock.close()
                    return

                cmd = req[1]
                if cmd == 3:  # UDP ASSOCIATE
                    ssh_sock.close()
                    ssh_sock = None
                    bnd_resp = b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", self.socks_port)
                    client_sock.sendall(bnd_resp)
                    client_sock.settimeout(None)
                    while self.running:
                        chunk = client_sock.recv(1024)
                        if not chunk:
                            break
                    client_sock.close()
                    return
                else:
                    ssh_sock.sendall(req)
                    self._bidirectional_pipe(client_sock, ssh_sock)
                    return

            ssh_sock.sendall(data)
            self._bidirectional_pipe(client_sock, ssh_sock)

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
                    dest_ip_bytes = data[offset:offset+4]
                    offset += 4
                elif atyp == 3:  # FQDN
                    d_len = data[offset]
                    offset += 1
                    domain = data[offset:offset+d_len].decode('utf-8', errors='ignore')
                    offset += d_len
                    if domain not in self.dns_cache:
                        self.dns_cache[domain] = socket.inet_aton(socket.gethostbyname(domain))
                    dest_ip_bytes = self.dns_cache[domain]
                else:
                    continue

                dest_port = struct.unpack("!H", data[offset:offset+2])[0]
                payload = data[offset+2:]

                self.badvpn_client.send_packet(addr, dest_ip_bytes, dest_port, payload)
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        try:
            self.tcp_server.close()
        except Exception:
            pass
        try:
            self.udp_server.close()
        except Exception:
            pass
        self.badvpn_client.close()


# ----------------- GUI Application -----------------
class SOCKSProxyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        # Renamed title
        self.title("SOCKS5 Tunnel")
        self.geometry("500x760")
        self.resizable(False, False)
        self.configure(bg="#1E1E24")

        self.is_connected = False
        self.ssh_process = None
        self.bridge = None
        self._is_loading_config = False
        self._is_testing = False

        self._build_ui()
        self.load_config(CONFIG_FILE)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_ui(self):
        # 1. Main toggle button & status area
        btn_frame = tk.Frame(self, bg="#1E1E24", pady=8)
        btn_frame.pack(fill="x")

        self.canvas_size = 115
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
        self.status_lbl = tk.Label(btn_frame, text="Disconnected", fg="#8C93A4", bg="#1E1E24", font=("Segoe UI", 11, "bold"))
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

        self._add_label(settings_frame, "SSH Host:", 0, 0)
        self.host_entry = self._add_entry(settings_frame, "1.2.3.4", 0, 1)

        self._add_label(settings_frame, "SSH Port:", 0, 2)
        self.ssh_port_entry = self._add_entry(settings_frame, "22", 0, 3, width=7)

        self._add_label(settings_frame, "Username:", 1, 0)
        self.user_entry = self._add_entry(settings_frame, "root", 1, 1)

        self._add_label(settings_frame, "SOCKS5 Port:", 1, 2)
        self.socks_port_entry = self._add_entry(settings_frame, "1080", 1, 3, width=7)

        self._add_label(settings_frame, "SSH Password:", 2, 0)
        self.pass_entry = self._add_entry(settings_frame, "", 2, 1, show="*")

        self.compress_var = tk.BooleanVar(value=True)
        self.compress_chk = tk.Checkbutton(
            settings_frame, text="Compression (-C)", variable=self.compress_var,
            bg="#1E1E24", fg="#FFFFFF", selectcolor="#2B2D33",
            activebackground="#1E1E24", activeforeground="#FFFFFF",
            command=self._on_setting_changed
        )
        self.compress_chk.grid(row=2, column=2, columnspan=2, sticky="w", padx=4)

        self._add_label(settings_frame, "UDP Gateway:", 3, 0)
        self.udp_gw_var = tk.StringVar(value="disabled")
        self.udp_gw_combo = ttk.Combobox(
            settings_frame, textvariable=self.udp_gw_var,
            values=["disabled", "badvpn-udpgw"], state="readonly", width=14
        )
        self.udp_gw_combo.grid(row=3, column=1, sticky="w", padx=3, pady=2)
        self.udp_gw_combo.bind("<<ComboboxSelected>>", lambda e: self._on_setting_changed())

        self._add_label(settings_frame, "UDP Port:", 3, 2)
        self.udpgw_port_entry = self._add_entry(settings_frame, "7300", 3, 3, width=7)

        self._add_label(settings_frame, "Bypass List:", 4, 0)
        self.bypass_text = tk.Text(
            settings_frame, height=3, width=32, bg="#2A2C35", fg="#FFFFFF",
            insertbackground="white", relief="flat", font=("Consolas", 8), wrap="word"
        )
        self.bypass_text.grid(row=4, column=1, columnspan=3, sticky="we", padx=3, pady=3)
        self.bypass_text.bind("<KeyRelease>", lambda event: self._on_setting_changed())

        io_btn_frame = tk.Frame(settings_frame, bg="#1E1E24")
        io_btn_frame.grid(row=5, column=0, columnspan=4, pady=(6, 2), sticky="e")

        self.test_btn = tk.Button(
            io_btn_frame, text="⚡ Test", command=self.run_test,
            bg="#2563EB", fg="#FFFFFF", activebackground="#1D4ED8", activeforeground="#FFFFFF",
            relief="flat", padx=10, font=("Segoe UI", 8, "bold"), cursor="hand2"
        )
        self.test_btn.pack(side="left", padx=4)

        import_btn = tk.Button(
            io_btn_frame, text="Import .ini...", command=self.import_config,
            bg="#32353E", fg="#E0E0E0", relief="flat", padx=8, font=("Segoe UI", 8)
        )
        import_btn.pack(side="left", padx=4)

        export_btn = tk.Button(
            io_btn_frame, text="Export .ini...", command=self.export_config,
            bg="#32353E", fg="#E0E0E0", relief="flat", padx=8, font=("Segoe UI", 8)
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
        return entry

    def _get_bypass_val(self) -> str:
        return self.bypass_text.get("1.0", "end-1c").strip()

    def _set_bypass_val(self, val: str):
        self.bypass_text.delete("1.0", tk.END)
        self.bypass_text.insert("1.0", val)

    def _on_setting_changed(self):
        if not self._is_loading_config:
            self.save_config(CONFIG_FILE)

    def save_config(self, filepath: str):
        config = configparser.ConfigParser(comment_prefixes=('#',), inline_comment_prefixes=None)
        raw_bypass = self._get_bypass_val()
        items = [x.strip() for x in raw_bypass.replace("\n", ";").split(";") if x.strip()]
        formatted_bypass = ("\n" + "\n".join(f"    {item}" for item in items)) if items else ""

        config["SSH"] = {
            "host": self.host_entry.get().strip(),
            "port": self.ssh_port_entry.get().strip(),
            "user": self.user_entry.get().strip(),
            "password": self.pass_entry.get(),
            "compression": str(self.compress_var.get())
        }
        config["PROXY"] = {
            "socks_port": self.socks_port_entry.get().strip(),
            "bypass_list": formatted_bypass
        }
        config["UDP"] = {
            "gateway": self.udp_gw_var.get(),
            "udpgw_port": self.udpgw_port_entry.get().strip()
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
            self._set_entry_val(self.socks_port_entry, sys_port)
            self._set_bypass_val(sys_bypass)
            self._is_loading_config = False
            self.save_config(filepath)
            return

        config = configparser.ConfigParser(comment_prefixes=('#',), inline_comment_prefixes=None)
        try:
            config.read(filepath, encoding="utf-8")
            ssh_sec = config["SSH"] if "SSH" in config else {}
            proxy_sec = config["PROXY"] if "PROXY" in config else {}
            udp_sec = config["UDP"] if "UDP" in config else {}

            self._set_entry_val(self.host_entry, ssh_sec.get("host", "1.2.3.4"))
            self._set_entry_val(self.ssh_port_entry, ssh_sec.get("port", "22"))
            self._set_entry_val(self.user_entry, ssh_sec.get("user", "root"))
            self._set_entry_val(self.pass_entry, ssh_sec.get("password", ""))
            self.compress_var.set(ssh_sec.getboolean("compression", fallback=True))

            self._set_entry_val(self.socks_port_entry, proxy_sec.get("socks_port", "1080"))
            raw_bypass = proxy_sec.get("bypass_list", "")
            items = [line.strip() for line in raw_bypass.splitlines() if line.strip()]
            self._set_bypass_val(";".join(items))

            self.udp_gw_var.set(udp_sec.get("gateway", "disabled"))
            self._set_entry_val(self.udpgw_port_entry, udp_sec.get("udpgw_port", "7300"))

            self.log(f"> Settings loaded from: {os.path.basename(filepath)}")
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
            filetypes=[("INI files", "*.ini"), ("All files", "*.*")],
            title="Export settings to file"
        )
        if filepath:
            self.save_config(filepath)
            messagebox.showinfo("Export", f"Settings exported successfully to:\n{filepath}")

    def import_config(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("INI files", "*.ini"), ("All files", "*.*")],
            title="Import settings from file"
        )
        if filepath:
            self.load_config(filepath)
            self.save_config(CONFIG_FILE)
            messagebox.showinfo("Import", f"Settings loaded successfully from:\n{filepath}")

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

        # 1. Test TCP connection via google.com:80
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
                    raise Exception(f"SOCKS5 CONNECT failed (code: {conn_resp[1] if len(conn_resp)>1 else 'unknown'})")

                http_req = b"HEAD / HTTP/1.1\r\nHost: google.com\r\nUser-Agent: SOCKS-Tester\r\nConnection: close\r\n\r\n"
                tcp_sock.sendall(http_req)

                http_resp = tcp_sock.recv(512)
                tcp_ms = (time.perf_counter() - t0) * 1000.0
                tcp_ok = True

                if http_resp:
                    first_line = http_resp.split(b"\r\n")[0].decode('utf-8', errors='ignore')
                    self.log(f"> [TCP Test] SUCCESS: google.com:80 -> {first_line} ({tcp_ms:.1f} ms)")
                else:
                    self.log(f"> [TCP Test] SUCCESS: Connection established ({tcp_ms:.1f} ms)")
        except Exception as e:
            tcp_status = "Error"
            self.log(f"> [TCP Test] ERROR: {e}")

        # 2. Test UDP via DNS request to 8.8.8.8:53
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
                    raise Exception(f"UDP ASSOCIATE rejected (code {reply[1] if len(reply)>1 else '?'})")

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

        # Build ping summary line
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
        for fname in ("askpass_temp.bat", "askpass_temp.sh"):
            path = os.path.join(CONFIG_DIR, fname)
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

    def start_tunnel(self):
        host = self.host_entry.get().strip()
        user = self.user_entry.get().strip()
        ssh_port = self.ssh_port_entry.get().strip()
        socks_port = self.socks_port_entry.get().strip()
        password = self.pass_entry.get()
        bypass = self._get_bypass_val()
        use_compression = self.compress_var.get()
        udp_gw = self.udp_gw_var.get()
        udpgw_port = self.udpgw_port_entry.get().strip()

        if not host or not user:
            messagebox.showwarning("Warning", "Please provide SSH host and username!")
            return

        ssh_cmd = ["ssh"]
        target_check_port = int(socks_port)

        if udp_gw == "badvpn-udpgw":
            internal_ssh_port = get_free_port(int(socks_port) + 1)
            target_check_port = internal_ssh_port
            ssh_cmd.extend([
                "-D", f"127.0.0.1:{internal_ssh_port}",
                "-L", f"{udpgw_port}:127.0.0.1:{udpgw_port}"
            ])
            try:
                self.bridge = SocksUdpBridge(
                    socks_port=int(socks_port),
                    internal_ssh_port=internal_ssh_port,
                    udpgw_port=int(udpgw_port),
                    log_cb=self.log
                )
                self.bridge.start()
            except Exception as e:
                self.log(f"> Local SOCKS5 bridge error: {e}")
                return
        else:
            ssh_cmd.extend(["-D", f"127.0.0.1:{socks_port}"])

        ssh_cmd.extend([
            "-p", ssh_port,
            "-N",
            "-v",
            "-o", "StrictHostKeyChecking=accept-new"
        ])
        if use_compression:
            ssh_cmd.append("-C")
        ssh_cmd.append(f"{user}@{host}")

        env = os.environ.copy()
        if password:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            if IS_WINDOWS:
                askpass_path = os.path.join(CONFIG_DIR, "askpass_temp.bat")
                with open(askpass_path, "w", encoding="utf-8") as f:
                    f.write(f"@echo {password}\n")
            else:
                askpass_path = os.path.join(CONFIG_DIR, "askpass_temp.sh")
                with open(askpass_path, "w", encoding="utf-8") as f:
                    f.write(f"#!/bin/sh\necho '{password}'\n")
                os.chmod(askpass_path, 0o700)

            env["SSH_ASKPASS"] = askpass_path
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = "dummy:0"

        self.log(f"> Starting SSH: {' '.join(ssh_cmd)}")

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
            return

        threading.Thread(
            target=self._monitor_ssh,
            args=(socks_port, bypass, target_check_port),
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
        start_wait = time.time()
        while time.time() - start_wait < 15.0:
            if self.ssh_process.poll() is not None:
                break
            try:
                with socket.create_connection(('127.0.0.1', check_port), timeout=0.3):
                    connected_ok = True
                    break
            except OSError:
                time.sleep(0.2)

        if connected_ok:
            self.after(0, lambda: self._set_ui_state(True, socks_port, bypass))
        else:
            self.log(f"> Warning: SSH port (:{check_port}) did not respond in time. Please check the log.")

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
            set_system_proxy(True, socks_port, bypass)
            self.log("> System proxy enabled.")
            # Run quick diagnostics 600 ms after connection start
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


if __name__ == "__main__":
    app = SOCKSProxyApp()
    app.mainloop()