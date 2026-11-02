# SSH Tunnel

**SSH Tunnel** is a lightweight, cross-platform GUI application built with Python and Tkinter that creates a local SOCKS5/SOCKS4 proxy over an OpenSSH tunnel and automatically configures system proxy settings on Windows and Linux. It also includes a built-in bridge for routing UDP traffic (such as DNS queries) over SSH using `badvpn-udpgw`.

## Key Features

* **One-Click SSH SOCKS Tunneling:** Launches and monitors an OpenSSH client (`ssh -D`) in the background with a visual status indicator (`ON` / `OFF`) and real-time log output.
* **Connection Profiles:** Manage multiple server profiles (`New`, `Rename`, `Delete`) directly from the GUI, with automatic persistence in `~/.socks5tunnel/config.ini` and `.ini` profile import/export.
* **Automatic System Proxy Configuration:**
  * **Windows:** Automatically updates `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings` (`ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigURL`) and notifies WinINet (`InternetSetOptionW`) immediately without requiring a browser restart.
  * **Linux:** Automatically configures desktop proxy settings via `gsettings` (`org.gnome.system.proxy`) for GNOME, Cinnamon, and MATE environments.
* **Remote Tunnel DNS -> IPv4:** Prevents browser DNS leaks and resolves domain names to IPv4 inside the SSH tunnel via a local PAC script and DNS-over-TCP resolver.
* **UDP-over-SSH Support (`badvpn-udpgw`):** Includes an internal `SocksUdpBridge` and `BadVpnClient` that intercept SOCKS5 `UDP ASSOCIATE` requests on the local SOCKS port and forward UDP datagrams over an SSH local port forward (`-L`) to a remote `badvpn-udpgw` daemon.
* **Dedicated Bypass List Editor:** Manage proxy exclusion rules in a separate window with one host, domain, or subnet per line.
* **Password & Host Key Automation:** Supports password authentication via `SSH_ASKPASS` (`SSH_ASKPASS_REQUIRE=force`) so you do not need to type your password in a terminal window.
* **Built-in Connection Diagnostics:** Features a `⚡ Test` utility (also triggered automatically 600 ms after connection) that verifies TCP connectivity via an HTTP `HEAD` request to `google.com:80` and UDP connectivity via a DNS query for `example.com` to `8.8.8.8:53`, displaying round-trip latency in milliseconds.

## Requirements

* **Operating System:** Windows or Linux.
* **Python:** Python 3.x with `tkinter` installed.
* **OpenSSH Client:** The `ssh` executable must be available in your system `PATH`.
* **Linux Desktop Proxy (Optional):** `gsettings` must be available in `PATH` for automatic system proxy toggling on Linux.
* **Remote Server (Optional for UDP):** If using UDP forwarding, the `badvpn-udpgw` daemon must be running on the remote SSH server (default port `7300`).

## Installation & Launch

1. Make sure Python 3 and the OpenSSH client (`ssh`) are installed on your system.
2. Run the application directly:
   * **Windows:** Double-click `ssh_tunnel.pyw` or run `pythonw ssh_tunnel.pyw`.
   * **Linux:** Run `python3 ssh_tunnel.pyw`.
3. On first launch, if `~/.socks5tunnel/config.ini` does not exist, **SSH Tunnel** reads your current system proxy port and bypass list and generates a default configuration file.

## Configuration Fields

* **Profile:** Select an existing connection profile or click **New**, **Rename**, or **Delete** to manage profiles.
* **SSH Host:** IPv4 address or domain name of your remote SSH server (default: `1.2.3.4`).
* **SSH Port:** Remote SSH port (default: `22`).
* **Username:** SSH login username (default: `root`).
* **SOCKS5 Port:** Local port where the SOCKS proxy will listen on `127.0.0.1` (default: `1080`).
* **SSH Password:** Password for the SSH user (optional if you use SSH keys; right-click to toggle password visibility).
* **Compression (-C):** Enables OpenSSH data compression (`-C` flag) to speed up text and HTTP transfers.
* **UDP Gateway:**
  * `disabled`: TCP-only forwarding via the local SOCKS5 bridge.
  * `badvpn-udpgw`: Enables SOCKS5 UDP support on `127.0.0.1:<SOCKS5 Port>` and forwards `<UDP Port>:127.0.0.1:<UDP Port>` to route UDP packets through `badvpn-udpgw`.
* **UDP Port:** Local and remote port used by `badvpn-udpgw` (default: `7300`).
* **DNS Routing:** Routes browser DNS lookups inside the SSH tunnel and resolves domains to IPv4.
* **Bypass List:** Click **Edit Bypass List...** to open the exclusion list window and enter hosts, domains, or subnets (one entry per line) that should connect directly without going through the proxy. Localhost addresses (`<local>` on Windows; `localhost`, `127.0.0.0/8`, `::1` on Linux) are appended automatically.

## Usage

1. Select or create a **Profile** and enter your **SSH Host**, **SSH Port**, **Username**, and **SSH Password** in the **Connection Settings** panel.
2. Click the central circular **OFF** button to start the tunnel.
3. **SSH Tunnel** will launch `ssh` and wait up to 20 seconds for the internal listener port to accept connections.
4. Once connected, the main button turns green (**ON**), the status changes to **Connected**, the system proxy is enabled, and an automatic connection test runs after 600 ms.
5. Click **⚡ Test** at any time while connected to measure TCP and UDP latency and view detailed results in the **SSH & Bridge Log** console.
6. Click **ON** again (or close the window) to terminate the `ssh` process, stop the local bridge, disable the system proxy, and clean up temporary authentication files.