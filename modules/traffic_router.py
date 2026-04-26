# aegis-scanner/modules/traffic_router.py
"""
مدیریت مسیر ترافیک برای شبیه‌سازی APT در engagementهای مجاز.

این ماژول به red teamer کمک می‌کند:
  ├── زنجیر proxy را پیکربندی کند (Tor + SOCKS5 + HTTP)
  ├── قابلیت‌های routing فعلی سیستم را بررسی کند
  ├── proxychains.conf را به‌صورت خودکار تولید کند
  ├── Tor circuit status را بررسی کند
  └── پیشنهادهای عملیاتی برای هر سناریو بدهد

هدف: شبیه‌سازی رفتار APT واقعی در قالب engagement مجاز
با scope document معتبر.

⚠️ استفاده از این ابزار بدون مجوز کتبی صاحب سیستم،
   نقض قانون جرایم رایانه‌ای است.
"""

import os
import re
import socket
import logging
import subprocess
import time
import ipaddress
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ─── Proxy types ──────────────────────────────────────────────────────────────
PROXY_TYPE_SOCKS4  = "socks4"
PROXY_TYPE_SOCKS5  = "socks5"
PROXY_TYPE_HTTP    = "http"
PROXY_TYPE_TOR     = "tor"


@dataclass
class ProxyNode:
    """یک node در زنجیر proxy"""
    proxy_type: str          # socks4/5/http/tor
    host:       str
    port:       int
    username:   Optional[str] = None
    password:   Optional[str] = None
    latency_ms: float         = 0.0
    is_alive:   bool          = False
    country:    str           = ""
    note:       str           = ""

    def to_proxychains_line(self) -> str:
        """تبدیل به خط proxychains.conf"""
        base = f"{self.proxy_type} {self.host} {self.port}"
        if self.username and self.password:
            base += f" {self.username} {self.password}"
        return base


@dataclass
class TorStatus:
    """وضعیت Tor"""
    is_running:    bool  = False
    control_port:  int   = 9051
    socks_port:    int   = 9050
    circuit_built: bool  = False
    exit_ip:       str   = ""
    exit_country:  str   = ""
    version:       str   = ""
    bandwidth_kb:  float = 0.0


@dataclass
class RoutingProfile:
    """پروفایل کامل routing برای یک سناریو"""
    profile_name:   str
    chain_type:     str           # strict/dynamic/random
    proxies:        list          # list of ProxyNode
    tor_enabled:    bool
    tor_status:     Optional[TorStatus]
    proxychains_config: str       # محتوای کامل proxychains.conf
    nmap_prefix:    str           # prefix برای اجرا با proxychains
    curl_proxy:     str           # برای تست با curl
    estimated_latency_ms: float
    security_notes: list
    limitations:    list


class TrafficRouter:
    """
    مدیریت مسیر ترافیک برای red team engagements مجاز.

    اصل اساسی: این ابزار فقط برای شبیه‌سازی APT در محیط‌های
    دارای scope document معتبر طراحی شده است.
    """

    TOR_SOCKS_PORT   = 9050
    TOR_CONTROL_PORT = 9051
    DEFAULT_TIMEOUT  = 8

    def __init__(self):
        self._system_proxies = self._detect_system_proxies()

    # ─── System proxy detection ───────────────────────────────────────────
    @staticmethod
    def _detect_system_proxies() -> dict:
        """تشخیص proxy‌های موجود در سیستم"""
        proxies = {}
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "SOCKS_PROXY",
                    "http_proxy", "https_proxy", "all_proxy"):
            val = os.environ.get(var)
            if val:
                proxies[var] = val
        return proxies

    # ─── Tor management ───────────────────────────────────────────────────
    def check_tor(self) -> TorStatus:
        """بررسی وضعیت Tor"""
        status = TorStatus()

        # بررسی اینکه آیا Tor در حال اجرا است
        try:
            result = subprocess.run(
                ["pgrep", "-x", "tor"],
                capture_output=True, timeout=5
            )
            status.is_running = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # fallback: تلاش برای اتصال به SOCKS port
            try:
                sock = socket.create_connection(
                    ("127.0.0.1", self.TOR_SOCKS_PORT), timeout=2
                )
                sock.close()
                status.is_running = True
            except (ConnectionRefusedError, socket.timeout):
                pass

        if not status.is_running:
            return status

        status.socks_port   = self.TOR_SOCKS_PORT
        status.control_port = self.TOR_CONTROL_PORT

        # بررسی نسخه Tor
        try:
            result = subprocess.run(
                ["tor", "--version"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                match = re.search(r"Tor version ([\d.]+)", result.stdout)
                if match:
                    status.version = match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # بررسی circuit از طریق Tor SOCKS
        if REQUESTS_OK:
            exit_ip, exit_country = self._get_tor_exit_info()
            status.exit_ip       = exit_ip
            status.exit_country  = exit_country
            status.circuit_built = bool(exit_ip)

        return status

    def _get_tor_exit_info(self) -> tuple:
        """دریافت IP و کشور exit node فعلی Tor"""
        try:
            session = requests.Session()
            session.proxies = {
                "http":  f"socks5://127.0.0.1:{self.TOR_SOCKS_PORT}",
                "https": f"socks5://127.0.0.1:{self.TOR_SOCKS_PORT}",
            }
            resp = session.get(
                "https://ipinfo.io/json",
                timeout=self.DEFAULT_TIMEOUT
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("ip", ""), data.get("country", "")
        except Exception as e:
            logger.debug(f"[Router] Tor exit info: {e}")
        return "", ""

    def new_tor_identity(self) -> bool:
        """درخواست circuit جدید از Tor (NEWNYM signal)"""
        try:
            sock = socket.create_connection(
                ("127.0.0.1", self.TOR_CONTROL_PORT), timeout=5
            )
            # Auth (اگر password نداشته باشد)
            sock.send(b'AUTHENTICATE ""\r\n')
            time.sleep(0.2)
            sock.recv(128)
            # درخواست identity جدید
            sock.send(b"SIGNAL NEWNYM\r\n")
            time.sleep(0.5)
            resp = sock.recv(128).decode("ascii", errors="ignore")
            sock.close()
            success = "250" in resp
            if success:
                logger.info("[Router] New Tor identity requested")
                time.sleep(2)  # انتظار برای ساخت circuit جدید
            return success
        except Exception as e:
            logger.debug(f"[Router] Tor NEWNYM: {e}")
            return False

    # ─── Proxy testing ────────────────────────────────────────────────────
    def test_proxy(self, node: ProxyNode, test_url: str = "https://ipinfo.io/ip") -> bool:
        """تست در دسترس بودن یک proxy node"""
        if not REQUESTS_OK:
            return self._tcp_test(node)

        try:
            if node.proxy_type in (PROXY_TYPE_SOCKS4, PROXY_TYPE_SOCKS5):
                proxy_url = f"{node.proxy_type}://"
                if node.username:
                    proxy_url += f"{node.username}:{node.password}@"
                proxy_url += f"{node.host}:{node.port}"
            else:  # HTTP
                proxy_url = f"http://{node.host}:{node.port}"

            session = requests.Session()
            session.proxies = {"http": proxy_url, "https": proxy_url}
            t0 = time.monotonic()
            resp = session.get(test_url, timeout=10)
            node.latency_ms = (time.monotonic() - t0) * 1000
            node.is_alive   = resp.status_code == 200
            return node.is_alive
        except Exception:
            return self._tcp_test(node)

    @staticmethod
    def _tcp_test(node: ProxyNode) -> bool:
        """تست TCP ساده برای proxy"""
        try:
            sock = socket.create_connection((node.host, node.port), timeout=5)
            sock.close()
            node.is_alive = True
            return True
        except Exception:
            node.is_alive = False
            return False

    def measure_proxy_latency(self, node: ProxyNode) -> float:
        """اندازه‌گیری latency proxy"""
        times = []
        for _ in range(3):
            try:
                t0 = time.monotonic()
                sock = socket.create_connection((node.host, node.port), timeout=5)
                rtt  = (time.monotonic() - t0) * 1000
                sock.close()
                times.append(rtt)
            except Exception:
                pass
        return sum(times) / len(times) if times else 9999.0

    # ─── ProxyChains config generation ───────────────────────────────────
    def generate_proxychains_config(
        self,
        proxies:    list,
        chain_type: str = "strict",
        tor:        bool = True,
    ) -> str:
        """
        تولید فایل proxychains4.conf بهینه‌شده.

        chain_type:
          strict  → ترتیب ثابت (APT simulation)
          dynamic → اگر یک node down بود، رد می‌شود
          random  → ترتیب تصادفی (best for anonymity)
        """
        lines = [
            "# proxychains4.conf — Generated by Aegis-Scanner",
            "# For authorized red team engagements only",
            "",
            f"{chain_type}_chain",
            "",
            "# Proxy DNS through proxy chain",
            "proxy_dns",
            "",
            "# Quiet mode (no output)",
            "quiet_mode",
            "",
            "# TCP read timeout (ms)",
            "tcp_read_time_out 15000",
            "tcp_connect_time_out 8000",
            "",
            "[ProxyList]",
            "# format: type host port [user pass]",
            "",
        ]

        # Tor اول (اگر فعال باشد)
        if tor:
            lines.append("# Tor SOCKS5 — exit node anonymization")
            lines.append(f"socks5 127.0.0.1 {self.TOR_SOCKS_PORT}")
            lines.append("")

        # بقیه proxy‌ها
        for i, proxy in enumerate(proxies, 1):
            if proxy.is_alive:
                lines.append(f"# Proxy {i}: {proxy.note or proxy.host}")
                lines.append(proxy.to_proxychains_line())
                lines.append("")

        return "\n".join(lines)

    # ─── Profile builder ──────────────────────────────────────────────────
    def build_profile(
        self,
        scenario:    str = "apt_simulation",
        proxies:     Optional[list] = None,
        use_tor:     bool = True,
        chain_type:  str = "strict",
    ) -> RoutingProfile:
        """
        ساخت پروفایل routing برای یک سناریو مشخص.

        سناریوها:
          apt_simulation   → زنجیر پایدار Tor + SOCKS5
          recon_only       → Tor تنها برای reconnaissance
          internal_pivot   → SOCKS5 داخلی (بعد از pivot)
          direct           → بدون proxy (برای تست کنترل‌شده)
        """
        proxies   = proxies or []
        tor_status = self.check_tor() if use_tor else TorStatus()

        # تست proxy‌ها
        alive_proxies = []
        total_latency = 0.0

        for proxy in proxies:
            alive = self.test_proxy(proxy)
            if alive:
                alive_proxies.append(proxy)
                total_latency += proxy.latency_ms

        if use_tor and tor_status.is_running:
            total_latency += 300   # Tor overhead تقریبی

        # ساخت config
        config = self.generate_proxychains_config(
            alive_proxies, chain_type, tor_status.is_running and use_tor
        )

        # prefix برای Nmap
        nmap_prefix = "proxychains4 -q " if (alive_proxies or tor_status.is_running) else ""
        curl_proxy  = self._build_curl_proxy_str(alive_proxies, tor_status)

        # یادداشت‌های امنیتی
        security_notes, limitations = self._build_notes(
            alive_proxies, tor_status, chain_type
        )

        return RoutingProfile(
            profile_name=scenario,
            chain_type=chain_type,
            proxies=alive_proxies,
            tor_enabled=tor_status.is_running and use_tor,
            tor_status=tor_status if use_tor else None,
            proxychains_config=config,
            nmap_prefix=nmap_prefix,
            curl_proxy=curl_proxy,
            estimated_latency_ms=total_latency,
            security_notes=security_notes,
            limitations=limitations,
        )

    def _build_curl_proxy_str(
        self, proxies: list, tor: TorStatus
    ) -> str:
        """ساخت string proxy برای curl"""
        if tor.is_running:
            return f"--proxy socks5://127.0.0.1:{self.TOR_SOCKS_PORT}"
        if proxies:
            p = proxies[0]
            return f"--proxy {p.proxy_type}://{p.host}:{p.port}"
        return ""

    @staticmethod
    def _build_notes(
        proxies: list, tor: TorStatus, chain_type: str
    ) -> tuple:
        notes = []
        limitations = []

        if tor.is_running:
            notes.append(
                f"Tor active | Exit: {tor.exit_ip} ({tor.exit_country}) | "
                f"Circuit built: {tor.circuit_built}"
            )
        else:
            limitations.append(
                "Tor not running — run 'tor' or 'sudo service tor start' "
                "for best anonymization in engagement"
            )

        if not proxies:
            limitations.append(
                "No additional SOCKS5 proxies configured — "
                "add proxies for multi-hop routing"
            )

        if chain_type == "strict":
            notes.append(
                "Strict chain: all proxies must be alive — "
                "more predictable for scope compliance"
            )
        elif chain_type == "random":
            notes.append(
                "Random chain: order varies per connection — "
                "best for simulating distributed APT behavior"
            )

        if proxies:
            alive_count = sum(1 for p in proxies if p.is_alive)
            notes.append(f"Proxy nodes: {alive_count}/{len(proxies)} alive")

        # محدودیت مهم Nmap
        limitations.append(
            "Nmap SYN scan (-sS) does NOT work through proxychains — "
            "use TCP connect scan (-sT) instead: "
            "proxychains4 nmap -sT -Pn [target]"
        )
        limitations.append(
            "UDP scans and ICMP cannot be proxied — "
            "only TCP-based scans work through proxy chains"
        )

        return notes, limitations

    # ─── Serialization ────────────────────────────────────────────────────
    def to_dict(self, profile: RoutingProfile) -> dict:
        tor_dict = {}
        if profile.tor_status:
            ts = profile.tor_status
            tor_dict = {
                "is_running":    ts.is_running,
                "socks_port":    ts.socks_port,
                "circuit_built": ts.circuit_built,
                "exit_ip":       ts.exit_ip,
                "exit_country":  ts.exit_country,
                "version":       ts.version,
            }

        return {
            "profile_name":          profile.profile_name,
            "chain_type":            profile.chain_type,
            "proxy_count":           len(profile.proxies),
            "tor_enabled":           profile.tor_enabled,
            "tor_status":            tor_dict,
            "proxychains_config":    profile.proxychains_config,
            "nmap_scan_command":     f"{profile.nmap_prefix}nmap -sT -Pn [target]",
            "curl_test_command":     f"curl {profile.curl_proxy} https://ipinfo.io/ip",
            "estimated_latency_ms":  round(profile.estimated_latency_ms, 1),
            "security_notes":        profile.security_notes,
            "limitations":           profile.limitations,
        }

    def print_setup_guide(self) -> str:
        """راهنمای راه‌اندازی سریع برای red teamer"""
        return """
╔══════════════════════════════════════════════════════════════╗
║       Traffic Routing Setup Guide — Authorized Use Only      ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  1. Install Tor:                                             ║
║     sudo apt install tor                                     ║
║     sudo service tor start                                   ║
║                                                              ║
║  2. Install proxychains4:                                    ║
║     sudo apt install proxychains4                            ║
║                                                              ║
║  3. Test Tor circuit:                                        ║
║     curl --proxy socks5://127.0.0.1:9050 https://ipinfo.io  ║
║                                                              ║
║  4. Nmap through Tor (TCP only):                             ║
║     proxychains4 nmap -sT -Pn -n TARGET                     ║
║                                                              ║
║  5. New Tor circuit between scan phases:                     ║
║     Use: engine.traffic_router.new_tor_identity()           ║
║                                                              ║
║  ⚠️  UDP/ICMP/SYN scans CANNOT be proxied                    ║
║  ⚠️  Always verify scope document before use                  ║
╚══════════════════════════════════════════════════════════════╝
"""
