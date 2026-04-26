# aegis-scanner/core/nmap_controller.py
"""
Wrapper کامل برای Nmap با مدیریت دقیق خطا، retry، و parsing.
از python-nmap استفاده می‌کند اما subprocess را نیز برای موارد edge case کنترل می‌کند.
"""

import logging
import subprocess
import time
import re
import socket
from typing import Optional, Tuple
from dataclasses import dataclass, field

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

from config.settings import NmapSettings
from config.constants import NMAP_SCAN_LEVELS, NMAP_TIMING_PROFILES

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """نتیجه ساختارمند یک اسکن Nmap"""
    target: str
    scan_args: str
    raw_data: dict
    hosts_up: int
    hosts_down: int
    open_ports: list
    scan_start: float
    scan_end: float
    rtt_ms: float
    packet_loss_pct: float
    error: Optional[str] = None
    warnings: list = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return self.scan_end - self.scan_start

    @property
    def success(self) -> bool:
        # اسکن موفق = بدون error
        # hosts_up=0 یعنی host down یا firewalled — ولی اسکن خودش سالم بوده
        return self.error is None


class NmapController:
    """
    مدیریت کامل عملیات Nmap با قابلیت retry و مدیریت خطا.
    
    اصل طراحی: هر scan بدون در نظر گرفتن نتیجه باید داده‌ای برگرداند؛
    شکست به معنای از دست دادن اطلاعات نیست بلکه جزئی از اطلاعات است.
    """

    def __init__(self, settings: NmapSettings):
        self.settings = settings
        if not NMAP_AVAILABLE:
            raise RuntimeError(
                "python-nmap not installed. Run: pip install python-nmap"
            )
        self._scanner = nmap.PortScanner()
        logger.info(f"[Nmap] Controller initialized | binary: {settings.binary_path}")

    # ─── Target validation ─────────────────────────────────────────────────
    @staticmethod
    def validate_target(target: str) -> Tuple[bool, str]:
        """
        اعتبارسنجی target برای جلوگیری از injection و خطای فنی.
        برمی‌گرداند: (valid, normalized_target)
        """
        target = target.strip()

        # بررسی خالی بودن
        if not target:
            return False, "Target cannot be empty"

        # جلوگیری از command injection
        dangerous = [";", "&", "|", "`", "$", "(", ")", "<", ">", "\\"]
        if any(c in target for c in dangerous):
            return False, f"Invalid characters in target: {target}"

        # IP range CIDR
        cidr_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"
        if re.match(cidr_pattern, target):
            return True, target

        # IP range dash notation (192.168.1.1-50)
        dash_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$"
        if re.match(dash_pattern, target):
            return True, target

        # IP wildcard (192.168.1.*)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\*$", target):
            return True, target

        # Single IP
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, target):
            parts = target.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                return True, target
            return False, f"Invalid IP address: {target}"

        # Hostname validation
        hostname_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$"
        if re.match(hostname_pattern, target):
            return True, target

        return False, f"Unrecognized target format: {target}"

    # ─── RTT measurement ───────────────────────────────────────────────────
    def measure_rtt(self, target: str, count: int = 4) -> Tuple[float, float]:
        """
        اندازه‌گیری RTT و packet loss با ping.
        برمی‌گرداند: (avg_rtt_ms, packet_loss_pct)
        """
        try:
            result = subprocess.run(
                ["ping", "-c", str(count), "-W", "3", target],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout

            # استخراج RTT
            rtt_match = re.search(
                r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms",
                output
            )
            avg_rtt = float(rtt_match.group(1)) if rtt_match else 999.0

            # استخراج packet loss
            loss_match = re.search(r"(\d+)% packet loss", output)
            packet_loss = float(loss_match.group(1)) if loss_match else 100.0

            logger.debug(f"[Nmap] RTT={avg_rtt}ms | Loss={packet_loss}%")
            return avg_rtt, packet_loss

        except subprocess.TimeoutExpired:
            logger.warning("[Nmap] Ping timed out")
            return 999.0, 100.0
        except FileNotFoundError:
            logger.warning("[Nmap] ping not available, estimating RTT via TCP")
            return self._tcp_rtt(target)
        except Exception as e:
            logger.error(f"[Nmap] RTT measurement error: {e}")
            return 500.0, 50.0

    def _tcp_rtt(self, target: str, port: int = 80) -> Tuple[float, float]:
        """اندازه‌گیری RTT از طریق TCP connection"""
        try:
            start = time.time()
            sock = socket.create_connection((target, port), timeout=5)
            rtt = (time.time() - start) * 1000
            sock.close()
            return rtt, 0.0
        except Exception:
            return 999.0, 100.0

    # ─── Core scan ─────────────────────────────────────────────────────────
    def run_scan(
        self,
        target: str,
        ports: str = "1-1024",
        scan_level: int = 2,
        custom_args: Optional[str] = None,
        sudo: Optional[bool] = None,
    ) -> ScanResult:
        """
        اجرای اسکن Nmap با مدیریت کامل خطا و retry.
        
        Args:
            target: IP / hostname / CIDR
            ports: port range (e.g., "22,80,443" or "1-65535")
            scan_level: 1-5 از NMAP_SCAN_LEVELS
            custom_args: جایگزین args پیش‌فرض
            sudo: اجرا با sudo (برای SYN scan)
        """
        valid, normalized = self.validate_target(target)
        if not valid:
            return ScanResult(
                target=target, scan_args="", raw_data={},
                hosts_up=0, hosts_down=0, open_ports=[],
                scan_start=time.time(), scan_end=time.time(),
                rtt_ms=0, packet_loss_pct=0,
                error=normalized
            )

        # تعیین args
        if custom_args:
            args = custom_args
        else:
            level_data = NMAP_SCAN_LEVELS.get(scan_level, NMAP_SCAN_LEVELS[2])
            args = level_data["args"]

        use_sudo = sudo if sudo is not None else self.settings.privileged
        if use_sudo:
            args = f"--privileged {args}"

        scan_start = time.time()
        logger.info(f"[Nmap] Scanning {normalized} | ports={ports} | args={args}")

        # retry loop
        last_error: Optional[str] = None
        for attempt in range(1, self.settings.max_retries + 2):
            try:
                self._scanner.scan(
                    hosts=normalized,
                    ports=ports,
                    arguments=args,
                    timeout=self.settings.default_timeout,
                    sudo=use_sudo,
                )
                scan_end = time.time()
                logger.info(
                    f"[Nmap] Scan completed in {scan_end - scan_start:.1f}s "
                    f"(attempt {attempt})"
                )

                result = self._parse_results(
                    normalized, args, scan_start, scan_end
                )
                return result

            except nmap.PortScannerError as e:
                last_error = str(e)
                if "requires root" in last_error.lower() and not use_sudo:
                    logger.warning("[Nmap] Privilege required, retrying without SYN scan")
                    args = args.replace("-sS", "-sT").replace("-O", "")
                    continue
                logger.error(f"[Nmap] Scan error (attempt {attempt}): {e}")

            except Exception as e:
                last_error = str(e)
                logger.error(f"[Nmap] Unexpected error (attempt {attempt}): {e}")

            if attempt <= self.settings.max_retries:
                wait = 2 ** attempt
                logger.info(f"[Nmap] Waiting {wait}s before retry...")
                time.sleep(wait)

        scan_end = time.time()
        return ScanResult(
            target=normalized, scan_args=args, raw_data={},
            hosts_up=0, hosts_down=0, open_ports=[],
            scan_start=scan_start, scan_end=scan_end,
            rtt_ms=0, packet_loss_pct=0,
            error=last_error or "Unknown scan failure"
        )

    # ─── Result parsing ────────────────────────────────────────────────────
    def _parse_results(
        self, target: str, args: str,
        scan_start: float, scan_end: float
    ) -> ScanResult:
        """parsing خروجی python-nmap به ScanResult ساختارمند"""
        raw_data = dict(self._scanner._scan_result)
        scan_stats = self._scanner.scanstats()

        hosts_up   = int(scan_stats.get("uphosts", 0))
        hosts_down = int(scan_stats.get("downhosts", 0))

        open_ports = []
        warnings   = []

        for host in self._scanner.all_hosts():
            host_data = self._scanner[host]
            for proto in ("tcp", "udp"):
                if proto not in host_data:
                    continue
                for port, pdata in host_data[proto].items():
                    if pdata.get("state") == "open":
                        open_ports.append({
                            "host":    host,
                            "port":    int(port),
                            "proto":   proto,
                            "service": pdata.get("name", "unknown"),
                            "product": pdata.get("product", ""),
                            "version": pdata.get("version", ""),
                            "extra":   pdata.get("extrainfo", ""),
                            "cpe":     pdata.get("cpe", ""),
                            "scripts": pdata.get("script", {}),
                        })

        return ScanResult(
            target=target,
            scan_args=args,
            raw_data=raw_data,
            hosts_up=hosts_up,
            hosts_down=hosts_down,
            open_ports=open_ports,
            scan_start=scan_start,
            scan_end=scan_end,
            rtt_ms=0,
            packet_loss_pct=0,
            warnings=warnings,
        )

    # ─── Quick host discovery ──────────────────────────────────────────────
    def host_discovery(self, target: str) -> list:
        """کشف سریع host های زنده بدون port scan"""
        try:
            self._scanner.scan(hosts=target, arguments="-sn -T4")
            return [h for h in self._scanner.all_hosts()
                    if self._scanner[h].state() == "up"]
        except Exception as e:
            logger.error(f"[Nmap] Host discovery error: {e}")
            return []
