# aegis-scanner/modules/realtime_analyzer.py
"""
تحلیل Real-Time پکت‌های شبکه.

این ماژول در v3 به engine اصلی متصل شد.

قابلیت‌ها:
  - اندازه‌گیری دقیق RTT از طریق TCP handshake واقعی
  - تشخیص middlebox / DPI / Stateful Firewall
  - TCP fingerprint برای OS guess
  - تشخیص throttling و RST injection
  - تنظیم خودکار Nmap args بر اساس داده real-time
  - Scapy (اگر نصب) برای دقت بیشتر، fallback به raw socket

ابزارهای پشتیبانی‌شده:
  - scapy (ترجیحی — دقیق‌تر)
  - socket raw (fallback — محدود)
  - tcpdump (برای capture)
"""

import os
import re
import time
import socket
import struct
import logging
import threading
import subprocess
import statistics
from dataclasses import dataclass, field
from typing import Optional, Callable

logger = logging.getLogger(__name__)

try:
    from scapy.all import (
        IP, TCP, ICMP, sr1, send, conf,
        sniff, wrpcap, rdpcap
    )
    from scapy.error import Scapy_Exception
    conf.verb = 0
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    logger.debug("[RTA] scapy not installed — using socket-based fallback")


@dataclass
class PacketSample:
    timestamp:   float
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    protocol:    str
    flags:       str
    ttl:         int
    window_size: int
    payload_len: int
    rtt_ms:      Optional[float] = None


@dataclass
class TCPHandshake:
    target:         str
    port:           int
    syn_sent_at:    float
    synack_recv_at: float
    rtt_ms:         float
    server_ttl:     int
    server_window:  int
    server_mss:     int
    success:        bool
    os_guess:       str


@dataclass
class NetworkBehavior:
    target:            str
    samples:           int
    avg_rtt_ms:        float
    min_rtt_ms:        float
    max_rtt_ms:        float
    std_rtt_ms:        float
    packet_loss_pct:   float
    rst_injections:    int
    throttling_detected: bool
    mtu_issues:        bool
    ttl_variance:      float
    recommended_timing: str
    recommended_mtu:   int
    middlebox_detected: bool
    analysis_notes:    list = field(default_factory=list)


@dataclass
class ScanAdaptation:
    original_args: str
    adapted_args:  str
    changes_made:  list
    confidence:    float
    basis:         str


class RealtimeAnalyzer:
    """
    تحلیلگر real-time شبکه — در v3 به engine متصل شد.
    """

    OS_FINGERPRINTS = [
        {"os": "Linux 4.x/5.x",  "ttl": 64,  "window": 29200, "mss": 1460},
        {"os": "Linux 3.x",       "ttl": 64,  "window": 14600, "mss": 1460},
        {"os": "Windows 10/11",   "ttl": 128, "window": 65535, "mss": 1460},
        {"os": "Windows Server",  "ttl": 128, "window": 8192,  "mss": 1460},
        {"os": "macOS/FreeBSD",   "ttl": 64,  "window": 65535, "mss": 1460},
        {"os": "Cisco IOS",       "ttl": 255, "window": 4128,  "mss": 536},
        {"os": "Solaris",         "ttl": 255, "window": 49152, "mss": 1460},
        {"os": "AIX",             "ttl": 60,  "window": 16384, "mss": 1460},
    ]

    def measure_tcp_handshake(
        self, target: str, port: int = 80,
        count: int = 3, timeout: float = 5.0
    ) -> TCPHandshake:
        """اندازه‌گیری RTT با TCP handshake واقعی"""
        if SCAPY_OK:
            return self._handshake_scapy(target, port, count, timeout)
        return self._handshake_socket(target, port, count, timeout)

    def _handshake_scapy(
        self, target: str, port: int, count: int, timeout: float
    ) -> TCPHandshake:
        rtts, server_ttl, server_window, server_mss = [], 0, 0, 0

        for _ in range(count):
            try:
                syn = IP(dst=target) / TCP(
                    dport=port, sport=40000 + (_ * 11),
                    flags="S", seq=int(time.time() * 1000) & 0xFFFFFFFF
                )
                t0   = time.monotonic()
                resp = sr1(syn, timeout=timeout, verbose=0)
                rtt  = (time.monotonic() - t0) * 1000

                if resp and resp.haslayer(TCP):
                    tcp_layer = resp.getlayer(TCP)
                    if tcp_layer.flags & 0x12:  # SYN-ACK
                        rtts.append(rtt)
                        server_ttl    = resp.ttl
                        server_window = tcp_layer.window
                        # استخراج MSS از options
                        for opt in tcp_layer.options:
                            if opt[0] == "MSS":
                                server_mss = opt[1]
                        # ارسال RST برای بستن اتصال
                        rst = IP(dst=target) / TCP(
                            dport=port, sport=syn[TCP].sport,
                            flags="R", seq=tcp_layer.ack
                        )
                        send(rst, verbose=0)
                time.sleep(0.2)
            except Exception as e:
                logger.debug(f"[RTA/scapy] handshake: {e}")

        return self._build_handshake_result(
            target, port, rtts, server_ttl, server_window, server_mss
        )

    def _handshake_socket(
        self, target: str, port: int, count: int, timeout: float
    ) -> TCPHandshake:
        rtts, server_ttl, server_window, server_mss = [], 0, 0, 0

        for _ in range(count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                t0     = time.monotonic()
                result = sock.connect_ex((target, port))
                rtt    = (time.monotonic() - t0) * 1000
                if result == 0:
                    rtts.append(rtt)
                    try:
                        server_ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                    except Exception:
                        pass
                sock.close()
                time.sleep(0.1)
            except Exception as e:
                logger.debug(f"[RTA/socket] handshake: {e}")

        return self._build_handshake_result(
            target, port, rtts, server_ttl, server_window, server_mss
        )

    def _build_handshake_result(
        self, target: str, port: int,
        rtts: list, ttl: int, window: int, mss: int
    ) -> TCPHandshake:
        success = bool(rtts)
        avg_rtt = statistics.mean(rtts) if rtts else 9999.0
        os_guess = self._guess_os(ttl, window, mss)

        return TCPHandshake(
            target=target, port=port,
            syn_sent_at=0, synack_recv_at=0,
            rtt_ms=round(avg_rtt, 2),
            server_ttl=ttl, server_window=window,
            server_mss=mss or 1460,
            success=success, os_guess=os_guess,
        )

    def _guess_os(self, ttl: int, window: int, mss: int) -> str:
        if not ttl:
            return "Unknown"
        best_match, best_score = "Unknown", 0

        for fp in self.OS_FINGERPRINTS:
            score    = 0
            ttl_diff = abs(ttl - fp["ttl"])
            if ttl_diff <= 5:    score += 3
            elif ttl_diff <= 15: score += 1

            if window and abs(window - fp["window"]) < 1000:
                score += 2
            if mss and abs(mss - fp["mss"]) < 50:
                score += 1

            if score > best_score:
                best_score = score
                best_match = fp["os"]

        return best_match

    def analyze_network_behavior(
        self, target: str, test_ports: list,
        duration_sec: float = 10.0,
        callback: Optional[Callable[[str], None]] = None,
    ) -> NetworkBehavior:
        """تحلیل رفتار شبکه — تشخیص throttling، RST injection، MTU blackhole"""
        samples, rst_count, ttl_values = [], 0, []

        if callback:
            callback("Starting real-time network analysis...")

        start = time.monotonic()
        while time.monotonic() - start < duration_sec:
            for port in test_ports[:3]:
                try:
                    t0   = time.monotonic()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3.0)
                    result = sock.connect_ex((target, port))
                    rtt    = (time.monotonic() - t0) * 1000

                    if result == 0:
                        samples.append(rtt)
                        try:
                            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                            if ttl:
                                ttl_values.append(ttl)
                        except Exception:
                            pass
                    elif result == 104:  # ECONNRESET
                        rst_count += 1

                    sock.close()
                    time.sleep(0.3)
                except Exception:
                    pass

        return self._analyze_samples(target, samples, rst_count, ttl_values, callback)

    def _analyze_samples(
        self, target: str, samples: list,
        rst_count: int, ttl_values: list,
        callback: Optional[Callable],
    ) -> NetworkBehavior:
        n, notes = len(samples), []

        if n < 2:
            return NetworkBehavior(
                target=target, samples=n,
                avg_rtt_ms=samples[0] if samples else 9999,
                min_rtt_ms=samples[0] if samples else 9999,
                max_rtt_ms=samples[0] if samples else 9999,
                std_rtt_ms=0, packet_loss_pct=100.0,
                rst_injections=rst_count, throttling_detected=False,
                mtu_issues=False, ttl_variance=0,
                recommended_timing="T2", recommended_mtu=1400,
                middlebox_detected=rst_count > 0,
                analysis_notes=["Insufficient samples for deep analysis"],
            )

        avg_rtt = statistics.mean(samples)
        min_rtt = min(samples)
        max_rtt = max(samples)
        std_rtt = statistics.stdev(samples) if n > 1 else 0
        loss    = 0.0

        # تشخیص throttling
        throttling = False
        if n >= 6:
            first_half  = statistics.mean(samples[:n // 2])
            second_half = statistics.mean(samples[n // 2:])
            if second_half > first_half * 1.5:
                throttling = True
                notes.append(
                    f"Throttling: RTT {first_half:.0f}ms → {second_half:.0f}ms "
                    "— IDS/QoS rate-limiting suspected"
                )

        if rst_count > 0:
            notes.append(
                f"{rst_count} RST injections — stateful firewall blocking scans"
            )

        ttl_var   = statistics.stdev(ttl_values) if len(ttl_values) > 1 else 0.0
        middlebox = ttl_var > 3 or rst_count > 0
        if ttl_var > 3:
            notes.append(
                f"TTL variance σ={ttl_var:.1f} — load balancer or NAT detected"
            )

        mtu_issues = std_rtt > avg_rtt * 0.6 and loss < 10
        if mtu_issues:
            notes.append(
                f"High RTT variance (σ={std_rtt:.0f}ms) — possible MTU black hole"
            )

        if throttling or rst_count > 2:
            rec_timing = "T1"
        elif avg_rtt > 200 or std_rtt > 50:
            rec_timing = "T2"
        elif avg_rtt > 50:
            rec_timing = "T3"
        else:
            rec_timing = "T4"

        rec_mtu = 1280 if mtu_issues else (1400 if avg_rtt > 300 else 1500)

        if callback:
            callback(
                f"Analysis: RTT={avg_rtt:.0f}ms±{std_rtt:.0f}ms | "
                f"Timing={rec_timing} | MTU={rec_mtu}"
            )

        return NetworkBehavior(
            target=target, samples=n,
            avg_rtt_ms=round(avg_rtt, 1), min_rtt_ms=round(min_rtt, 1),
            max_rtt_ms=round(max_rtt, 1), std_rtt_ms=round(std_rtt, 1),
            packet_loss_pct=round(loss, 1), rst_injections=rst_count,
            throttling_detected=throttling, mtu_issues=mtu_issues,
            ttl_variance=round(ttl_var, 2), recommended_timing=rec_timing,
            recommended_mtu=rec_mtu, middlebox_detected=middlebox,
            analysis_notes=notes,
        )

    def adapt_scan_args(
        self, original_args: str,
        behavior: NetworkBehavior,
        handshake: Optional[TCPHandshake] = None,
    ) -> ScanAdaptation:
        """تنظیم خودکار Nmap args بر اساس داده real-time"""
        import re as _re
        args      = original_args
        changes   = []
        confidence = 0.0

        # Timing
        new_timing = behavior.recommended_timing
        if new_timing:
            args = _re.sub(r"-T\d", "", args).strip()
            args += f" -{new_timing}"
            changes.append(f"Timing → {new_timing} (RTT={behavior.avg_rtt_ms:.0f}ms)")
            confidence += 0.3

        # MTU
        if behavior.recommended_mtu < 1500:
            if "--mtu" not in args:
                args += f" --mtu {behavior.recommended_mtu}"
            else:
                args = _re.sub(r"--mtu \d+", f"--mtu {behavior.recommended_mtu}", args)
            changes.append(f"MTU → {behavior.recommended_mtu}")
            confidence += 0.2

        # Throttling
        if behavior.throttling_detected:
            if "--max-rate" not in args and "--min-rate" not in args:
                args += " --max-rate 10"
            changes.append("max-rate 10/s (throttling)")
            confidence += 0.2

        # RST injection
        if behavior.rst_injections > 0:
            if "--max-retries" not in args:
                retries = min(behavior.rst_injections + 1, 5)
                args += f" --max-retries {retries}"
            changes.append(f"max-retries ({behavior.rst_injections} RSTs detected)")
            confidence += 0.15

        # MSS از handshake
        if handshake and handshake.success and handshake.server_mss:
            optimal_mtu = handshake.server_mss + 40
            if optimal_mtu < 1500 and "--mtu" not in args:
                args += f" --mtu {optimal_mtu}"
                changes.append(f"MTU tuned to MSS+40 ({optimal_mtu})")
                confidence += 0.1

        confidence = min(confidence, 0.95)
        basis = (
            f"{behavior.samples} real-time measurements | "
            f"avg_rtt={behavior.avg_rtt_ms}ms | "
            f"throttling={behavior.throttling_detected} | "
            f"middlebox={behavior.middlebox_detected}"
        )

        return ScanAdaptation(
            original_args=original_args,
            adapted_args=args.strip(),
            changes_made=changes,
            confidence=confidence,
            basis=basis,
        )

    def capture_with_tcpdump(
        self, target: str, duration: int = 10,
        output_file: Optional[str] = None,
    ) -> list:
        """Capture پکت‌ها با tcpdump"""
        if output_file is None:
            output_file = f"/tmp/aegis_capture_{int(time.time())}.pcap"
        try:
            cmd = [
                "tcpdump", "-i", "any", "-w", output_file,
                "-G", str(duration), "-W", "1", f"host {target}",
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(duration + 1)
            proc.terminate()
            logger.info(f"[RTA] Capture saved: {output_file}")
            return [output_file]
        except FileNotFoundError:
            logger.warning("[RTA] tcpdump not available")
            return []
        except Exception as e:
            logger.debug(f"[RTA] tcpdump: {e}")
            return []

    # ─── Serialization ────────────────────────────────────────────────────
    @staticmethod
    def handshake_to_dict(h: TCPHandshake) -> dict:
        return {
            "target": h.target, "port": h.port,
            "rtt_ms": h.rtt_ms, "server_ttl": h.server_ttl,
            "server_window": h.server_window, "server_mss": h.server_mss,
            "success": h.success, "os_guess": h.os_guess,
        }

    @staticmethod
    def behavior_to_dict(b: NetworkBehavior) -> dict:
        return {
            "target": b.target, "samples": b.samples,
            "avg_rtt_ms": b.avg_rtt_ms, "min_rtt_ms": b.min_rtt_ms,
            "max_rtt_ms": b.max_rtt_ms, "std_rtt_ms": b.std_rtt_ms,
            "packet_loss_pct": b.packet_loss_pct,
            "rst_injections": b.rst_injections,
            "throttling_detected": b.throttling_detected,
            "mtu_issues": b.mtu_issues, "ttl_variance": b.ttl_variance,
            "recommended_timing": b.recommended_timing,
            "recommended_mtu": b.recommended_mtu,
            "middlebox_detected": b.middlebox_detected,
            "analysis_notes": b.analysis_notes,
        }

    @staticmethod
    def adaptation_to_dict(a: ScanAdaptation) -> dict:
        return {
            "original_args": a.original_args,
            "adapted_args":  a.adapted_args,
            "changes_made":  a.changes_made,
            "confidence":    round(a.confidence, 2),
            "basis":         a.basis,
        }
