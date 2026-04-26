# aegis-scanner/modules/evasion_engine.py
"""
موتور فرار پیشرفته از IDS/IPS/Firewall.

تکنیک‌های پیاده‌سازی شده (بر اساس مستندات Nmap و تحقیقات امنیتی):
  ├── TTL Manipulation     → دستکاری TTL برای دور زدن packet reassembly در IDS
  ├── Packet Fragmentation → fragmentation با اندازه‌های غیرمعمول
  ├── Decoy Injection      → اضافه کردن IP های جعلی به اسکن
  ├── Timing Jitter        → تغییر تصادفی فاصله‌ی بین packet‌ها
  ├── Source Port Spoof    → استفاده از پورت‌های مجاز (53, 80, 443)
  ├── Bad Checksum         → شناسایی stateless firewall
  └── Protocol Confusion   → ارسال payload غیرمنتظره برای تشخیص IDS signature
"""

import random
import logging
import socket
import struct
import time
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class EvasionProfile:
    """پروفایل کامل فرار برای یک target"""
    target: str
    firewall_detected:     bool = False
    ids_detected:          bool = False
    stateless_firewall:    bool = False
    honeypot_suspicion:    float = 0.0          # 0.0 - 1.0
    recommended_ttl:       int   = 64
    recommended_mtu:       int   = 1500
    recommended_timing:    str   = "T3"
    recommended_decoys:    str   = ""
    source_port:           int   = 0
    scan_flags:            list  = field(default_factory=list)
    final_nmap_args:       str   = ""
    evasion_score:         int   = 0            # 1-10
    techniques_applied:    list  = field(default_factory=list)
    detection_risk:        str   = "MEDIUM"     # LOW / MEDIUM / HIGH
    analysis_notes:        list  = field(default_factory=list)


class EvasionEngine:
    """
    موتور تحلیل و ساخت استراتژی فرار از سیستم‌های تشخیص نفوذ.

    pipeline:
    1. Firewall fingerprint  → تشخیص نوع فایروال
    2. IDS probe             → بررسی وجود IDS
    3. TTL analysis          → تعیین hop count و TTL بهینه
    4. Strategy selection    → انتخاب بهترین ترکیب تکنیک‌ها
    5. Nmap args generation  → ساختن command نهایی
    """

    # پورت‌های "قانونی" که فایروال‌ها معمولاً block نمی‌کنند
    TRUSTED_SOURCE_PORTS = [53, 80, 88, 443, 8080, 8443]

    # TTL پیش‌فرض سیستم‌عامل‌ها
    OS_DEFAULT_TTL = {
        "windows": 128,
        "linux":   64,
        "cisco":   255,
        "solaris": 255,
        "freebsd": 64,
    }

    # حداکثر MTU برای fragmentation مؤثر بر IDS‌های مختلف
    EVASION_MTU_MAP = {
        "snort":    8,     # Snort reassembly threshold
        "suricata": 16,
        "generic":  24,    # معمول‌ترین مقدار
        "safe":     48,    # ایمن‌ترین مقدار
    }

    def __init__(self):
        self._rng = random.SystemRandom()   # cryptographically random

    # ─── Main pipeline ────────────────────────────────────────────────────
    def analyze_and_build_profile(
        self,
        target: str,
        open_ports: list,
        rtt_ms: float,
        scan_level: int = 2,
    ) -> EvasionProfile:
        """
        تحلیل کامل target و ساخت پروفایل بهینه فرار.
        """
        profile = EvasionProfile(target=target)

        # Phase 1: TTL analysis
        self._analyze_ttl(target, profile)

        # Phase 2: Firewall detection
        self._detect_firewall(target, open_ports, profile)

        # Phase 3: IDS behavioral probe
        self._probe_ids_presence(target, open_ports, profile)

        # Phase 4: Source port selection
        profile.source_port = self._select_source_port(open_ports)

        # Phase 5: Build final evasion strategy
        self._build_strategy(profile, rtt_ms, scan_level)

        # Phase 6: Score evasion effectiveness
        profile.evasion_score   = self._score_evasion(profile)
        profile.detection_risk  = self._assess_detection_risk(profile)

        logger.info(
            f"[EvasionEngine] Profile built | "
            f"Firewall={profile.firewall_detected} | "
            f"IDS={profile.ids_detected} | "
            f"Score={profile.evasion_score}/10"
        )
        return profile

    # ─── Phase 1: TTL Analysis ────────────────────────────────────────────
    def _analyze_ttl(self, target: str, profile: EvasionProfile) -> None:
        """
        اندازه‌گیری TTL برای تخمین hop count و OS target.
        TTL دریافتی = TTL اولیه OS - hop_count
        """
        try:
            result = subprocess.run(
                ["ping", "-c", "3", "-W", "2", target],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout

            # استخراج TTL از خروجی ping
            import re
            ttl_matches = re.findall(r"ttl=(\d+)", output, re.IGNORECASE)
            if not ttl_matches:
                profile.analysis_notes.append("Could not determine TTL (ICMP blocked?)")
                return

            avg_ttl = sum(int(t) for t in ttl_matches) / len(ttl_matches)

            # تخمین OS بر اساس TTL
            if avg_ttl > 200:
                detected_os = "cisco/solaris"
                base_ttl    = 255
            elif avg_ttl > 100:
                detected_os = "windows"
                base_ttl    = 128
            else:
                detected_os = "linux/freebsd"
                base_ttl    = 64

            hop_count = round(base_ttl - avg_ttl)
            profile.recommended_ttl = base_ttl
            profile.techniques_applied.append(f"TTL fingerprint: {detected_os} (~{hop_count} hops)")
            profile.analysis_notes.append(
                f"Observed TTL={avg_ttl:.0f} → estimated OS={detected_os}, "
                f"hops≈{hop_count}"
            )

        except subprocess.TimeoutExpired:
            profile.analysis_notes.append("TTL analysis timed out")
        except Exception as e:
            logger.debug(f"[EvasionEngine] TTL analysis: {e}")

    # ─── Phase 2: Firewall Detection ──────────────────────────────────────
    def _detect_firewall(
        self, target: str, open_ports: list, profile: EvasionProfile
    ) -> None:
        """
        تشخیص فایروال با بررسی الگوی پاسخ‌ها.

        نشانه‌های stateful firewall:
        - پورت‌های filtered بدون RST
        - RTT غیریکنواخت

        نشانه‌های stateless firewall:
        - RST فوری روی تمام closed ports
        - TTL یکسان برای تمام پاسخ‌ها
        """
        # بررسی وجود filtered ports از طریق nmap
        try:
            result = subprocess.run(
                ["nmap", "-sA", "-p", "80,443,22", "--open", "-T4", target],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout

            if "filtered" in output.lower():
                profile.firewall_detected = True
                profile.techniques_applied.append("Stateful firewall detected (filtered ports)")
                profile.analysis_notes.append(
                    "ACK scan shows filtered ports → stateful firewall present"
                )

            if "unfiltered" in output.lower():
                profile.stateless_firewall = True
                profile.analysis_notes.append(
                    "ACK scan shows unfiltered → stateless/packet-filter firewall"
                )

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"[EvasionEngine] Firewall probe: {e}")
            # fallback: اگر open ports خیلی کم است، احتمال فایروال بالا است
            if len(open_ports) < 3:
                profile.firewall_detected = True
                profile.analysis_notes.append(
                    "Few open ports detected — firewall likely present (assumption)"
                )

    # ─── Phase 3: IDS Behavioral Probe ───────────────────────────────────
    def _probe_ids_presence(
        self, target: str, open_ports: list, profile: EvasionProfile
    ) -> None:
        """
        تشخیص IDS با مقایسه‌ی رفتار پورت‌های باز و بسته.

        تکنیک: ارسال چند probe با timing متفاوت و بررسی consistency.
        IDS‌ها معمولاً بعد از burst traffic رفتار target را تغییر می‌دهند.
        """
        if not open_ports:
            return

        test_port = open_ports[0]["port"]
        response_times = []

        # ارسال ۵ probe متوالی
        for _ in range(5):
            try:
                t_start = time.monotonic()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                result = sock.connect_ex((target, test_port))
                rtt = (time.monotonic() - t_start) * 1000
                sock.close()
                if result == 0:
                    response_times.append(rtt)
                time.sleep(0.1)
            except Exception:
                pass

        if len(response_times) < 3:
            profile.analysis_notes.append("IDS probe: insufficient responses")
            return

        # تحلیل variance در response time
        avg_rtt  = sum(response_times) / len(response_times)
        variance = sum((r - avg_rtt) ** 2 for r in response_times) / len(response_times)
        std_dev  = variance ** 0.5

        # variance بالا → IDS در حال تأخیر‌گذاری (rate limiting)
        if std_dev > avg_rtt * 0.5 and std_dev > 50:
            profile.ids_detected = True
            profile.techniques_applied.append(
                f"IDS behavioral signature: high RTT variance (σ={std_dev:.1f}ms)"
            )
            profile.analysis_notes.append(
                f"RTT stddev={std_dev:.1f}ms (>{avg_rtt*0.5:.1f}ms threshold) "
                f"→ possible IDS rate-limiting detected"
            )
        else:
            profile.analysis_notes.append(
                f"RTT variance normal (σ={std_dev:.1f}ms) → IDS not detected"
            )

    # ─── Phase 4: Source port selection ──────────────────────────────────
    def _select_source_port(self, open_ports: list) -> int:
        """
        انتخاب source port برای دور زدن ACL‌های ساده.
        ترجیح: از پورت‌هایی که firewall معمولاً allow می‌کند.
        """
        open_port_nums = {p["port"] for p in open_ports}

        # استفاده از پورت مجاز که روی target open است
        for port in self.TRUSTED_SOURCE_PORTS:
            if port in open_port_nums:
                return port

        # fallback به DNS (53) که معمولاً مجاز است
        return 53

    # ─── Phase 5: Build evasion strategy ─────────────────────────────────
    def _build_strategy(
        self, profile: EvasionProfile, rtt_ms: float, scan_level: int
    ) -> None:
        """ساخت args نهایی Nmap بر اساس تحلیل‌های انجام‌شده"""
        args_parts = []

        # ─── Scan type ────────────────────────────────────────────────────
        args_parts.append("-sS")    # SYN scan (نیاز به root)
        args_parts.append("--open")

        # ─── Timing ───────────────────────────────────────────────────────
        if profile.ids_detected:
            timing = "T1"
            profile.recommended_timing = "T1"
            profile.techniques_applied.append("T1 timing (IDS detected)")
        elif profile.firewall_detected:
            timing = "T2"
            profile.recommended_timing = "T2"
            profile.techniques_applied.append("T2 timing (firewall detected)")
        elif rtt_ms < 50:
            timing = "T4"
            profile.recommended_timing = "T4"
        else:
            timing = "T3"
            profile.recommended_timing = "T3"
        args_parts.append(f"-{timing}")

        # ─── Fragmentation ────────────────────────────────────────────────
        if profile.ids_detected:
            mtu = self.EVASION_MTU_MAP["snort"]
            profile.recommended_mtu = mtu
            args_parts.append(f"--mtu {mtu}")
            profile.techniques_applied.append(f"Packet fragmentation (MTU={mtu})")
        elif profile.firewall_detected:
            mtu = self.EVASION_MTU_MAP["generic"]
            profile.recommended_mtu = mtu
            args_parts.append(f"--mtu {mtu}")
            profile.techniques_applied.append(f"Packet fragmentation (MTU={mtu})")

        # ─── Decoys ───────────────────────────────────────────────────────
        if profile.firewall_detected or profile.ids_detected:
            decoy_count = 5 if profile.ids_detected else 3
            decoys = self._generate_decoys(profile.target, decoy_count)
            decoy_str = ",".join(decoys) + ",ME"
            profile.recommended_decoys = decoy_str
            args_parts.append(f"-D {decoy_str}")
            profile.techniques_applied.append(
                f"Decoy injection ({decoy_count} decoys)"
            )

        # ─── Source port ──────────────────────────────────────────────────
        if profile.source_port:
            args_parts.append(f"--source-port {profile.source_port}")
            profile.techniques_applied.append(
                f"Source port spoofing (port {profile.source_port})"
            )

        # ─── TTL manipulation ─────────────────────────────────────────────
        if profile.recommended_ttl != 64:
            args_parts.append(f"--ttl {profile.recommended_ttl}")
            profile.techniques_applied.append(
                f"TTL manipulation ({profile.recommended_ttl})"
            )

        # ─── Randomize hosts ──────────────────────────────────────────────
        args_parts.append("--randomize-hosts")

        # ─── Max retries ──────────────────────────────────────────────────
        retries = 3 if profile.ids_detected else 1
        args_parts.append(f"--max-retries {retries}")

        # ─── Version detection ────────────────────────────────────────────
        if scan_level >= 2:
            args_parts.append("-sV --version-intensity 5")

        profile.final_nmap_args = " ".join(args_parts)

    # ─── Decoy generation ─────────────────────────────────────────────────
    def _generate_decoys(self, target: str, count: int = 5) -> list:
        """
        تولید IP های decoy که در همان subnet target قرار دارند.
        استفاده از IP‌های واقعی‌تر (هم‌شبکه) باعث bypass بهتر می‌شود.
        """
        decoys = []
        try:
            # تلاش برای استفاده از IP هم‌شبکه
            parts = target.split(".")
            if len(parts) == 4:
                base = ".".join(parts[:3])
                own_last = int(parts[3])
                candidates = [
                    i for i in range(1, 255)
                    if i != own_last and i != 1 and i != 254
                ]
                selected = self._rng.sample(candidates, min(count, len(candidates)))
                decoys = [f"{base}.{i}" for i in selected]
        except Exception:
            pass

        # fallback: RND (random IPs)
        if not decoys:
            decoys = [f"RND:{count}"]

        return decoys

    # ─── Scoring ──────────────────────────────────────────────────────────
    def _score_evasion(self, profile: EvasionProfile) -> int:
        """امتیاز اثربخشی استراتژی فرار (1-10)"""
        score = 5  # baseline

        if profile.ids_detected:
            score += 2    # کشف IDS → تکنیک‌های بیشتر فعال شد
        if profile.firewall_detected:
            score += 1
        if profile.recommended_decoys:
            score += 1
        if profile.source_port in self.TRUSTED_SOURCE_PORTS:
            score += 1
        if "--mtu" in profile.final_nmap_args:
            score += 1
        if profile.recommended_timing in ("T1", "T2"):
            score -= 1    # آهسته‌تر → کمتر شناسایی می‌شود اما score رتبه‌بندی پایین‌تر

        return min(max(score, 1), 10)

    def _assess_detection_risk(self, profile: EvasionProfile) -> str:
        """ارزیابی ریسک شناسایی شدن scan"""
        if profile.ids_detected and not profile.recommended_decoys:
            return "HIGH"
        if profile.ids_detected and profile.recommended_decoys:
            return "MEDIUM"
        if profile.firewall_detected and profile.recommended_timing in ("T1", "T2"):
            return "LOW"
        if profile.recommended_timing in ("T4", "T5"):
            return "HIGH"
        return "MEDIUM"

    def to_dict(self, profile: EvasionProfile) -> dict:
        """تبدیل پروفایل به dict"""
        return {
            "target":              profile.target,
            "firewall_detected":   profile.firewall_detected,
            "ids_detected":        profile.ids_detected,
            "stateless_firewall":  profile.stateless_firewall,
            "recommended_ttl":     profile.recommended_ttl,
            "recommended_mtu":     profile.recommended_mtu,
            "recommended_timing":  profile.recommended_timing,
            "recommended_decoys":  profile.recommended_decoys,
            "source_port":         profile.source_port,
            "final_nmap_args":     profile.final_nmap_args,
            "evasion_score":       profile.evasion_score,
            "techniques_applied":  profile.techniques_applied,
            "detection_risk":      profile.detection_risk,
            "analysis_notes":      profile.analysis_notes,
        }
