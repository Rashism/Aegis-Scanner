# aegis-scanner/modules/honeypot_detector.py
"""
تشخیص Honeypot با آنالیز آماری رفتار target.

تکنیک‌های تشخیص:
  ├── Port Consistency Analysis   → honeypot‌ها معمولاً تعداد بالایی پورت open دارند
  ├── Banner Timing Fingerprint   → تأخیر غیرطبیعی در ارسال banner
  ├── Response Entropy Analysis   → banner‌های ثابت یا الگودار
  ├── Cross-Port Correlation      → پاسخ مشابه روی پورت‌های مختلف
  ├── Interaction Depth Test      → رفتار زمانی که داده‌های garbage ارسال می‌شود
  └── Known Honeypot Signatures   → شناسه‌های شناخته‌شده (Cowrie, Dionaea, HoneyD)
"""

import re
import socket
import time
import logging
import hashlib
import statistics
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ─── Known honeypot fingerprints ─────────────────────────────────────────────
HONEYPOT_SIGNATURES = {
    # SSH honeypots
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2": {
        "name": "Cowrie (default banner)",
        "confidence": 0.90,
        "note": "Classic Cowrie default SSH banner",
    },
    "SSH-2.0-OpenSSH_5.1p1 Debian-5": {
        "name": "Kippo honeypot",
        "confidence": 0.85,
        "note": "Old Kippo default banner",
    },
    "SSH-2.0-libssh-0.7.0": {
        "name": "Possible Cowrie variant",
        "confidence": 0.70,
        "note": "libssh version commonly used in honeypots",
    },
    # HTTP honeypots
    "Server: Apache/2.2.22": {
        "name": "Glastopf web honeypot (possible)",
        "confidence": 0.60,
        "note": "Very old Apache version — often honeypot fingerprint",
    },
    "Server: nginx/1.4.6": {
        "name": "Possible HoneyProxy",
        "confidence": 0.55,
        "note": "Old nginx in suspicious context",
    },
    # FTP honeypots
    "220 (vsFTPd 2.3.4)": {
        "name": "Classic backdoored vsFTPd / honeypot bait",
        "confidence": 0.95,
        "note": "vsFTPd 2.3.4 had famous backdoor — often used as honeypot lure",
    },
    # Telnet
    "Ubuntu 8.04": {
        "name": "HoneyD (possible)",
        "confidence": 0.65,
        "note": "Very old OS banner — suspicious if combined with many open ports",
    },
}

# اگر target روی این پورت‌ها همه open بود، احتمال honeypot بالاست
HONEYPOT_PORT_SETS = [
    {21, 22, 23, 25, 80, 443, 3306, 8080},     # Cowrie + web honeypot combo
    {22, 23, 80, 8080, 3128, 9200},             # Dionaea variant
    {21, 22, 23, 25, 53, 80, 110, 443, 3306},   # Full-service honeypot
]


@dataclass
class HoneypotAnalysis:
    """نتیجه تحلیل honeypot برای یک target"""
    target:           str
    is_honeypot:      bool
    confidence:       float           # 0.0 - 1.0
    verdict:          str             # CLEAN / SUSPICIOUS / LIKELY_HONEYPOT / HONEYPOT
    matched_signatures: list
    behavioral_flags:   list
    port_anomalies:     list
    timing_anomalies:   list
    recommendation:     str
    risk_of_proceeding: str           # LOW / MEDIUM / HIGH / CRITICAL


class HoneypotDetector:
    """
    تشخیص honeypot با ترکیب چندین روش تحلیل.

    اصل اساسی: هیچ تک تکنیکی به تنهایی کافی نیست.
    امتیاز نهایی از مجموع شواهد محاسبه می‌شود.
    """

    HONEYPOT_THRESHOLD    = 0.65    # بالای این → likely honeypot
    SUSPICIOUS_THRESHOLD  = 0.35    # بالای این → suspicious

    # حداکثر زمان برای دریافت banner (ms)
    # honeypot‌ها معمولاً با تأخیر کمتری پاسخ می‌دهند (pre-recorded banners)
    BANNER_FAST_THRESHOLD = 50      # ms — خیلی سریع = suspicious
    BANNER_SLOW_THRESHOLD = 3000    # ms — خیلی کند = هم suspicious

    def analyze(self, target: str, open_ports: list) -> HoneypotAnalysis:
        """
        تحلیل کامل honeypot برای یک target.

        Args:
            target: IP address
            open_ports: لیست dict از NmapController
        """
        evidence_score = 0.0
        matched_sigs   = []
        behav_flags    = []
        port_anomalies = []
        timing_anomaly = []

        # ─── Check 1: Port set analysis ───────────────────────────────────
        port_set = {p["port"] for p in open_ports}
        port_score, port_anom = self._analyze_port_set(port_set)
        evidence_score += port_score
        port_anomalies.extend(port_anom)

        # ─── Check 2: Banner signature matching ───────────────────────────
        sig_score, sigs = self._check_banner_signatures(open_ports)
        evidence_score += sig_score
        matched_sigs.extend(sigs)

        # ─── Check 3: Banner timing analysis ──────────────────────────────
        timing_score, t_flags = self._analyze_banner_timing(target, open_ports)
        evidence_score += timing_score
        timing_anomaly.extend(t_flags)

        # ─── Check 4: Response entropy (banner variety) ───────────────────
        entropy_score, e_flags = self._analyze_response_entropy(target, open_ports)
        evidence_score += entropy_score
        behav_flags.extend(e_flags)

        # ─── Check 5: Garbage data reaction ───────────────────────────────
        garbage_score, g_flags = self._test_garbage_response(target, open_ports)
        evidence_score += garbage_score
        behav_flags.extend(g_flags)

        # ─── Check 6: Too-perfect service set ─────────────────────────────
        if len(open_ports) >= 15:
            evidence_score += 0.25
            port_anomalies.append(
                f"Unusually high number of open ports ({len(open_ports)}) "
                "— common in honeypot configurations"
            )

        # ─── Normalize score to 0-1 ───────────────────────────────────────
        confidence = min(evidence_score, 1.0)

        # ─── Verdict ──────────────────────────────────────────────────────
        is_honeypot, verdict = self._determine_verdict(confidence)
        recommendation       = self._build_recommendation(confidence, matched_sigs)
        risk                 = self._assess_risk(confidence)

        return HoneypotAnalysis(
            target=target,
            is_honeypot=is_honeypot,
            confidence=round(confidence, 3),
            verdict=verdict,
            matched_signatures=matched_sigs,
            behavioral_flags=behav_flags,
            port_anomalies=port_anomalies,
            timing_anomalies=timing_anomaly,
            recommendation=recommendation,
            risk_of_proceeding=risk,
        )

    # ─── Check 1: Port set ────────────────────────────────────────────────
    @staticmethod
    def _analyze_port_set(port_set: set) -> tuple:
        score     = 0.0
        anomalies = []

        for known_set in HONEYPOT_PORT_SETS:
            overlap = len(port_set & known_set) / len(known_set)
            if overlap >= 0.75:
                score = max(score, 0.30)
                anomalies.append(
                    f"Port set matches known honeypot configuration "
                    f"({overlap*100:.0f}% overlap): {sorted(port_set & known_set)}"
                )

        # بررسی باز بودن telnet + ssh + ftp به طور همزمان (خیلی مشکوک)
        if {21, 22, 23}.issubset(port_set):
            score = max(score, 0.20)
            anomalies.append(
                "FTP + SSH + Telnet all open simultaneously — "
                "high honeypot probability (no legitimate server needs all three)"
            )

        return score, anomalies

    # ─── Check 2: Banner signatures ───────────────────────────────────────
    @staticmethod
    def _check_banner_signatures(open_ports: list) -> tuple:
        score = 0.0
        found = []

        for port_data in open_ports:
            product = port_data.get("product", "")
            version = port_data.get("version", "")
            banner  = f"{product} {version}".strip()

            for sig, info in HONEYPOT_SIGNATURES.items():
                sig_lower = sig.lower()
                banner_lower = banner.lower()
                # روش ۱: substring کامل
                matched = sig_lower in banner_lower
                # روش ۲: word-level با حذف punctuation
                if not matched:
                    import re
                    sig_words = re.findall(r'[a-z0-9._-]{4,}', sig_lower)
                    matched = sig_words and all(w in banner_lower for w in sig_words[:2])
                # روش ۳: product name مستقیم
                if not matched and port_data.get("product"):
                    prod = port_data["product"].lower().replace(" ", "")
                    sig_prods = re.findall(r'[a-z][a-z0-9._-]{3,}', sig_lower)
                    matched = any(p in banner_lower or banner_lower in p for p in sig_prods[:2])
                if matched:
                    conf = info["confidence"]
                    score = max(score, conf * 0.5)
                    found.append({
                        "port":       port_data.get("port"),
                        "honeypot":   info["name"],
                        "confidence": conf,
                        "banner":     banner,
                        "note":       info["note"],
                    })

        return score, found

    # ─── Check 3: Banner timing ───────────────────────────────────────────
    def _analyze_banner_timing(self, target: str, open_ports: list) -> tuple:
        score  = 0.0
        flags  = []
        timings = []

        # فقط روی ۳ پورت اول تست می‌کنیم
        for port_data in open_ports[:3]:
            port = port_data.get("port")
            if not port:
                continue
            t = self._grab_banner_timing(target, port)
            if t is not None:
                timings.append(t)

        if len(timings) < 2:
            return score, flags

        avg_timing = statistics.mean(timings)
        std_timing = statistics.stdev(timings) if len(timings) > 1 else 0

        # honeypot‌ها اغلب با تأخیر کمتری (pre-recorded) پاسخ می‌دهند
        if avg_timing < self.BANNER_FAST_THRESHOLD:
            score += 0.15
            flags.append(
                f"Suspiciously fast banner responses (avg={avg_timing:.0f}ms) "
                "— may be pre-recorded honeypot banners"
            )

        # consistency خیلی بالا هم مشکوک است (real servers vary)
        if std_timing < 5 and len(timings) >= 3:
            score += 0.10
            flags.append(
                f"Unnaturally consistent banner timing (σ={std_timing:.1f}ms) "
                "— suggests scripted responses"
            )

        return score, flags

    @staticmethod
    def _grab_banner_timing(target: str, port: int, timeout: float = 3.0) -> Optional[float]:
        """اندازه‌گیری زمان تا دریافت اولین byte از banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            t0 = time.monotonic()
            sock.connect((target, port))
            t1 = time.monotonic()
            sock.recv(256)
            t2 = time.monotonic()
            sock.close()
            return (t2 - t0) * 1000   # ms تا دریافت اولین داده
        except Exception:
            return None

    # ─── Check 4: Response entropy ────────────────────────────────────────
    def _analyze_response_entropy(self, target: str, open_ports: list) -> tuple:
        """
        بررسی اینکه آیا banner‌های مختلف انتروپی طبیعی دارند.
        honeypot‌ها معمولاً banner‌های ثابت و قابل پیش‌بینی دارند.
        """
        score = 0.0
        flags = []
        banners = []

        for port_data in open_ports[:5]:
            port = port_data.get("port")
            if port:
                banner = self._grab_banner_bytes(target, port)
                if banner:
                    banners.append(banner)

        if len(banners) < 2:
            return score, flags

        # بررسی duplicate banners
        hashes = [hashlib.md5(b).hexdigest() for b in banners]
        if len(set(hashes)) < len(hashes):
            score += 0.20
            flags.append(
                "Identical banners detected across different ports "
                "— strong honeypot indicator"
            )

        # بررسی entropy محتوای banner
        for i, banner in enumerate(banners):
            ent = self._shannon_entropy(banner)
            if ent < 2.0 and len(banner) > 10:
                score += 0.10
                flags.append(
                    f"Low entropy banner on port "
                    f"{open_ports[i].get('port','?')} "
                    f"(H={ent:.2f}) — may be template-generated"
                )
                break   # یک مورد کافی است

        return score, flags

    @staticmethod
    def _grab_banner_bytes(target: str, port: int, max_bytes: int = 512) -> Optional[bytes]:
        """دریافت bytes اولیه banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target, port))
            data = sock.recv(max_bytes)
            sock.close()
            return data
        except Exception:
            return None

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """محاسبه Shannon entropy برای bytes"""
        if not data:
            return 0.0
        import math
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        length = len(data)
        return -sum(
            (f / length) * math.log2(f / length)
            for f in freq.values()
            if f > 0
        )

    # ─── Check 5: Garbage data response ──────────────────────────────────
    def _test_garbage_response(self, target: str, open_ports: list) -> tuple:
        """
        ارسال داده garbage و بررسی واکنش.
        real services معمولاً با خطا disconnect می‌کنند.
        honeypot‌ها اغلب garbage را record می‌کنند و disconnect می‌کنند.
        """
        score = 0.0
        flags = []

        # فقط روی پورت‌های HTTP/FTP تست می‌کنیم
        http_ports = [p for p in open_ports if p.get("service") in ("http", "https", "ftp")]
        if not http_ports:
            return score, flags

        port_data = http_ports[0]
        port = port_data.get("port")
        if not port:
            return score, flags

        garbage = b"\x00\x01\x02\x03AEGIS_PROBE\xff\xfe\n\r"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((target, port))
            sock.send(garbage)
            time.sleep(0.5)

            t0 = time.monotonic()
            try:
                response = sock.recv(512)
                response_time = (time.monotonic() - t0) * 1000
            except socket.timeout:
                response      = b""
                response_time = 3000.0
            sock.close()

            if response and len(response) > 50:
                # پاسخ مفصل به garbage مشکوک است
                score += 0.15
                flags.append(
                    f"Target responded with {len(response)} bytes to garbage probe "
                    "— may be honeypot capturing all traffic"
                )

        except Exception as e:
            logger.debug(f"[HoneypotDetector] Garbage probe: {e}")

        return score, flags

    # ─── Verdict & helpers ────────────────────────────────────────────────
    def _determine_verdict(self, confidence: float) -> tuple:
        if confidence >= self.HONEYPOT_THRESHOLD:
            return True, "LIKELY_HONEYPOT"
        if confidence >= self.SUSPICIOUS_THRESHOLD:
            return False, "SUSPICIOUS"
        if confidence >= 0.15:
            return False, "MONITOR"
        return False, "CLEAN"

    @staticmethod
    def _build_recommendation(confidence: float, signatures: list) -> str:
        if confidence >= 0.65:
            sig_names = ", ".join(s["honeypot"] for s in signatures) if signatures else "unknown"
            return (
                f"⛔ HIGH RISK: This target shows strong honeypot indicators "
                f"({sig_names}). Proceeding may expose your TTPs to the defender. "
                "Abort or use isolated VM with no attribution."
            )
        if confidence >= 0.35:
            return (
                "⚠️ CAUTION: Target shows suspicious characteristics. "
                "Minimize interaction, avoid credential-based attacks, "
                "and monitor for honeypot-specific callbacks (DNS, HTTP OOB)."
            )
        return (
            "✅ Target appears legitimate. "
            "Standard operational security precautions apply."
        )

    @staticmethod
    def _assess_risk(confidence: float) -> str:
        if confidence >= 0.65:   return "CRITICAL"
        if confidence >= 0.35:   return "HIGH"
        if confidence >= 0.15:   return "MEDIUM"
        return "LOW"

    def to_dict(self, analysis: HoneypotAnalysis) -> dict:
        return {
            "target":              analysis.target,
            "is_honeypot":         analysis.is_honeypot,
            "confidence":          analysis.confidence,
            "verdict":             analysis.verdict,
            "matched_signatures":  analysis.matched_signatures,
            "behavioral_flags":    analysis.behavioral_flags,
            "port_anomalies":      analysis.port_anomalies,
            "timing_anomalies":    analysis.timing_anomalies,
            "recommendation":      analysis.recommendation,
            "risk_of_proceeding":  analysis.risk_of_proceeding,
        }
