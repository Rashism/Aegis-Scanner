# aegis-scanner/modules/stealth_advisor.py
"""
Stealth Scoring & IDS Evasion Advisor — Aegis-Scanner v4
=========================================================
بعد از هر اسکن جواب می‌دهد:
  "آیا احتمالاً detect شدم؟"
  "دفعه بعد چطور invisible‌تر باشم؟"
"""

import logging
import math
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class StealthScore:
    score:              float        # 0-100 (100=کاملاً مخفی)
    detection_risk:     str          # LOW / MEDIUM / HIGH / CRITICAL
    estimated_detected: bool
    confidence:         float        # اطمینان از ارزیابی

    # عوامل کسر امتیاز
    deductions:         list = field(default_factory=list)

    # توصیه‌های بهبود
    recommendations:    list = field(default_factory=list)

    # دستور Nmap بهتر برای دفعه بعد
    better_command:     str  = ""

    # خلاصه
    summary:            str  = ""


class StealthAdvisor:
    """
    تحلیل‌گر stealth — از داده‌های session یک امتیاز و توصیه می‌سازد.
    """

    # آستانه‌های امتیاز
    THRESHOLDS = {
        "LOW":      80,
        "MEDIUM":   55,
        "HIGH":     30,
    }

    def analyze(self, session) -> StealthScore:
        """
        تحلیل کامل یک scan session و تولید stealth score.
        """
        score       = 100.0
        deductions  = []
        recs        = []

        scan    = session.scan_result
        evasion = session.evasion_profile or {}
        opsec   = session.opsec_report or {}
        rt      = session.realtime_analysis or {}
        rtt     = (scan.rtt_ms if scan else 0) or 0
        level   = session.scan_level

        # ── Factor 1: Scan level ─────────────────────────────────────────
        level_penalty = {1: 0, 2: 5, 3: 15, 4: 25, 5: 10}
        pen = level_penalty.get(level, 10)
        if pen:
            score -= pen
            deductions.append({
                "factor": f"Scan Level {level}",
                "penalty": pen,
                "detail": f"Level {level} scans generate {'high' if level == 4 else 'moderate'} network noise",
            })

        # ── Factor 2: NSE scripts ────────────────────────────────────────
        if scan and "--script=" in (scan.scan_args or ""):
            args = scan.scan_args
            script_count = args.count(",") + 1 if "--script=" in args else 0
            if script_count > 20:
                score -= 20
                deductions.append({
                    "factor": "Heavy NSE Script Load",
                    "penalty": 20,
                    "detail": f"{script_count} scripts create anomalous traffic patterns",
                })
            elif script_count > 5:
                score -= 10
                deductions.append({
                    "factor": "Multiple NSE Scripts",
                    "penalty": 10,
                    "detail": f"{script_count} scripts may trigger IDS signatures",
                })

        # ── Factor 3: Timing ─────────────────────────────────────────────
        if scan and scan.scan_args:
            args = scan.scan_args
            if "-T4" in args or "-T5" in args:
                score -= 20
                deductions.append({
                    "factor": "Aggressive Timing (T4/T5)",
                    "penalty": 20,
                    "detail": "Fast scans create burst traffic — easily detected by IDS",
                })
                recs.append({
                    "priority": "HIGH",
                    "action": "Use -T1 or -T2 timing",
                    "detail": "Slow scan rate blends with normal traffic",
                })
            elif "-T3" in args:
                score -= 5
                deductions.append({
                    "factor": "Normal Timing (T3)",
                    "penalty": 5,
                    "detail": "Default timing is recognizable as a port scan",
                })

        # ── Factor 4: Firewall/IDS detected ─────────────────────────────
        if evasion.get("firewall_detected"):
            score -= 5
            deductions.append({
                "factor": "Firewall Detected",
                "penalty": 5,
                "detail": "Firewall logs all connection attempts including scan traffic",
            })
            recs.append({
                "priority": "HIGH",
                "action": "Use --mtu 24 for packet fragmentation",
                "detail": "Fragments may bypass stateless firewall inspection",
            })

        if evasion.get("ids_detected"):
            score -= 25
            deductions.append({
                "factor": "IDS Detected",
                "penalty": 25,
                "detail": "Active IDS will likely alert on scan activity",
            })
            recs.append({
                "priority": "CRITICAL",
                "action": "Use -T0 timing + --randomize-hosts + --data-length 25",
                "detail": "Maximum stealth configuration against active IDS",
            })

        # ── Factor 5: Middlebox ──────────────────────────────────────────
        bh = rt.get("behavior", {})
        if bh.get("middlebox_detected"):
            score -= 10
            deductions.append({
                "factor": "Middlebox/DPI Detected",
                "penalty": 10,
                "detail": "Deep packet inspection may log or block scan traffic",
            })
            recs.append({
                "priority": "HIGH",
                "action": "Use --source-port 443 or --source-port 80",
                "detail": "Spoofing common source ports may bypass middlebox filtering",
            })

        # ── Factor 6: RST injections ─────────────────────────────────────
        rst = bh.get("rst_injections", 0)
        if rst > 0:
            pen2 = min(rst * 5, 20)
            score -= pen2
            deductions.append({
                "factor": f"RST Injections ({rst})",
                "penalty": pen2,
                "detail": "RST packets indicate active network monitoring",
            })

        # ── Factor 7: MTU / fragmentation ───────────────────────────────
        if scan and "--mtu" not in (scan.scan_args or ""):
            score -= 3
            recs.append({
                "priority": "MEDIUM",
                "action": "Add --mtu 24",
                "detail": "Packet fragmentation avoids some signature-based detection",
            })

        # ── Factor 8: Decoys ─────────────────────────────────────────────
        if scan and "-D" not in (scan.scan_args or "") and "--decoys" not in (scan.scan_args or ""):
            recs.append({
                "priority": "MEDIUM",
                "action": "Add -D RND:5",
                "detail": "5 random decoys obscure the real source IP",
            })

        # ── Factor 9: Scan duration ──────────────────────────────────────
        dur = session.duration
        if dur < 5:
            score -= 10
            deductions.append({
                "factor": "Very Fast Scan (<5s)",
                "penalty": 10,
                "detail": "Extremely fast scans are unnatural and easily fingerprinted",
            })

        # ── Factor 10: Port range ────────────────────────────────────────
        if session.ports == "1-65535" or "-p-" in (scan.scan_args or ""):
            score -= 15
            deductions.append({
                "factor": "Full Port Range",
                "penalty": 15,
                "detail": "Scanning all 65535 ports is the most obvious scan pattern",
            })
            recs.append({
                "priority": "MEDIUM",
                "action": "Split scans: top 1000 ports first, then targeted deeper scans",
                "detail": "Incremental scanning is less detectable than full-range",
            })

        # ── Clamp score ──────────────────────────────────────────────────
        score = max(0.0, min(100.0, score))

        # ── Detection risk ───────────────────────────────────────────────
        if score >= self.THRESHOLDS["LOW"]:
            risk = "LOW"
        elif score >= self.THRESHOLDS["MEDIUM"]:
            risk = "MEDIUM"
        elif score >= self.THRESHOLDS["HIGH"]:
            risk = "HIGH"
        else:
            risk = "CRITICAL"

        estimated_detected = score < 50
        confidence = self._estimate_confidence(evasion, rt, rst)

        # ── Build better command ─────────────────────────────────────────
        better_cmd = self._build_better_command(
            session, evasion, bh, risk
        )

        # ── Summary ──────────────────────────────────────────────────────
        summary = self._build_summary(score, risk, estimated_detected, deductions)

        # مرتب‌سازی توصیه‌ها بر اساس priority
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        recs.sort(key=lambda r: priority_order.get(r.get("priority", "LOW"), 3))

        return StealthScore(
            score=round(score, 1),
            detection_risk=risk,
            estimated_detected=estimated_detected,
            confidence=round(confidence, 2),
            deductions=deductions,
            recommendations=recs,
            better_command=better_cmd,
            summary=summary,
        )

    def _build_better_command(
        self, session, evasion: dict, behavior: dict, risk: str
    ) -> str:
        target = session.target
        ports  = session.ports
        level  = session.scan_level

        # Base args بر اساس level
        base = "-sS -sV" if level >= 3 else "-sV"

        # Timing بر اساس risk
        timing = {
            "CRITICAL": "-T0",
            "HIGH":     "-T1",
            "MEDIUM":   "-T2",
            "LOW":      "-T3",
        }.get(risk, "-T2")

        extras = []
        if evasion.get("firewall_detected"):
            extras.append("--mtu 24")
        if evasion.get("ids_detected"):
            extras.append("--randomize-hosts")
            extras.append("--data-length 25")
        if behavior.get("middlebox_detected"):
            extras.append("--source-port 443")

        extras.append("-D RND:5")
        extras.append("--max-retries 2")

        extra_str = " ".join(extras)
        return f"nmap {base} {timing} {extra_str} -p {ports} {target}"

    @staticmethod
    def _estimate_confidence(evasion: dict, rt: dict, rst_count: int) -> float:
        """اطمینان از ارزیابی"""
        confidence = 0.5
        if evasion:
            confidence += 0.2
        if rt.get("behavior"):
            confidence += 0.2
        if rst_count > 0:
            confidence += 0.1
        return min(confidence, 0.95)

    @staticmethod
    def _build_summary(
        score: float, risk: str,
        detected: bool, deductions: list
    ) -> str:
        parts = []
        if detected:
            parts.append(f"Stealth score: {score:.0f}/100 — اسکن احتمالاً detect شد.")
        else:
            parts.append(f"Stealth score: {score:.0f}/100 — اسکن نسبتاً مخفی بود.")

        if deductions:
            worst = max(deductions, key=lambda d: d.get("penalty", 0))
            parts.append(
                f"بزرگ‌ترین ریسک: {worst['factor']} (-{worst['penalty']} امتیاز)."
            )

        risk_msg = {
            "LOW":      "خطر شناسایی: پایین.",
            "MEDIUM":   "خطر شناسایی: متوسط — توصیه می‌شود evasion بهبود یابد.",
            "HIGH":     "خطر شناسایی: بالا — اسکن احتمالاً log شده.",
            "CRITICAL": "خطر شناسایی: بحرانی — اسکن قطعاً شناسایی شده.",
        }.get(risk, "")
        parts.append(risk_msg)
        return " ".join(parts)

    def to_dict(self, score: StealthScore) -> dict:
        return asdict(score)
