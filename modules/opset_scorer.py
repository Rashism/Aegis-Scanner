# aegis-scanner/modules/opset_scorer.py
"""
امتیازدهی OPSEC (Operational Security) به اسکن.

این ماژول به red teamer می‌گوید:
  - اسکن انجام‌شده چقدر قابل شناسایی است
  - چه artifact‌هایی جا گذاشته شده
  - چگونه ردپا را کمینه کند
  - چه لاگ‌هایی احتمالاً در target ثبت شده‌اند

امتیاز OPSEC: 1 (کاملاً شناسایی‌شده) تا 10 (کاملاً stealth)
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ─── Scoring weights ──────────────────────────────────────────────────────────
SCAN_LEVEL_BASE_OPSEC = {
    1: 6.0,   # Quick — تعداد کمی packet
    2: 4.5,   # Standard — متوسط
    3: 3.5,   # Aggressive — نویزی
    4: 2.0,   # Full Vuln — خیلی نویزی (vuln scripts)
    5: 7.5,   # Stealth — T2 timing
}

TIMING_OPSEC_BONUS = {
    "T0": +4.0,
    "T1": +3.0,
    "T2": +2.0,
    "T3":  0.0,
    "T4": -1.5,
    "T5": -3.0,
}

# اقداماتی که OPSEC را بهبود می‌دهند
OPSEC_IMPROVEMENTS = {
    "uses_decoys":         +1.5,
    "uses_fragmentation":  +1.0,
    "source_port_trusted": +0.5,
    "ttl_manipulation":    +0.5,
    "randomize_hosts":     +0.5,
    "version_scan_off":    +1.0,   # -sV فعال نیست
    "script_scan_off":     +1.5,   # -sC فعال نیست
}

# عواملی که OPSEC را کاهش می‌دهند
OPSEC_PENALTIES = {
    "script_scan":         -2.0,   # NSE scripts → payload‌های قابل شناسایی
    "version_intense":     -1.0,   # --version-intensity 9
    "os_detection":        -1.0,   # -O → OS fingerprint packets غیرعادی
    "aggressive":          -2.5,   # -A → همه‌چیز
    "no_evasion":          -1.5,   # بدون decoy یا fragmentation
    "insane_timing":       -3.0,   # T5
    "many_ports":          -0.5,   # -p 1-65535
    "udp_scan":            -0.5,   # UDP noisier than TCP
}


@dataclass
class OPSECLog:
    """یک artifact احتمالی که در target ثبت می‌شود"""
    log_source:   str    # syslog, IDS, firewall, web server
    log_level:    str    # INFO / WARNING / ALERT / CRITICAL
    description:  str    # چه چیزی لاگ می‌شود
    likelihood:   float  # 0-1 احتمال لاگ شدن
    can_mitigate: bool
    mitigation:   str


@dataclass
class OPSECReport:
    """گزارش کامل OPSEC"""
    session_id:     str
    target:         str
    opsec_score:    float           # 1.0 - 10.0
    opsec_grade:    str             # A+ تا F
    detection_risk: str             # LOW / MEDIUM / HIGH / CRITICAL
    likely_logs:    list            # لیست OPSECLog
    artifacts:      list            # آنچه در target جا ماند
    improvements:   list            # پیشنهادات بهبود
    critical_issues: list           # مشکلات فوری
    stealth_command: str            # stealth‌ترین دستور جایگزین
    analysis:       str             # تحلیل کامل متنی


class OPSECScorer:
    """
    تحلیل OPSEC اسکن Aegis-Scanner.

    به red teamer می‌گوید دقیقاً چه دیده می‌شود
    و چگونه ردپا را کمینه کند.
    """

    def score(
        self,
        session_id:     str,
        target:         str,
        scan_args:      str,
        scan_level:     int,
        evasion_profile: Optional[dict] = None,
        rtt_ms:         float = 100.0,
        open_ports_count: int = 0,
        vuln_scripts_run: bool = False,
    ) -> OPSECReport:
        """
        محاسبه امتیاز OPSEC و تولید گزارش کامل.
        """
        # Base score از scan level
        score = SCAN_LEVEL_BASE_OPSEC.get(scan_level, 4.0)

        improvements = []
        critical_issues = []
        artifacts       = []

        # ─── Timing bonus/penalty ─────────────────────────────────────────
        timing = self._extract_timing(scan_args, evasion_profile)
        timing_delta = TIMING_OPSEC_BONUS.get(timing, 0.0)
        score += timing_delta
        if timing_delta > 0:
            improvements.append(f"Good timing template ({timing}): +{timing_delta}")

        # ─── Evasion techniques ───────────────────────────────────────────
        if evasion_profile:
            if evasion_profile.get("recommended_decoys"):
                score += OPSEC_IMPROVEMENTS["uses_decoys"]
                improvements.append("Decoy IPs in use: attribution difficult")
            if evasion_profile.get("recommended_mtu", 1500) < 1500:
                score += OPSEC_IMPROVEMENTS["uses_fragmentation"]
                improvements.append("Packet fragmentation: IDS signature evasion")
            if evasion_profile.get("source_port"):
                score += OPSEC_IMPROVEMENTS["source_port_trusted"]
                improvements.append(f"Trusted source port ({evasion_profile['source_port']})")
        else:
            score += OPSEC_PENALTIES["no_evasion"]
            critical_issues.append(
                "No evasion techniques applied — scan is easily attributable"
            )

        # ─── Scan args analysis ───────────────────────────────────────────
        args_lower = scan_args.lower()

        if "-sc" in args_lower or "--script" in args_lower:
            score += OPSEC_PENALTIES["script_scan"]
            artifacts.append(
                "NSE script payloads sent to target — "
                "logged in web server/IDS with User-Agent and paths"
            )
            if "vuln" in args_lower:
                critical_issues.append(
                    "Vulnerability scripts (-script vuln) sent detectable payloads "
                    "including SQLi probes, exploit headers, and fuzzing — "
                    "IDS will alert, SOC will investigate"
                )

        if "-sv" in args_lower or "-sv" in scan_args:
            score += OPSEC_PENALTIES["version_intense"]
            artifacts.append(
                "Service version detection sent protocol-specific probes — "
                "banner grab attempts logged in service logs"
            )

        if "-o " in args_lower or "-a" in args_lower:
            score += OPSEC_PENALTIES["os_detection"]
            artifacts.append(
                "OS detection sent malformed/unusual TCP packets — "
                "detectable by modern IDS (Snort/Suricata rule: POLICY nmap)"
            )

        if "-a" in args_lower and len(scan_args) < 10:
            score += OPSEC_PENALTIES["aggressive"]
            critical_issues.append(
                "-A flag combines OS detection, version scan, scripts, and traceroute — "
                "maximum noise, guaranteed detection by any IDS"
            )

        if "t5" in args_lower:
            score += OPSEC_PENALTIES["insane_timing"]
            critical_issues.append(
                "T5 (insane) timing: extremely high packet rate — "
                "triggers port scan detection in every modern firewall/IDS"
            )

        if "p-" in scan_args or "p 1-65535" in scan_args:
            score += OPSEC_PENALTIES["many_ports"]
            artifacts.append(
                "Full port scan (all 65535 ports) — "
                "creates massive firewall log entries, easily detected"
            )

        if "-su" in args_lower:
            score += OPSEC_PENALTIES["udp_scan"]
            artifacts.append(
                "UDP scan generated ICMP unreachable responses — "
                "detectable in firewall/network logs"
            )

        # ─── Likely logs ─────────────────────────────────────────────────
        likely_logs = self._estimate_logs(scan_level, scan_args, evasion_profile)

        # ─── Clamp score ─────────────────────────────────────────────────
        score = round(min(max(score, 1.0), 10.0), 1)

        # ─── Grade + risk ─────────────────────────────────────────────────
        grade          = self._score_to_grade(score)
        detection_risk = self._score_to_risk(score)

        # ─── Stealth command suggestion ───────────────────────────────────
        stealth_cmd = self._build_stealth_command(target, rtt_ms, scan_level)

        # ─── Improvements ────────────────────────────────────────────────
        if not any("decoy" in i.lower() for i in improvements):
            improvements.append(
                "Add decoys: -D RND:10 to mix your IP with random sources"
            )
        if timing in ("T3", "T4", "T5"):
            improvements.append(
                f"Reduce timing to T1 or T2 for significant OPSEC improvement"
            )
        if "-sc" in args_lower:
            improvements.append(
                "Remove NSE scripts for initial scan; run targeted scripts only after IA"
            )

        analysis = self._write_analysis(
            score, grade, detection_risk,
            scan_level, artifacts, critical_issues
        )

        return OPSECReport(
            session_id=session_id,
            target=target,
            opsec_score=score,
            opsec_grade=grade,
            detection_risk=detection_risk,
            likely_logs=likely_logs,
            artifacts=artifacts,
            improvements=improvements,
            critical_issues=critical_issues,
            stealth_command=stealth_cmd,
            analysis=analysis,
        )

    # ─── Helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _extract_timing(scan_args: str, evasion: Optional[dict]) -> str:
        if evasion and evasion.get("recommended_timing"):
            return evasion["recommended_timing"]
        import re
        match = re.search(r"-T(\d)", scan_args)
        if match:
            return f"T{match.group(1)}"
        return "T3"

    @staticmethod
    def _estimate_logs(
        scan_level: int, scan_args: str, evasion: Optional[dict]
    ) -> list:
        """تخمین لاگ‌هایی که در target ثبت می‌شوند"""
        logs = []
        has_evasion = bool(evasion and evasion.get("recommended_decoys"))

        # firewall logs همیشه هستند
        logs.append({
            "source":      "Firewall / iptables",
            "level":       "INFO",
            "description": "SYN packets to scanned ports logged with source IP",
            "likelihood":  0.95,
            "mitigation":  "Use decoys (-D) and VPN/proxy chain",
        })

        # syslog
        if scan_level >= 3:
            logs.append({
                "source":      "syslog / auth.log",
                "level":       "WARNING",
                "description": "Multiple connection attempts — may trigger fail2ban",
                "likelihood":  0.75,
                "mitigation":  "Use T1 timing and limit scan scope",
            })

        # IDS
        if scan_level >= 2:
            logs.append({
                "source":      "IDS (Snort/Suricata)",
                "level":       "ALERT",
                "description": "Nmap port scan signature detected (ET SCAN NMAP)",
                "likelihood":  0.80 if not has_evasion else 0.35,
                "mitigation":  "Fragment packets (--mtu 8) + timing T1",
            })

        # web server
        if "-sc" in scan_args.lower() or "--script" in scan_args.lower():
            logs.append({
                "source":      "Web server access log (Apache/Nginx)",
                "level":       "WARNING",
                "description": "NSE script HTTP requests logged with Nmap User-Agent",
                "likelihood":  0.99,
                "mitigation":  "Use --script-args http.useragent='Mozilla/5.0' or avoid web scripts",
            })

        # SIEM correlation
        if scan_level >= 4:
            logs.append({
                "source":      "SIEM (Splunk/ELK)",
                "level":       "CRITICAL",
                "description": (
                    "Correlation rule triggered: port scan + vuln probe + "
                    "multiple failed connections = likely pentest/attack"
                ),
                "likelihood":  0.90,
                "mitigation":  "Split scan into phases over multiple days",
            })

        return logs

    @staticmethod
    def _score_to_grade(score: float) -> str:
        if score >= 9.0:  return "A+"
        if score >= 8.0:  return "A"
        if score >= 7.0:  return "B"
        if score >= 6.0:  return "C"
        if score >= 4.0:  return "D"
        if score >= 2.0:  return "E"
        return "F"

    @staticmethod
    def _score_to_risk(score: float) -> str:
        if score >= 8.0:  return "LOW"
        if score >= 6.0:  return "MEDIUM"
        if score >= 3.0:  return "HIGH"
        return "CRITICAL"

    @staticmethod
    def _build_stealth_command(target: str, rtt_ms: float, scan_level: int) -> str:
        """بهترین دستور Nmap برای حداکثر stealth"""
        timing = "T1" if rtt_ms < 200 else "T0"
        return (
            f"nmap -sS {timing} --mtu 8 -D RND:15,ME "
            f"--source-port 53 --randomize-hosts "
            f"--max-retries 1 --min-rate 5 "
            f"-sV --version-intensity 2 "
            f"-F {target}"   # -F = top 100 ports for initial stealth recon
        )

    @staticmethod
    def _write_analysis(
        score: float, grade: str, risk: str,
        level: int, artifacts: list, issues: list
    ) -> str:
        lines = [
            f"OPSEC Score: {score}/10 (Grade {grade}) — Detection Risk: {risk}",
            "",
            f"This scan (level {level}) generated approximately "
            f"{len(artifacts)} detectable artifact(s) on the target system.",
        ]
        if issues:
            lines.append(
                f"\nCritical issues found: {len(issues)} — "
                "immediate attention required before proceeding."
            )
        if risk in ("CRITICAL", "HIGH"):
            lines.append(
                "\nRecommendation: Abort current scan methodology. "
                "Use the provided stealth command and introduce "
                "48-72 hour delays between scan phases."
            )
        return "\n".join(lines)

    def to_dict(self, report: OPSECReport) -> dict:
        return {
            "session_id":     report.session_id,
            "target":         report.target,
            "opsec_score":    report.opsec_score,
            "opsec_grade":    report.opsec_grade,
            "detection_risk": report.detection_risk,
            "likely_logs":    report.likely_logs,
            "artifacts":      report.artifacts,
            "improvements":   report.improvements,
            "critical_issues":report.critical_issues,
            "stealth_command":report.stealth_command,
            "analysis":       report.analysis,
        }
