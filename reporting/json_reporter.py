# aegis-scanner/reporting/json_reporter.py
"""
تولید گزارش JSON ساختارمند از نتایج اسکن.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from config.settings import ReportSettings
from config.constants import PROJECT_NAME, VERSION

logger = logging.getLogger(__name__)


class JSONReporter:
    def __init__(self, settings: ReportSettings):
        self.settings = settings
        Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    def generate(self, session) -> str:
        """تولید فایل JSON و برگرداندن مسیر فایل"""
        report = self._build_report(session)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = session.target.replace("/", "_").replace(".", "-")
        filename = f"aegis_{target_safe}_{timestamp}.json"
        filepath = Path(self.settings.output_dir) / filename

        try:
            with open(filepath, "w") as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"[JSONReporter] Report saved: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"[JSONReporter] Failed to save: {e}")
            return ""

    def _build_report(self, session) -> dict:
        scan = session.scan_result

        report = {
            "meta": {
                "tool":             PROJECT_NAME,
                "version":          VERSION,
                "session_id":       session.session_id,
                "generated":        datetime.now().isoformat(),
                "duration_s":       round(session.duration, 1),
                "phases_completed": getattr(session, "phases_completed", []),
            },
            "target": {
                "address":    session.target,
                "ports":      session.ports,
                "scan_level": session.scan_level,
            },
            "scan": {
                "args":            scan.scan_args if scan else "",
                "hosts_up":        scan.hosts_up if scan else 0,
                "hosts_down":      scan.hosts_down if scan else 0,
                "open_ports":      scan.open_ports if scan else [],
                "rtt_ms":          scan.rtt_ms if scan else 0,
                "packet_loss_pct": scan.packet_loss_pct if scan else 0,
                "duration_s":      round(scan.duration_seconds, 1) if scan else 0,
            },
            # ─── Base modules ──────────────────────────────────────────
            "network_optimization": session.optimized_params or {},
            "port_analysis":        session.port_analysis or {},
            "vulnerabilities":      session.vulnerabilities or [],
            "exploit_suggestions":  session.exploit_suggestions or [],
            "ai_analysis":          session.ai_analysis or {},
            "next_best_action":     session.next_best_action or {},
            # ─── Advanced Red Team modules ─────────────────────────────
            "honeypot_analysis":    getattr(session, "honeypot_analysis", None) or {},
            "evasion_profile":      getattr(session, "evasion_profile", None) or {},
            "protocol_inspection":  getattr(session, "protocol_inspection", None) or {},
            "attack_chain":         getattr(session, "attack_chain", None) or {},
            "opsec_report":         getattr(session, "opsec_report", None) or {},
            "lateral_movement":     getattr(session, "lateral_movement", None) or {},
            # ─── v3 modules ──────────────────────────────────────────
            "realtime_analysis":    getattr(session, "realtime_analysis", None) or {},
            "osint_data":           getattr(session, "osint_data", None) or {},
            "ai_triage":            getattr(session, "ai_triage", None) or {},
            # ─── v4 modules ──────────────────────────────────────────────
            "intelligence":         getattr(session, "intelligence", None) or {},
            "auto_recon":           getattr(session, "auto_recon", None) or {},
            "stealth_score":        getattr(session, "stealth_score", None) or {},
            # ─── Meta ──────────────────────────────────────────────────
            "errors": session.errors,
        }

        if self.settings.include_raw_nmap and scan:
            report["raw_nmap"] = scan.raw_data

        return report
