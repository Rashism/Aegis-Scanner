# aegis-scanner/intelligence/knowledge_base.py
"""
پایگاه دانش محلی برای یادگیری مستمر Aegis-Scanner.
نتایج اسکن‌های موفق ذخیره و برای بهبود پیشنهادات آینده استفاده می‌شوند.
"""

import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from config.constants import KB_FILE, SCAN_HISTORY_FILE

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """
    پایگاه دانش ساده مبتنی بر JSON.
    
    ساختار:
    - patterns: الگوهای موفق (target_profile → best_scan_args)
    - service_insights: بینش‌های سرویس (service_name → known_issues)
    - scan_history: تاریخچه اسکن‌ها برای گزارش‌دهی
    """

    MAX_HISTORY_ENTRIES = 500     # حداکثر تعداد رکورد نگهداری

    def __init__(
        self,
        kb_file: str = KB_FILE,
        history_file: str = SCAN_HISTORY_FILE
    ):
        self.kb_path      = Path(kb_file)
        self.history_path = Path(history_file)
        self.kb_path.parent.mkdir(parents=True, exist_ok=True)

        self._kb      = self._load(self.kb_path, default={
            "patterns": {}, "service_insights": {}, "meta": {}
        })
        self._history = self._load(self.history_path, default={"scans": []})

    # ─── I/O ──────────────────────────────────────────────────────────────
    @staticmethod
    def _load(path: Path, default: dict) -> dict:
        if path.exists():
            try:
                with open(path) as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"[KB] Load error {path}: {e}")
        return default

    def _save_kb(self) -> None:
        try:
            with open(self.kb_path, "w") as f:
                json.dump(self._kb, f, indent=2)
        except Exception as e:
            logger.error(f"[KB] Save error: {e}")

    def _save_history(self) -> None:
        try:
            with open(self.history_path, "w") as f:
                json.dump(self._history, f, indent=2)
        except Exception as e:
            logger.error(f"[KB] History save error: {e}")

    # ─── Session save ─────────────────────────────────────────────────────
    def save_session(self, session) -> None:
        """ذخیره نتایج یک scan session در knowledge base"""
        try:
            self._update_patterns(session)
            self._update_service_insights(session)
            self._append_history(session)
            self._save_kb()
            self._save_history()
            logger.info(f"[KB] Session {session.session_id} saved to knowledge base")
        except Exception as e:
            logger.error(f"[KB] Failed to save session: {e}")

    def _update_patterns(self, session) -> None:
        """بروزرسانی الگوهای موفق اسکن"""
        if not session.scan_result or not session.scan_result.success:
            return

        # کلید: profile شبکه بر اساس RTT bucket
        rtt = session.scan_result.rtt_ms
        rtt_bucket = (
            "fast"   if rtt < 50 else
            "medium" if rtt < 200 else
            "slow"
        )
        profile_key = f"rtt_{rtt_bucket}_level_{session.scan_level}"

        existing = self._kb["patterns"].get(profile_key, {})
        existing.update({
            "best_args":     session.scan_result.scan_args,
            "timing":        session.optimized_params.get("timing", "T3") if session.optimized_params else "T3",
            "mtu":           session.optimized_params.get("mtu", 1500) if session.optimized_params else 1500,
            "success_count": existing.get("success_count", 0) + 1,
            "last_used":     datetime.now().isoformat(),
        })
        self._kb["patterns"][profile_key] = existing

    def _update_service_insights(self, session) -> None:
        """بروزرسانی بینش‌های سرویس"""
        if not session.vulnerabilities:
            return

        for vuln in session.vulnerabilities:
            service = vuln.get("service", "unknown")
            cve_id  = vuln.get("cve_id", "")
            if not service or not cve_id:
                continue

            svc_data = self._kb["service_insights"].get(service, {
                "known_cves": [], "occurrence_count": 0
            })

            if cve_id not in svc_data["known_cves"]:
                svc_data["known_cves"].append(cve_id)
            svc_data["occurrence_count"] += 1
            svc_data["last_seen"] = datetime.now().isoformat()

            self._kb["service_insights"][service] = svc_data

    def _append_history(self, session) -> None:
        """اضافه کردن خلاصه session به تاریخچه"""
        entry = {
            "session_id":   session.session_id,
            "timestamp":    datetime.now().isoformat(),
            "target":       session.target,
            "ports":        session.ports,
            "scan_level":   session.scan_level,
            "hosts_up":     session.scan_result.hosts_up if session.scan_result else 0,
            "open_ports":   len(session.scan_result.open_ports) if session.scan_result else 0,
            "vulns_found":  len(session.vulnerabilities) if session.vulnerabilities else 0,
            "duration":     round(session.duration, 1),
            "had_errors":   bool(session.errors),
            "reports":      session.report_paths,
        }

        scans = self._history.get("scans", [])
        scans.insert(0, entry)   # جدیدترین اول

        # حفظ حداکثر تعداد رکورد
        if len(scans) > self.MAX_HISTORY_ENTRIES:
            scans = scans[:self.MAX_HISTORY_ENTRIES]

        self._history["scans"] = scans

    # ─── Retrieval ─────────────────────────────────────────────────────────
    def get_best_args_for_profile(self, rtt_ms: float, scan_level: int) -> Optional[str]:
        """بازیابی بهترین args برای یک شرایط شبکه"""
        rtt_bucket = (
            "fast"   if rtt_ms < 50 else
            "medium" if rtt_ms < 200 else
            "slow"
        )
        profile_key = f"rtt_{rtt_bucket}_level_{scan_level}"
        pattern = self._kb["patterns"].get(profile_key)
        if pattern and pattern.get("success_count", 0) >= 3:
            return pattern.get("best_args")
        return None

    def get_known_cves_for_service(self, service: str) -> list:
        """لیست CVE‌های شناخته‌شده برای یک سرویس"""
        return self._kb["service_insights"].get(service, {}).get("known_cves", [])

    def get_recent_scans(self, limit: int = 10) -> list:
        """دریافت آخرین scan‌ها"""
        return self._history.get("scans", [])[:limit]

    def is_healthy(self) -> bool:
        """بررسی سلامت knowledge base"""
        return bool(self._kb) and bool(self._history)

    def get_stats(self) -> dict:
        """آمار کلی knowledge base"""
        return {
            "total_scans":      len(self._history.get("scans", [])),
            "known_patterns":   len(self._kb.get("patterns", {})),
            "service_profiles": len(self._kb.get("service_insights", {})),
        }
