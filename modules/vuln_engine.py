# aegis-scanner/modules/vuln_engine.py
"""
موتور آسیب‌پذیری: نگاشت CPE → CVE از طریق NVD API.
فقط از داده‌های واقعی NVD استفاده می‌کند، هرگز CVE مصنوعی تولید نمی‌کند.
"""

import os
import json
import time
import logging
import hashlib
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

from config.constants import (
    NVD_API_BASE, NVD_API_KEY_ENV, NVD_RESULTS_PER_PAGE,
    NVD_CACHE_TTL_HOURS, CVSS_CRITICAL, CVSS_HIGH, CVSS_MEDIUM, CVSS_LOW,
    CVE_CACHE_FILE
)

logger = logging.getLogger(__name__)


class CVECache:
    """کش لوکال برای کاهش درخواست‌های API به NVD"""

    def __init__(self, cache_file: str = CVE_CACHE_FILE):
        self.cache_file = Path(cache_file)
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict = self._load()

    def _load(self) -> dict:
        if self.cache_file.exists():
            try:
                with open(self.cache_file) as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save(self) -> None:
        try:
            with open(self.cache_file, "w") as f:
                json.dump(self._data, f, indent=2)
        except Exception as e:
            logger.warning(f"[CVECache] Save failed: {e}")

    def _key(self, query: str) -> str:
        return hashlib.md5(query.encode()).hexdigest()

    def get(self, query: str) -> Optional[list]:
        k = self._key(query)
        entry = self._data.get(k)
        if not entry:
            return None
        # بررسی TTL
        cached_at = datetime.fromisoformat(entry["cached_at"])
        if datetime.now() - cached_at > timedelta(hours=NVD_CACHE_TTL_HOURS):
            del self._data[k]
            return None
        return entry["cves"]

    def set(self, query: str, cves: list) -> None:
        k = self._key(query)
        self._data[k] = {
            "cached_at": datetime.now().isoformat(),
            "query": query,
            "cves": cves,
        }
        self._save()


class VulnEngine:
    """
    موتور آسیب‌پذیری با اتصال به NVD API 2.0.
    
    pipeline:
    CPE از Nmap → NVD API → CVE list → CVSS scoring → sorted findings
    
    بدون API key: 5 req/30sec
    با API key:  50 req/30sec
    """

    NVD_RATE_LIMIT_DELAY = 6.0      # ثانیه بین درخواست‌ها (بدون API key)
    NVD_RATE_LIMIT_WITH_KEY = 0.6   # با API key

    def __init__(self):
        self.api_key   = os.getenv(NVD_API_KEY_ENV)
        self.cache     = CVECache()
        self._last_req = 0.0
        if self.api_key:
            logger.info("[VulnEngine] NVD API key found — higher rate limit active")
        else:
            logger.info("[VulnEngine] No NVD API key — using conservative rate limit")

    # ─── Main entry point ──────────────────────────────────────────────────
    def map_vulnerabilities(self, open_ports: list) -> list:
        """
        نگاشت تمام پورت‌های باز به CVE‌های مرتبط.
        
        Args:
            open_ports: لیست dict از NmapController
        Returns:
            list از vulnerability dict‌ها، مرتب‌شده بر اساس CVSS
        """
        all_vulns = []

        for port_data in open_ports:
            cpe     = port_data.get("cpe", "")
            product = port_data.get("product", "")
            version = port_data.get("version", "")
            service = port_data.get("service", "")

            cves = []

            # روش 1: CPE مستقیم (دقیق‌ترین روش)
            if cpe:
                cves = self._query_by_cpe(cpe)

            # روش 2: keyword search (اگر CPE موجود نبود یا نتیجه‌ای نداشت)
            if not cves and product and version:
                keyword = f"{product} {version}".strip()
                cves = self._query_by_keyword(keyword)

            # روش 3: فقط service name
            if not cves and service and service not in ("tcpwrapped", "unknown"):
                cves = self._query_by_keyword(service)

            for cve in cves:
                all_vulns.append({
                    "host":       port_data.get("host", ""),
                    "port":       port_data.get("port", 0),
                    "service":    service,
                    "product":    product,
                    "version":    version,
                    "cpe":        cpe,
                    **cve
                })

        # مرتب‌سازی بر اساس CVSS score (نزولی)
        all_vulns.sort(key=lambda v: v.get("cvss_score", 0), reverse=True)
        return all_vulns

    # ─── NVD API queries ──────────────────────────────────────────────────
    def _query_by_cpe(self, cpe: str) -> list:
        """جستجو در NVD بر اساس CPE دقیق"""
        cached = self.cache.get(f"cpe:{cpe}")
        if cached is not None:
            logger.debug(f"[VulnEngine] Cache hit: {cpe}")
            return cached

        self._rate_limit()
        params = {
            "cpeName": cpe,
            "resultsPerPage": NVD_RESULTS_PER_PAGE,
        }
        result = self._api_request(params)
        self.cache.set(f"cpe:{cpe}", result)
        return result

    def _query_by_keyword(self, keyword: str) -> list:
        """جستجو در NVD بر اساس keyword"""
        cached = self.cache.get(f"kw:{keyword}")
        if cached is not None:
            return cached

        self._rate_limit()
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": NVD_RESULTS_PER_PAGE,
        }
        result = self._api_request(params)
        self.cache.set(f"kw:{keyword}", result)
        return result

    def _api_request(self, params: dict) -> list:
        """درخواست به NVD API با مدیریت خطا"""
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            resp = requests.get(
                NVD_API_BASE, params=params,
                headers=headers, timeout=15
            )
            if resp.status_code == 403:
                logger.warning("[VulnEngine] NVD rate limit hit, backing off 30s")
                time.sleep(30)
                return []
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            data = resp.json()
            return self._parse_nvd_response(data)

        except requests.Timeout:
            logger.warning("[VulnEngine] NVD API timeout")
            return []
        except requests.RequestException as e:
            logger.error(f"[VulnEngine] NVD API error: {e}")
            return []

    # ─── Rate limiting ─────────────────────────────────────────────────────
    def _rate_limit(self) -> None:
        """رعایت rate limit NVD API"""
        delay = self.NVD_RATE_LIMIT_WITH_KEY if self.api_key else self.NVD_RATE_LIMIT_DELAY
        elapsed = time.time() - self._last_req
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_req = time.time()

    # ─── Response parsing ──────────────────────────────────────────────────
    @staticmethod
    def _parse_nvd_response(data: dict) -> list:
        """تبدیل پاسخ JSON خام NVD به لیست CVE ساختارمند"""
        vulnerabilities = data.get("vulnerabilities", [])
        result = []

        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "UNKNOWN")

            # توضیحات (انگلیسی اول)
            descriptions = cve_data.get("descriptions", [])
            description  = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available"
            )

            # CVSS scoring (نسخه 3.1 ترجیح داده می‌شود، fallback به 2.0)
            cvss_score, cvss_vector, cvss_version = VulnEngine._extract_cvss(cve_data)
            severity = VulnEngine._score_to_severity(cvss_score)

            # تاریخ انتشار
            published = cve_data.get("published", "")[:10]   # فقط تاریخ

            # وضعیت patch
            weaknesses = [
                w.get("description", [{}])[0].get("value", "")
                for w in cve_data.get("weaknesses", [])
                if w.get("description")
            ]

            # منابع
            references = [
                r.get("url", "")
                for r in cve_data.get("references", [])[:3]  # max 3 ref
            ]

            result.append({
                "cve_id":       cve_id,
                "description":  description[:500],   # truncate برای خوانایی
                "cvss_score":   cvss_score,
                "cvss_vector":  cvss_vector,
                "cvss_version": cvss_version,
                "severity":     severity,
                "published":    published,
                "weaknesses":   weaknesses,
                "references":   references,
            })

        return result

    @staticmethod
    def _extract_cvss(cve_data: dict) -> tuple:
        """استخراج CVSS score با fallback"""
        metrics = cve_data.get("metrics", {})

        # CVSS v3.1
        v31 = metrics.get("cvssMetricV31", [])
        if v31:
            m = v31[0].get("cvssData", {})
            return (
                float(m.get("baseScore", 0)),
                m.get("vectorString", ""),
                "3.1"
            )

        # CVSS v3.0
        v30 = metrics.get("cvssMetricV30", [])
        if v30:
            m = v30[0].get("cvssData", {})
            return (
                float(m.get("baseScore", 0)),
                m.get("vectorString", ""),
                "3.0"
            )

        # CVSS v2.0
        v2 = metrics.get("cvssMetricV2", [])
        if v2:
            m = v2[0].get("cvssData", {})
            return (
                float(m.get("baseScore", 0)),
                m.get("vectorString", ""),
                "2.0"
            )

        return 0.0, "", "N/A"

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= CVSS_CRITICAL:  return "CRITICAL"
        if score >= CVSS_HIGH:      return "HIGH"
        if score >= CVSS_MEDIUM:    return "MEDIUM"
        if score >= CVSS_LOW:       return "LOW"
        return "INFO"
