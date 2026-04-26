# aegis-scanner/intelligence/cve_mapper.py
"""
CVE Mapper: نگاشت دقیق CPE → CVE با کش لوکال و fallback آفلاین.
این ماژول لایه‌ای بین VulnEngine و NVD API فراهم می‌کند که:
1. CPE‌های Nmap را نرمال‌سازی می‌کند
2. جستجوی fuzzy برای service/version انجام می‌دهد
3. نتایج را با کش لوکال بهینه می‌کند
"""

import re
import logging
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CPEComponents:
    """اجزای یک CPE URI"""
    part:     str   # a=application, o=os, h=hardware
    vendor:   str
    product:  str
    version:  str
    raw:      str

    @property
    def search_keyword(self) -> str:
        """تبدیل CPE به keyword جستجو برای NVD"""
        parts = []
        if self.vendor and self.vendor != "*":
            # vendor را human-readable می‌کنیم
            parts.append(self.vendor.replace("_", " "))
        if self.product and self.product != "*":
            parts.append(self.product.replace("_", " "))
        if self.version and self.version not in ("*", "-"):
            parts.append(self.version)
        return " ".join(parts)


class CVEMapper:
    """
    نگاشت هوشمند بین اطلاعات سرویس Nmap و CVE‌های NVD.

    دو روش کار:
    1. CPE مستقیم: اگر Nmap یک CPE معتبر برگرداند
    2. Fuzzy keyword: بر اساس product + version
    """

    # ─── CPE URI parser ────────────────────────────────────────────────────
    CPE22_PATTERN = re.compile(
        r"cpe:/([aho]):([^:]+):([^:]+)(?::([^:]+))?",
        re.IGNORECASE
    )
    CPE23_PATTERN = re.compile(
        r"cpe:2\.3:([aho]):([^:]+):([^:]+):([^:]+)",
        re.IGNORECASE
    )

    @classmethod
    def parse_cpe(cls, cpe_str: str) -> Optional[CPEComponents]:
        """
        پارس CPE 2.2 یا 2.3 به اجزا.

        مثال‌ها:
          cpe:/a:apache:http_server:2.4.49
          cpe:2.3:a:microsoft:iis:10.0:*:*:*:*:*:*:*
        """
        if not cpe_str:
            return None

        # CPE 2.3
        m = cls.CPE23_PATTERN.match(cpe_str)
        if m:
            return CPEComponents(
                part=m.group(1), vendor=m.group(2),
                product=m.group(3), version=m.group(4),
                raw=cpe_str
            )

        # CPE 2.2
        m = cls.CPE22_PATTERN.match(cpe_str)
        if m:
            return CPEComponents(
                part=m.group(1), vendor=m.group(2),
                product=m.group(3), version=m.group(4) or "*",
                raw=cpe_str
            )

        return None

    # ─── Version normalization ─────────────────────────────────────────────
    @staticmethod
    def normalize_version(version_str: str) -> str:
        """
        پاک‌سازی نسخه از suffix‌های اضافه.
        مثال: "2.4.49-debian" → "2.4.49"
        """
        if not version_str:
            return ""
        # استخراج بخش نسخه عددی اصلی (X.Y.Z)
        # ابتدا حذف build/OS suffix بعد از خط تیره یا +
        cleaned = re.sub(r"[-+~].*$", "", version_str.strip())
        # استخراج pattern عددی مانند 7.4 یا 2.4.49 (قبل از هر حرف غیرعددی)
        match = re.match(r"(\d+(?:\.\d+)*)", cleaned)
        if match:
            return match.group(1)
        return ""

    # ─── Search query builder ──────────────────────────────────────────────
    @classmethod
    def build_search_queries(
        cls,
        service: str,
        product: str,
        version: str,
        cpe: str,
    ) -> list:
        """
        ساختن لیست query‌های جستجو با اولویت‌بندی.
        بهترین query اول.
        """
        queries = []

        # 1. CPE مستقیم (دقیق‌ترین)
        if cpe:
            queries.append({"type": "cpe", "value": cpe, "priority": 1})

        # 2. Product + version (دقیق)
        ver_norm = cls.normalize_version(version)
        if product and ver_norm:
            queries.append({
                "type":     "keyword",
                "value":    f"{product} {ver_norm}",
                "priority": 2,
            })

        # 3. Product بدون version (عمومی‌تر)
        if product:
            queries.append({
                "type":     "keyword",
                "value":    product,
                "priority": 3,
            })

        # 4. Service name (کلی‌ترین)
        if service and service not in ("tcpwrapped", "unknown", ""):
            queries.append({
                "type":     "keyword",
                "value":    service,
                "priority": 4,
            })

        return queries

    # ─── CVE relevance filter ──────────────────────────────────────────────
    @staticmethod
    def filter_relevant_cves(
        cves: list,
        product: str,
        version: str,
        max_results: int = 10,
    ) -> list:
        """
        فیلتر CVE‌ها بر اساس relevance به product/version.
        جلوگیری از false positive‌های NVD keyword search.
        """
        if not cves:
            return []

        product_lower = product.lower() if product else ""
        ver_norm = CVEMapper.normalize_version(version)

        scored = []
        for cve in cves:
            desc = cve.get("description", "").lower()
            score = 0

            # +3 اگر نام product در description باشد
            if product_lower and product_lower in desc:
                score += 3

            # +2 اگر version در description باشد
            if ver_norm and ver_norm in desc:
                score += 2

            # +1 برای CVSS بالا
            cvss = cve.get("cvss_score", 0)
            if cvss >= 9.0:
                score += 1

            # -1 برای CVE‌های خیلی قدیمی (> 10 سال)
            pub = cve.get("published", "")
            if pub and pub[:4].isdigit():
                year = int(pub[:4])
                if year < 2014:
                    score -= 1

            scored.append((score, cve))

        # مرتب‌سازی: score بالا + CVSS بالا
        scored.sort(key=lambda x: (-x[0], -x[1].get("cvss_score", 0)))
        return [cve for _, cve in scored[:max_results]]

    # ─── CPE expansion ─────────────────────────────────────────────────────
    VENDOR_ALIASES: dict = {
        "apache":    ["apache", "apache_software_foundation"],
        "microsoft": ["microsoft"],
        "nginx":     ["nginx", "f5"],
        "openssh":   ["openbsd", "openssh"],
        "openssl":   ["openssl"],
        "mysql":     ["mysql", "oracle"],
        "php":       ["php"],
        "wordpress": ["wordpress"],
        "drupal":    ["drupal"],
        "jenkins":   ["jenkins", "jenkins-ci"],
        "redis":     ["redis"],
        "mongodb":   ["mongodb"],
        "elastic":   ["elastic", "elasticsearch"],
    }

    @classmethod
    def expand_vendor(cls, vendor: str) -> list:
        """گسترش نام vendor به aliasهای معروف"""
        vendor_lower = vendor.lower()
        for key, aliases in cls.VENDOR_ALIASES.items():
            if vendor_lower in aliases or key in vendor_lower:
                return aliases
        return [vendor_lower]

    # ─── Service → likely CVE keywords ────────────────────────────────────
    # این mapping از SANS Top 20 و CIS Benchmarks گرفته شده
    SERVICE_CVE_KEYWORDS: dict = {
        "ssh":        ["openssh", "libssh"],
        "http":       ["apache", "nginx", "iis", "lighttpd"],
        "https":      ["openssl", "apache", "nginx"],
        "ftp":        ["vsftpd", "proftpd", "pureftpd"],
        "smtp":       ["postfix", "sendmail", "exim"],
        "rdp":        ["windows remote desktop", "ms-rdp"],
        "smb":        ["samba", "windows smb"],
        "mysql":      ["mysql", "mariadb"],
        "postgresql": ["postgresql"],
        "redis":      ["redis"],
        "mongodb":    ["mongodb"],
        "vnc":        ["vnc", "realvnc", "tightvnc"],
        "telnet":     ["telnetd"],
    }

    @classmethod
    def get_service_keywords(cls, service: str) -> list:
        """دریافت keyword‌های احتمالی برای یک سرویس"""
        return cls.SERVICE_CVE_KEYWORDS.get(service.lower(), [service])
