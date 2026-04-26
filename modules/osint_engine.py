# aegis-scanner/modules/osint_engine.py
"""
موتور OSINT حرفه‌ای Aegis-Scanner.

این ماژول اطلاعات عمومی هدف را از منابع مختلف جمع‌آوری می‌کند:

منابع داده:
  ├── Shodan API      → banner، پورت‌های باز، آسیب‌پذیری‌ها
  ├── Censys API      → TLS certificate، ASN، org info
  ├── VirusTotal API  → IP reputation، passive DNS، malware history
  ├── AbuseIPDB API   → گزارش‌های سوء‌استفاده
  ├── ipinfo.io       → geo، ASN، org (بدون API key هم کار می‌کند)
  ├── DNS enumeration → A، MX، NS، TXT، SOA، CNAME
  ├── Certificate Transparency → subdomain discovery از CT logs
  ├── Whois           → registrar، creation date، contact
  └── Local GeoIP     → تعیین موقعیت جغرافیایی آفلاین

اصل طراحی: اگر API key موجود نبود، fallback به روش‌های local/public اعمال می‌شود.
هرگز از اطلاعات خصوصی یا غیرمجاز استفاده نمی‌شود.
"""

import os
import re
import json
import socket
import logging
import time
import ipaddress
import subprocess
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# ─── API Configuration (از متغیر محیطی) ─────────────────────────────────────
SHODAN_KEY    = os.getenv("SHODAN_API_KEY")
CENSYS_ID     = os.getenv("CENSYS_API_ID")
CENSYS_SECRET = os.getenv("CENSYS_API_SECRET")
VT_KEY        = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY     = os.getenv("ABUSEIPDB_API_KEY")
IPINFO_KEY    = os.getenv("IPINFO_TOKEN")       # اختیاری — بدون key هم کار می‌کند

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    logger.warning("[OSINT] requests not installed — HTTP sources disabled")


@dataclass
class GeoInfo:
    ip:           str
    country:      str  = ""
    country_code: str  = ""
    city:         str  = ""
    region:       str  = ""
    asn:          str  = ""
    org:          str  = ""
    isp:          str  = ""
    latitude:     float = 0.0
    longitude:    float = 0.0
    is_tor:       bool  = False
    is_proxy:     bool  = False
    is_hosting:   bool  = False
    source:       str  = ""


@dataclass
class DNSInfo:
    target:        str
    resolved_ips:  list = field(default_factory=list)
    mx_records:    list = field(default_factory=list)
    ns_records:    list = field(default_factory=list)
    txt_records:   list = field(default_factory=list)
    cname_records: list = field(default_factory=list)
    soa_record:    str  = ""
    subdomains:    list = field(default_factory=list)
    reverse_dns:   dict = field(default_factory=dict)


@dataclass
class ShodanInfo:
    ip:            str
    ports:         list = field(default_factory=list)
    banners:       list = field(default_factory=list)
    vulns:         list = field(default_factory=list)
    tags:          list = field(default_factory=list)
    last_update:   str  = ""
    country:       str  = ""
    org:           str  = ""
    hostnames:     list = field(default_factory=list)
    os_detected:   str  = ""
    error:         Optional[str] = None


@dataclass
class ReputationInfo:
    ip:                str
    abuse_score:       int   = 0     # 0-100
    total_reports:     int   = 0
    is_malicious:      bool  = False
    vt_malicious:      int   = 0
    vt_suspicious:     int   = 0
    vt_harmless:       int   = 0
    last_seen_malicious: str = ""
    categories:        list  = field(default_factory=list)
    detected_urls:     list  = field(default_factory=list)
    passive_dns:       list  = field(default_factory=list)
    error:             Optional[str] = None


@dataclass
class CertificateInfo:
    target:        str
    common_name:   str  = ""
    sans:          list = field(default_factory=list)
    issuer:        str  = ""
    valid_from:    str  = ""
    valid_to:      str  = ""
    serial:        str  = ""
    fingerprint:   str  = ""
    is_wildcard:   bool = False
    subdomains_found: list = field(default_factory=list)   # از CT logs


@dataclass
class WhoisInfo:
    target:        str
    registrar:     str  = ""
    creation_date: str  = ""
    expiry_date:   str  = ""
    updated_date:  str  = ""
    status:        list = field(default_factory=list)
    nameservers:   list = field(default_factory=list)
    registrant:    str  = ""
    org:           str  = ""
    country:       str  = ""
    emails:        list = field(default_factory=list)
    raw:           str  = ""


@dataclass
class OSINTReport:
    """گزارش کامل OSINT برای یک target"""
    target:         str
    scan_time:      str = field(default_factory=lambda: datetime.now().isoformat())

    # نتایج
    geo:            Optional[GeoInfo]         = None
    dns:            Optional[DNSInfo]         = None
    shodan:         Optional[ShodanInfo]      = None
    reputation:     Optional[ReputationInfo]  = None
    certificate:    Optional[CertificateInfo] = None
    whois:          Optional[WhoisInfo]       = None

    # خلاصه
    risk_indicators: list = field(default_factory=list)
    attack_surface:  list = field(default_factory=list)
    data_sources:    list = field(default_factory=list)
    errors:          list = field(default_factory=list)
    summary:         str  = ""


class OSINTEngine:
    """
    موتور OSINT حرفه‌ای با پشتیبانی از API و fallback local.

    استراتژی:
    1. اگر API key موجود → استفاده از API (داده غنی‌تر)
    2. اگر API key موجود نبود → استفاده از منابع public/local
    3. همیشه حداقل geo + DNS + whois در دسترس است
    """

    IPINFO_URL   = "https://ipinfo.io/{ip}/json"
    SHODAN_URL   = "https://api.shodan.io/shodan/host/{ip}?key={key}"
    VT_URL       = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    ABUSE_URL    = "https://api.abuseipdb.com/api/v2/check"
    CRTSH_URL    = "https://crt.sh/?q={domain}&output=json"

    TIMEOUT = 10
    RATE_LIMIT_DELAY = 1.0   # بین درخواست‌های API

    def __init__(self):
        self._api_available = {
            "shodan":    bool(SHODAN_KEY),
            "censys":    bool(CENSYS_ID and CENSYS_SECRET),
            "virustotal":bool(VT_KEY),
            "abuseipdb": bool(ABUSE_KEY),
            "ipinfo":    True,   # بدون key هم کار می‌کند (rate limited)
        }
        self._log_api_status()

    def _log_api_status(self) -> None:
        available = [k for k, v in self._api_available.items() if v]
        missing   = [k for k, v in self._api_available.items() if not v]
        logger.info(f"[OSINT] APIs available: {available}")
        if missing:
            logger.info(f"[OSINT] APIs (fallback mode): {missing}")

    # ─── Main entry ──────────────────────────────────────────────────────
    def gather(self, target: str, deep: bool = True) -> OSINTReport:
        """
        جمع‌آوری کامل OSINT برای یک IP یا domain.

        Args:
            target: IP address یا domain name
            deep: اگر True، تمام منابع را بررسی می‌کند
        """
        report = OSINTReport(target=target)
        is_ip  = self._is_ip(target)

        logger.info(f"[OSINT] Starting intelligence gathering for {target}")

        # ─── Step 1: DNS enumeration (همیشه) ─────────────────────────────
        self._run_step(report, "dns", lambda: self._dns_enumeration(target, is_ip))

        # ─── Step 2: Geo/ASN (همیشه — fallback به ipinfo.io رایگان) ─────
        ip = target if is_ip else self._resolve_ip(target)
        if ip:
            self._run_step(report, "geo", lambda: self._geo_lookup(ip))

            # ─── Step 3: Whois ───────────────────────────────────────────
            self._run_step(report, "whois", lambda: self._whois_lookup(target))

            if deep:
                # ─── Step 4: Shodan ──────────────────────────────────────
                self._run_step(report, "shodan", lambda: self._shodan_lookup(ip))
                time.sleep(self.RATE_LIMIT_DELAY)

                # ─── Step 5: Reputation (VT + AbuseIPDB) ─────────────────
                self._run_step(report, "reputation", lambda: self._reputation_lookup(ip))
                time.sleep(self.RATE_LIMIT_DELAY)

            # ─── Step 6: Certificate Transparency ────────────────────────
            domain = target if not is_ip else self._reverse_lookup(ip)
            if domain:
                self._run_step(report, "certificate", lambda: self._ct_lookup(domain))

        # ─── Build summary ─────────────────────────────────────────────────
        report.risk_indicators = self._extract_risk_indicators(report)
        report.attack_surface  = self._extract_attack_surface(report)
        report.summary         = self._build_summary(report)

        logger.info(
            f"[OSINT] Complete: {len(report.data_sources)} sources, "
            f"{len(report.risk_indicators)} risk indicators"
        )
        return report

    def _run_step(self, report: OSINTReport, name: str, fn) -> None:
        """اجرای یک مرحله با مدیریت خطا"""
        try:
            result = fn()
            setattr(report, name, result)
            if result:
                report.data_sources.append(name)
        except Exception as e:
            report.errors.append(f"{name}: {e}")
            logger.debug(f"[OSINT] {name} error: {e}")

    # ─── DNS Enumeration ─────────────────────────────────────────────────
    def _dns_enumeration(self, target: str, is_ip: bool) -> DNSInfo:
        """جمع‌آوری کامل DNS records"""
        info = DNSInfo(target=target)

        if is_ip:
            # reverse DNS
            try:
                hostname = socket.gethostbyaddr(target)[0]
                info.reverse_dns[target] = hostname
            except socket.herror:
                pass
            return info

        # A records
        try:
            results = socket.getaddrinfo(target, None)
            info.resolved_ips = list({r[4][0] for r in results})
        except socket.gaierror:
            pass

        # Dig-based lookups (اگر dig نصب باشد)
        record_types = {
            "MX":    info.mx_records,
            "NS":    info.ns_records,
            "TXT":   info.txt_records,
            "CNAME": info.cname_records,
        }
        for rtype, container in record_types.items():
            records = self._dig_query(target, rtype)
            container.extend(records)

        # SOA
        soa = self._dig_query(target, "SOA")
        info.soa_record = soa[0] if soa else ""

        # Reverse DNS برای IP‌های resolve شده
        for ip in info.resolved_ips[:3]:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                info.reverse_dns[ip] = hostname
            except Exception:
                pass

        # Subdomain enumeration (passive — بدون brute force)
        info.subdomains = self._passive_subdomain_enum(target)

        return info

    @staticmethod
    def _dig_query(target: str, rtype: str) -> list:
        """اجرای dig query"""
        try:
            result = subprocess.run(
                ["dig", "+short", rtype, target],
                capture_output=True, text=True, timeout=8
            )
            if result.returncode == 0 and result.stdout.strip():
                return [r.strip() for r in result.stdout.strip().split("\n") if r.strip()]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # fallback به nslookup
            try:
                r2 = subprocess.run(
                    ["nslookup", "-type=" + rtype, target],
                    capture_output=True, text=True, timeout=8
                )
                if r2.returncode == 0:
                    lines = r2.stdout.strip().split("\n")
                    return [l.strip() for l in lines if "=" in l or ":" in l][:5]
            except Exception:
                pass
        return []

    def _passive_subdomain_enum(self, domain: str) -> list:
        """کشف subdomain از طریق CT logs و DNS passive"""
        subdomains = set()

        # از crt.sh (Certificate Transparency)
        if REQUESTS_OK:
            try:
                resp = requests.get(
                    self.CRTSH_URL.format(domain=f"%.{domain}"),
                    timeout=self.TIMEOUT,
                    headers={"Accept": "application/json"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        names = entry.get("name_value", "")
                        for name in names.split("\n"):
                            name = name.strip().lower()
                            if name.endswith(f".{domain}") and "*" not in name:
                                subdomains.add(name)
            except Exception as e:
                logger.debug(f"[OSINT] crt.sh: {e}")

        return sorted(subdomains)[:50]  # max 50

    # ─── Geo / ASN Lookup ────────────────────────────────────────────────
    def _geo_lookup(self, ip: str) -> GeoInfo:
        """تعیین موقعیت جغرافیایی و ASN — با fallback کامل"""
        geo = GeoInfo(ip=ip)

        # روش 1: ipinfo.io (رایگان با rate limit، یا با token)
        if REQUESTS_OK:
            try:
                url = self.IPINFO_URL.format(ip=ip)
                headers = {}
                if IPINFO_KEY:
                    headers["Authorization"] = f"Bearer {IPINFO_KEY}"

                resp = requests.get(url, headers=headers, timeout=self.TIMEOUT)
                if resp.status_code == 200:
                    data = resp.json()
                    geo.country      = data.get("country", "")
                    geo.country_code = data.get("country", "")
                    geo.city         = data.get("city", "")
                    geo.region       = data.get("region", "")
                    geo.org          = data.get("org", "")
                    geo.isp          = data.get("org", "")
                    # ASN parsing (format: "AS12345 ISP Name")
                    org_raw = data.get("org", "")
                    if org_raw.startswith("AS"):
                        parts = org_raw.split(" ", 1)
                        geo.asn = parts[0]
                        geo.org = parts[1] if len(parts) > 1 else org_raw

                    loc = data.get("loc", "0,0").split(",")
                    if len(loc) == 2:
                        geo.latitude  = float(loc[0])
                        geo.longitude = float(loc[1])
                    geo.source = "ipinfo.io"
                    return geo
            except Exception as e:
                logger.debug(f"[OSINT] ipinfo.io: {e}")

        # روش 2: ip-api.com (رایگان، بدون key)
        if REQUESTS_OK:
            try:
                resp = requests.get(
                    f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
                    f"regionName,city,isp,org,as,lat,lon,proxy,hosting",
                    timeout=self.TIMEOUT
                )
                if resp.status_code == 200:
                    d = resp.json()
                    if d.get("status") == "success":
                        geo.country      = d.get("country", "")
                        geo.country_code = d.get("countryCode", "")
                        geo.city         = d.get("city", "")
                        geo.region       = d.get("regionName", "")
                        geo.isp          = d.get("isp", "")
                        geo.org          = d.get("org", "")
                        geo.asn          = d.get("as", "").split(" ")[0]
                        geo.latitude     = d.get("lat", 0.0)
                        geo.longitude    = d.get("lon", 0.0)
                        geo.is_proxy     = d.get("proxy", False)
                        geo.is_hosting   = d.get("hosting", False)
                        geo.source       = "ip-api.com"
                        return geo
            except Exception as e:
                logger.debug(f"[OSINT] ip-api.com: {e}")

        # روش 3: Local هویت‌شناسی IP range (RFC ranges)
        geo.source = "local_inference"
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                geo.country = "Private"
                geo.org     = "Private/Internal Network"
            elif addr.is_loopback:
                geo.country = "Loopback"
                geo.org     = "Localhost"
        except ValueError:
            pass

        return geo

    # ─── Shodan Lookup ────────────────────────────────────────────────────
    def _shodan_lookup(self, ip: str) -> ShodanInfo:
        """جستجوی Shodan برای اطلاعات banner و پورت‌های باز"""
        info = ShodanInfo(ip=ip)

        if not SHODAN_KEY:
            # fallback: shodan CLI اگر نصب باشد
            return self._shodan_cli_fallback(ip)

        if not REQUESTS_OK:
            info.error = "requests library not available"
            return info

        try:
            resp = requests.get(
                self.SHODAN_URL.format(ip=ip, key=SHODAN_KEY),
                timeout=self.TIMEOUT
            )
            if resp.status_code == 401:
                info.error = "Invalid Shodan API key"
                return info
            if resp.status_code == 404:
                info.error = "No Shodan data for this IP"
                return info
            if resp.status_code != 200:
                info.error = f"Shodan API error: {resp.status_code}"
                return info

            data = resp.json()
            info.ports       = data.get("ports", [])
            info.country     = data.get("country_name", "")
            info.org         = data.get("org", "")
            info.hostnames   = data.get("hostnames", [])
            info.os_detected = data.get("os", "")
            info.tags        = data.get("tags", [])
            info.last_update = data.get("last_update", "")

            # CVEs از Shodan
            vulns = data.get("vulns", {})
            if vulns:
                info.vulns = list(vulns.keys())

            # Banners
            for service in data.get("data", [])[:10]:
                banner_entry = {
                    "port":      service.get("port"),
                    "transport": service.get("transport", "tcp"),
                    "product":   service.get("product", ""),
                    "version":   service.get("version", ""),
                    "banner":    service.get("data", "")[:200],
                }
                info.banners.append(banner_entry)

        except Exception as e:
            info.error = str(e)
            logger.debug(f"[OSINT] Shodan API: {e}")

        return info

    @staticmethod
    def _shodan_cli_fallback(ip: str) -> ShodanInfo:
        """fallback به Shodan CLI اگر نصب باشد"""
        info = ShodanInfo(ip=ip)
        try:
            result = subprocess.run(
                ["shodan", "host", ip, "--format", "json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                info.ports   = data.get("ports", [])
                info.country = data.get("country_name", "")
                info.org     = data.get("org", "")
                info.source_note = "shodan-cli"
        except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
            info.error = "Shodan API key not configured; shodan-cli not available"
        return info

    # ─── Reputation Lookup ────────────────────────────────────────────────
    def _reputation_lookup(self, ip: str) -> ReputationInfo:
        """بررسی reputation از AbuseIPDB و VirusTotal"""
        rep = ReputationInfo(ip=ip)

        # AbuseIPDB
        if ABUSE_KEY and REQUESTS_OK:
            try:
                resp = requests.get(
                    self.ABUSE_URL,
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Accept": "application/json",
                        "Key": ABUSE_KEY,
                    },
                    timeout=self.TIMEOUT,
                )
                if resp.status_code == 200:
                    d = resp.json().get("data", {})
                    rep.abuse_score    = d.get("abuseConfidenceScore", 0)
                    rep.total_reports  = d.get("totalReports", 0)
                    rep.is_malicious   = rep.abuse_score >= 80
                    rep.categories     = d.get("usageType", "").split(", ")
                    rep.last_seen_malicious = d.get("lastReportedAt", "")
            except Exception as e:
                logger.debug(f"[OSINT] AbuseIPDB: {e}")

        # VirusTotal
        if VT_KEY and REQUESTS_OK:
            try:
                resp = requests.get(
                    self.VT_URL.format(ip=ip),
                    headers={"x-apikey": VT_KEY},
                    timeout=self.TIMEOUT,
                )
                if resp.status_code == 200:
                    attrs = resp.json().get("data", {}).get("attributes", {})
                    last_analysis = attrs.get("last_analysis_stats", {})
                    rep.vt_malicious  = last_analysis.get("malicious", 0)
                    rep.vt_suspicious = last_analysis.get("suspicious", 0)
                    rep.vt_harmless   = last_analysis.get("harmless", 0)

                    # Passive DNS
                    resolutions = attrs.get("last_dns_records", [])
                    rep.passive_dns = [
                        {"type": r.get("type"), "value": r.get("value")}
                        for r in resolutions[:10]
                    ]

                    # Detected URLs
                    detected = resp.json().get("data", {}).get("relationships", {})
                    # اطلاعات کافی از attributes
                    if rep.vt_malicious > 0:
                        rep.is_malicious = True
            except Exception as e:
                logger.debug(f"[OSINT] VirusTotal: {e}")

        # اگر هیچ API موجود نباشد: بررسی blocklist‌های عمومی
        if not ABUSE_KEY and not VT_KEY:
            rep.error = "No reputation API keys configured — add ABUSEIPDB_API_KEY or VIRUSTOTAL_API_KEY"
            rep = self._public_blocklist_check(ip, rep)

        return rep

    def _public_blocklist_check(self, ip: str, rep: ReputationInfo) -> ReputationInfo:
        """
        بررسی DNS-based blacklists (DBL/DNSBL) — بدون نیاز به API key.
        تکنیک: reverse IP + query به DNSBL servers
        """
        # معروف‌ترین DNSBL‌ها
        dnsbl_servers = [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "dnsbl.sorbs.net",
            "b.barracudacentral.org",
        ]
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version != 4 or addr.is_private:
                return rep
            # معکوس کردن IP: 1.2.3.4 → 4.3.2.1
            reversed_ip = ".".join(reversed(ip.split(".")))
            hits = 0
            for dnsbl in dnsbl_servers:
                query = f"{reversed_ip}.{dnsbl}"
                try:
                    socket.gethostbyname(query)
                    hits += 1
                    rep.categories.append(f"Listed in {dnsbl}")
                except socket.gaierror:
                    pass   # not listed = good

            if hits > 0:
                rep.abuse_score   = min(hits * 25, 100)
                rep.is_malicious  = hits >= 2
                rep.total_reports = hits
        except Exception as e:
            logger.debug(f"[OSINT] DNSBL: {e}")
        return rep

    # ─── Certificate Transparency ─────────────────────────────────────────
    def _ct_lookup(self, domain: str) -> CertificateInfo:
        """جستجو در Certificate Transparency logs"""
        cert = CertificateInfo(target=domain)
        if not REQUESTS_OK:
            return cert
        try:
            resp = requests.get(
                self.CRTSH_URL.format(domain=domain),
                timeout=self.TIMEOUT * 2,
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return cert

            data = resp.json()
            subdomains = set()
            for entry in data:
                names = entry.get("name_value", "")
                issuer_raw = entry.get("issuer_name", "")
                if not cert.issuer and issuer_raw:
                    cert.issuer = issuer_raw
                if not cert.valid_from:
                    cert.valid_from = entry.get("not_before", "")
                if not cert.valid_to:
                    cert.valid_to = entry.get("not_after", "")

                for name in names.split("\n"):
                    name = name.strip().lower()
                    if name.endswith(f".{domain}") and "*" not in name:
                        subdomains.add(name)
                    elif name == domain:
                        cert.common_name = name
                    elif name.startswith("*."):
                        cert.is_wildcard = True
                        cert.sans.append(name)

            cert.subdomains_found = sorted(subdomains)[:100]

        except Exception as e:
            logger.debug(f"[OSINT] crt.sh: {e}")
        return cert

    # ─── Whois ───────────────────────────────────────────────────────────
    @staticmethod
    def _whois_lookup(target: str) -> WhoisInfo:
        """Whois lookup از طریق whois CLI"""
        info = WhoisInfo(target=target)
        try:
            result = subprocess.run(
                ["whois", target],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode != 0:
                return info

            raw = result.stdout
            info.raw = raw[:3000]   # ذخیره اول ۳۰۰۰ کاراکتر

            # Parsing فیلدهای مهم
            patterns = {
                "registrar":     [r"Registrar:\s*(.+)", r"registrar:\s*(.+)"],
                "creation_date": [r"Creation Date:\s*(.+)", r"created:\s*(.+)"],
                "expiry_date":   [r"Registry Expiry Date:\s*(.+)", r"expire:\s*(.+)", r"Expiry Date:\s*(.+)"],
                "updated_date":  [r"Updated Date:\s*(.+)", r"changed:\s*(.+)"],
                "registrant":    [r"Registrant Name:\s*(.+)", r"registrant:\s*(.+)"],
                "org":           [r"Registrant Organization:\s*(.+)", r"org:\s*(.+)"],
                "country":       [r"Registrant Country:\s*(.+)", r"country:\s*(.+)"],
            }
            for field, pats in patterns.items():
                for pat in pats:
                    match = re.search(pat, raw, re.IGNORECASE)
                    if match:
                        val = match.group(1).strip()
                        if val and not val.startswith("REDACTED"):
                            setattr(info, field, val[:200])
                            break

            # NS
            info.nameservers = re.findall(
                r"Name Server:\s*(.+)", raw, re.IGNORECASE
            )[:6]

            # Email (مراقب privacy باشید)
            emails = re.findall(r"[\w.+-]+@[\w.-]+\.\w+", raw)
            info.emails = list(set(emails))[:5]

        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            info.raw = f"whois not available: {e}"
        except Exception as e:
            logger.debug(f"[OSINT] whois: {e}")

        return info

    # ─── Helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _is_ip(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    def _resolve_ip(domain: str) -> Optional[str]:
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    @staticmethod
    def _reverse_lookup(ip: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return None

    # ─── Risk indicators ──────────────────────────────────────────────────
    def _extract_risk_indicators(self, report: OSINTReport) -> list:
        indicators = []

        if report.reputation:
            if report.reputation.is_malicious:
                indicators.append({
                    "type":     "MALICIOUS_IP",
                    "severity": "CRITICAL",
                    "detail":   f"Abuse score: {report.reputation.abuse_score}/100, "
                                f"Reports: {report.reputation.total_reports}",
                })
            if report.reputation.vt_malicious > 3:
                indicators.append({
                    "type":     "VIRUSTOTAL_FLAGGED",
                    "severity": "HIGH",
                    "detail":   f"VirusTotal: {report.reputation.vt_malicious} malicious detections",
                })

        if report.geo:
            if report.geo.is_proxy:
                indicators.append({
                    "type":     "PROXY_DETECTED",
                    "severity": "MEDIUM",
                    "detail":   "IP is behind a proxy/VPN",
                })
            if report.geo.is_hosting:
                indicators.append({
                    "type":     "HOSTING_PROVIDER",
                    "severity": "INFO",
                    "detail":   f"IP belongs to hosting: {report.geo.org}",
                })

        if report.shodan:
            if report.shodan.vulns:
                indicators.append({
                    "type":     "SHODAN_VULNS",
                    "severity": "HIGH",
                    "detail":   f"Shodan detected CVEs: {', '.join(report.shodan.vulns[:5])}",
                })
            if len(report.shodan.ports) > 20:
                indicators.append({
                    "type":     "MANY_OPEN_PORTS",
                    "severity": "MEDIUM",
                    "detail":   f"{len(report.shodan.ports)} open ports found in Shodan",
                })

        if report.certificate and report.certificate.subdomains_found:
            indicators.append({
                "type":     "SUBDOMAINS_FOUND",
                "severity": "INFO",
                "detail":   f"{len(report.certificate.subdomains_found)} subdomains via CT logs",
            })

        return indicators

    def _extract_attack_surface(self, report: OSINTReport) -> list:
        surface = []

        if report.shodan and report.shodan.ports:
            surface.append({
                "source":  "shodan",
                "finding": f"Open ports: {sorted(report.shodan.ports)[:20]}",
            })

        if report.dns and report.dns.subdomains:
            surface.append({
                "source":  "passive_dns",
                "finding": f"Subdomains: {report.dns.subdomains[:10]}",
            })

        if report.dns and report.dns.mx_records:
            surface.append({
                "source":  "dns_mx",
                "finding": f"Mail servers: {report.dns.mx_records[:3]}",
            })

        if report.certificate and report.certificate.subdomains_found:
            surface.append({
                "source":  "ct_logs",
                "finding": f"Subdomains from CT: {report.certificate.subdomains_found[:10]}",
            })

        return surface

    @staticmethod
    def _build_summary(report: OSINTReport) -> str:
        parts = []
        if report.geo:
            loc = f"{report.geo.city}, {report.geo.country}" if report.geo.city else report.geo.country
            parts.append(f"Location: {loc} ({report.geo.asn})")
        if report.shodan and not report.shodan.error:
            parts.append(f"Shodan ports: {len(report.shodan.ports)}")
        if report.reputation and report.reputation.abuse_score:
            parts.append(f"Abuse score: {report.reputation.abuse_score}/100")
        if report.certificate and report.certificate.subdomains_found:
            parts.append(f"Subdomains: {len(report.certificate.subdomains_found)}")
        return " | ".join(parts) if parts else "OSINT data collected"

    # ─── Serialization ────────────────────────────────────────────────────
    def to_dict(self, report: OSINTReport) -> dict:
        def safe_dict(obj) -> dict:
            if obj is None:
                return {}
            return {k: v for k, v in obj.__dict__.items()}

        return {
            "target":          report.target,
            "scan_time":       report.scan_time,
            "geo":             safe_dict(report.geo),
            "dns":             safe_dict(report.dns),
            "shodan":          safe_dict(report.shodan),
            "reputation":      safe_dict(report.reputation),
            "certificate":     safe_dict(report.certificate),
            "whois":           safe_dict(report.whois),
            "risk_indicators": report.risk_indicators,
            "attack_surface":  report.attack_surface,
            "data_sources":    report.data_sources,
            "errors":          report.errors,
            "summary":         report.summary,
        }
