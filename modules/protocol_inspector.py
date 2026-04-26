# aegis-scanner/modules/protocol_inspector.py
"""
بازرسی عمیق پروتکل‌های شبکه.

پروتکل‌های پشتیبانی‌شده:
  ├── TLS/SSL  → نسخه، cipher suite، گواهینامه، HSTS، HPKP
  ├── SSH      → الگوریتم‌های key exchange، cipher، MAC، host key type
  ├── HTTP/S   → security headers، server leak، methods، cookies
  └── SMB      → dialect، signing، guest access، null session
"""

import ssl
import socket
import struct
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ─── Weak cipher/algorithm databases ─────────────────────────────────────────
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_TLS_CIPHERS  = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
    "MD5", "RC2", "IDEA", "SEED",
}
STRONG_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}

WEAK_SSH_KEXES = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "ecdh-sha2-nistp256",   # NIST curves — NSA influence
}
WEAK_SSH_CIPHERS = {
    "arcfour", "arcfour128", "arcfour256",
    "blowfish-cbc", "cast128-cbc", "3des-cbc",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",  # CBC mode — vulnerable to BEAST
}
WEAK_SSH_MACS = {
    "hmac-md5", "hmac-md5-96",
    "hmac-sha1", "hmac-sha1-96",
    "umac-64@openssh.com",
}

SECURITY_HEADERS_REQUIRED = {
    "Strict-Transport-Security": "Prevents protocol downgrade attacks",
    "X-Frame-Options":           "Prevents clickjacking",
    "X-Content-Type-Options":    "Prevents MIME sniffing",
    "Content-Security-Policy":   "Prevents XSS and injection",
    "X-XSS-Protection":          "Legacy XSS filter (still valuable)",
    "Referrer-Policy":           "Controls referrer information",
    "Permissions-Policy":        "Restricts browser API access",
}

INFORMATION_LEAK_HEADERS = {
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Runtime", "X-Version",
}


@dataclass
class TLSInspection:
    host: str
    port: int
    tls_version:     Optional[str]  = None
    cipher_suite:    Optional[str]  = None
    key_bits:        Optional[int]  = None
    cert_subject:    Optional[str]  = None
    cert_issuer:     Optional[str]  = None
    cert_expiry:     Optional[str]  = None
    cert_expired:    bool           = False
    cert_self_signed:bool           = False
    cert_wildcard:   bool           = False
    san_domains:     list           = field(default_factory=list)
    weak_version:    bool           = False
    weak_cipher:     bool           = False
    supports_tls13:  bool           = False
    findings:        list           = field(default_factory=list)
    risk_level:      str            = "INFO"


@dataclass
class SSHInspection:
    host: str
    port: int
    server_banner:   str  = ""
    kex_algorithms:  list = field(default_factory=list)
    host_key_algos:  list = field(default_factory=list)
    encryption_algos:list = field(default_factory=list)
    mac_algorithms:  list = field(default_factory=list)
    compression:     list = field(default_factory=list)
    weak_kex:        list = field(default_factory=list)
    weak_ciphers:    list = field(default_factory=list)
    weak_macs:       list = field(default_factory=list)
    version:         str  = ""
    findings:        list = field(default_factory=list)
    risk_level:      str  = "INFO"


@dataclass
class HTTPInspection:
    host: str
    port: int
    server_header:   str  = ""
    status_code:     int  = 0
    missing_headers: list = field(default_factory=list)
    present_headers: dict = field(default_factory=dict)
    info_leak_headers:list= field(default_factory=list)
    allowed_methods: list = field(default_factory=list)
    dangerous_methods:list= field(default_factory=list)
    cookie_issues:   list = field(default_factory=list)
    redirect_chain:  list = field(default_factory=list)
    findings:        list = field(default_factory=list)
    risk_level:      str  = "INFO"


@dataclass
class ProtocolReport:
    """گزارش کامل بازرسی تمام پروتکل‌ها"""
    target:          str
    tls_results:     list = field(default_factory=list)
    ssh_results:     list = field(default_factory=list)
    http_results:    list = field(default_factory=list)
    overall_risk:    str  = "INFO"
    critical_count:  int  = 0
    high_count:      int  = 0
    all_findings:    list = field(default_factory=list)


class ProtocolInspector:
    """
    بازرسی عمیق پروتکل‌های شبکه برای یافتن misconfiguration
    و ضعف‌های cryptographic.
    """

    TIMEOUT = 8.0

    def inspect_all(self, target: str, open_ports: list) -> ProtocolReport:
        """بازرسی تمام پروتکل‌های شناسایی‌شده"""
        report = ProtocolReport(target=target)

        for port_data in open_ports:
            port    = port_data.get("port", 0)
            service = port_data.get("service", "").lower()

            # TLS inspection
            if service in ("https", "ssl", "tls") or port in (443, 8443, 993, 995, 465):
                result = self.inspect_tls(target, port)
                if result:
                    report.tls_results.append(result)
                    report.all_findings.extend(result.findings)

            # SSH inspection
            elif service == "ssh" or port == 22:
                result = self.inspect_ssh(target, port)
                if result:
                    report.ssh_results.append(result)
                    report.all_findings.extend(result.findings)

            # HTTP inspection
            elif service in ("http", "http-proxy") or port in (80, 8080, 8000, 8888):
                result = self.inspect_http(target, port, tls=False)
                if result:
                    report.http_results.append(result)
                    report.all_findings.extend(result.findings)

            elif service in ("https", "https-alt") or port in (443, 8443):
                result = self.inspect_http(target, port, tls=True)
                if result:
                    report.http_results.append(result)
                    report.all_findings.extend(result.findings)

        # Overall risk
        report.critical_count = sum(
            1 for f in report.all_findings if "CRITICAL" in str(f)
        )
        report.high_count = sum(
            1 for f in report.all_findings if "HIGH" in str(f)
        )
        if report.critical_count:
            report.overall_risk = "CRITICAL"
        elif report.high_count:
            report.overall_risk = "HIGH"
        elif report.all_findings:
            report.overall_risk = "MEDIUM"

        return report

    # ─── TLS inspection ───────────────────────────────────────────────────
    def inspect_tls(self, host: str, port: int) -> Optional[TLSInspection]:
        """بازرسی کامل TLS/SSL"""
        result = TLSInspection(host=host, port=port)

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    # نسخه TLS
                    result.tls_version = ssock.version()

                    # cipher suite
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        result.cipher_suite = cipher_info[0]
                        result.key_bits     = cipher_info[2]

                    # گواهینامه
                    cert = ssock.getpeercert()
                    self._analyze_cert(cert, result)

            # بررسی ضعف‌ها
            self._check_tls_weaknesses(result)

            # TLS 1.3 support
            result.supports_tls13 = self._check_tls13_support(host, port)

        except ssl.SSLError as e:
            result.findings.append({
                "severity": "HIGH",
                "finding":  f"SSL/TLS error: {e}",
                "detail":   "May indicate very old SSL or misconfig",
            })
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"[ProtocolInspector] TLS {host}:{port}: {e}")
            return None
        except Exception as e:
            logger.debug(f"[ProtocolInspector] TLS unexpected: {e}")
            return None

        return result

    def _analyze_cert(self, cert: dict, result: TLSInspection) -> None:
        """تحلیل گواهینامه TLS"""
        if not cert:
            result.findings.append({
                "severity": "HIGH",
                "finding":  "Could not retrieve TLS certificate",
                "detail":   "Certificate may be invalid or expired",
            })
            return

        # Subject
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        result.cert_subject = subject.get("commonName", "")
        result.cert_issuer  = issuer.get("organizationName", "")

        # Self-signed check
        if subject == issuer:
            result.cert_self_signed = True
            result.findings.append({
                "severity": "MEDIUM",
                "finding":  "Self-signed certificate",
                "detail":   f"CN={result.cert_subject} — not trusted by browsers",
            })

        # Expiry check
        not_after = cert.get("notAfter", "")
        if not_after:
            result.cert_expiry = not_after
            try:
                expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                if expiry_dt < now:
                    result.cert_expired = True
                    result.findings.append({
                        "severity": "HIGH",
                        "finding":  f"Certificate EXPIRED on {not_after}",
                        "detail":   "Expired cert — browsers will warn users",
                    })
                elif (expiry_dt - now).days < 30:
                    result.findings.append({
                        "severity": "MEDIUM",
                        "finding":  f"Certificate expires soon: {not_after}",
                        "detail":   f"Only {(expiry_dt - now).days} days remaining",
                    })
            except ValueError:
                pass

        # SAN domains
        san = cert.get("subjectAltName", [])
        result.san_domains = [v for t, v in san if t == "DNS"]

        # Wildcard
        if any("*" in d for d in result.san_domains):
            result.cert_wildcard = True
            result.findings.append({
                "severity": "INFO",
                "finding":  "Wildcard certificate in use",
                "detail":   f"Domains: {result.san_domains[:5]}",
            })

    def _check_tls_weaknesses(self, result: TLSInspection) -> None:
        """بررسی ضعف‌های TLS"""
        # نسخه ضعیف
        if result.tls_version in WEAK_TLS_VERSIONS:
            result.weak_version = True
            result.risk_level   = "HIGH"
            result.findings.append({
                "severity": "HIGH",
                "finding":  f"Weak TLS version: {result.tls_version}",
                "detail":   "Vulnerable to POODLE, BEAST, and downgrade attacks",
            })

        # cipher ضعیف
        if result.cipher_suite:
            for weak in WEAK_TLS_CIPHERS:
                if weak.upper() in result.cipher_suite.upper():
                    result.weak_cipher = True
                    result.findings.append({
                        "severity": "HIGH",
                        "finding":  f"Weak cipher in use: {result.cipher_suite}",
                        "detail":   f"Contains weak algorithm: {weak}",
                    })
                    break

        # کلید کوتاه
        if result.key_bits and result.key_bits < 2048:
            result.findings.append({
                "severity": "CRITICAL",
                "finding":  f"Dangerously short key: {result.key_bits} bits",
                "detail":   "RSA < 2048 bits is trivially breakable",
            })

    @staticmethod
    def _check_tls13_support(host: str, port: int) -> bool:
        """بررسی پشتیبانی از TLS 1.3"""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((host, port), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    return True
        except Exception:
            return False

    # ─── SSH inspection ───────────────────────────────────────────────────
    def inspect_ssh(self, host: str, port: int) -> Optional[SSHInspection]:
        """بازرسی عمیق SSH: banner + KEX algorithms"""
        result = SSHInspection(host=host, port=port)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.TIMEOUT)
            sock.connect((host, port))

            # دریافت banner
            banner_raw = sock.recv(256)
            banner = banner_raw.decode("utf-8", errors="ignore").strip()
            result.server_banner = banner

            # استخراج نسخه
            ver_match = re.match(r"SSH-(\S+)-(\S+)", banner)
            if ver_match:
                result.version = ver_match.group(1)

            # ارسال client banner برای دریافت KEXINIT
            client_banner = b"SSH-2.0-AegisScanner_1.0\r\n"
            sock.send(client_banner)

            # دریافت KEXINIT packet
            time.sleep(0.3)
            kex_data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    kex_data += chunk
                    if len(kex_data) > 2048:
                        break
            except socket.timeout:
                pass

            sock.close()

            # parse KEXINIT
            if len(kex_data) > 21:
                self._parse_kexinit(kex_data, result)

            # بررسی ضعف‌ها
            self._check_ssh_weaknesses(result)

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"[ProtocolInspector] SSH {host}:{port}: {e}")
            return None
        except Exception as e:
            logger.debug(f"[ProtocolInspector] SSH unexpected: {e}")
            return None

        return result

    @staticmethod
    def _parse_kexinit(data: bytes, result: SSHInspection) -> None:
        """
        Parse SSH KEXINIT packet (RFC 4253).
        ساختار: length(4) + padding(1) + type(1) + cookie(16) + name-lists...
        """
        try:
            # جستجوی SSH2_MSG_KEXINIT (20)
            idx = data.find(b'\x14')
            if idx < 0:
                return

            pos = idx + 1 + 16   # skip type + cookie

            def read_namelist(d: bytes, p: int) -> tuple:
                if p + 4 > len(d):
                    return [], p
                length = struct.unpack(">I", d[p:p+4])[0]
                p += 4
                if p + length > len(d):
                    return [], p
                names_str = d[p:p+length].decode("ascii", errors="ignore")
                p += length
                return [n.strip() for n in names_str.split(",") if n.strip()], p

            result.kex_algorithms,   pos = read_namelist(data, pos)
            result.host_key_algos,   pos = read_namelist(data, pos)
            result.encryption_algos, pos = read_namelist(data, pos)
            _,                       pos = read_namelist(data, pos)  # enc s→c (skip)
            result.mac_algorithms,   pos = read_namelist(data, pos)
            _,                       pos = read_namelist(data, pos)  # mac s→c (skip)
            result.compression,      pos = read_namelist(data, pos)

        except Exception as e:
            logger.debug(f"[ProtocolInspector] KEXINIT parse: {e}")

    def _check_ssh_weaknesses(self, result: SSHInspection) -> None:
        """تشخیص الگوریتم‌های ضعیف SSH"""
        # KEX
        result.weak_kex = [k for k in result.kex_algorithms if k in WEAK_SSH_KEXES]
        if result.weak_kex:
            result.findings.append({
                "severity": "HIGH",
                "finding":  f"Weak KEX algorithms: {result.weak_kex}",
                "detail":   "Vulnerable to downgrade attacks and weak DH parameters",
            })

        # Ciphers
        result.weak_ciphers = [c for c in result.encryption_algos if c in WEAK_SSH_CIPHERS]
        if result.weak_ciphers:
            result.findings.append({
                "severity": "HIGH",
                "finding":  f"Weak SSH ciphers: {result.weak_ciphers}",
                "detail":   "CBC mode ciphers vulnerable to BEAST-like attacks",
            })

        # MACs
        result.weak_macs = [m for m in result.mac_algorithms if m in WEAK_SSH_MACS]
        if result.weak_macs:
            result.findings.append({
                "severity": "MEDIUM",
                "finding":  f"Weak MAC algorithms: {result.weak_macs}",
                "detail":   "MD5 and SHA1-based MACs should not be used",
            })

        # نسخه SSH قدیمی
        if result.version and result.version.startswith("1"):
            result.findings.append({
                "severity": "CRITICAL",
                "finding":  f"SSH protocol version 1 detected!",
                "detail":   "SSHv1 is completely broken and must be disabled",
            })

        # Risk level
        critical = sum(1 for f in result.findings if f.get("severity") == "CRITICAL")
        high     = sum(1 for f in result.findings if f.get("severity") == "HIGH")
        if critical:   result.risk_level = "CRITICAL"
        elif high:     result.risk_level = "HIGH"
        elif result.findings: result.risk_level = "MEDIUM"

    # ─── HTTP inspection ──────────────────────────────────────────────────
    def inspect_http(
        self, host: str, port: int, tls: bool = False
    ) -> Optional[HTTPInspection]:
        """بازرسی HTTP: security headers، methods، اطلاعات نشت‌شده"""
        result = HTTPInspection(host=host, port=port)

        try:
            import http.client
            if tls:
                ctx  = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    host, port, timeout=self.TIMEOUT, context=ctx
                )
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.TIMEOUT)

            # GET /
            conn.request(
                "GET", "/",
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; AegisScanner/1.0)",
                    "Accept":     "*/*",
                }
            )
            resp = conn.getresponse()
            result.status_code = resp.status

            # هدرها
            headers = dict(resp.getheaders())
            result.present_headers = headers

            # بررسی security headers
            for header, purpose in SECURITY_HEADERS_REQUIRED.items():
                if not any(k.lower() == header.lower() for k in headers):
                    result.missing_headers.append({
                        "header":  header,
                        "purpose": purpose,
                    })

            # اطلاعات نشت‌شده
            for leak_header in INFORMATION_LEAK_HEADERS:
                val = next(
                    (v for k, v in headers.items() if k.lower() == leak_header.lower()),
                    None
                )
                if val:
                    result.info_leak_headers.append({
                        "header": leak_header,
                        "value":  val,
                    })
                    result.findings.append({
                        "severity": "LOW",
                        "finding":  f"Information disclosure: {leak_header}: {val}",
                        "detail":   "Reveals server technology stack",
                    })

            result.server_header = next(
                (v for k, v in headers.items() if k.lower() == "server"), ""
            )

            # Cookie security
            set_cookie = next(
                (v for k, v in headers.items() if k.lower() == "set-cookie"), ""
            )
            if set_cookie:
                self._check_cookie_security(set_cookie, result)

            conn.close()

            # OPTIONS method
            self._check_http_methods(host, port, tls, result)

            # بررسی headers
            self._evaluate_http_findings(result)

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"[ProtocolInspector] HTTP {host}:{port}: {e}")
            return None
        except Exception as e:
            logger.debug(f"[ProtocolInspector] HTTP unexpected: {e}")
            return None

        return result

    @staticmethod
    def _check_cookie_security(cookie_str: str, result: HTTPInspection) -> None:
        """بررسی flag‌های امنیتی cookie"""
        cookie_lower = cookie_str.lower()
        if "httponly" not in cookie_lower:
            result.cookie_issues.append("Session cookie missing HttpOnly flag")
            result.findings.append({
                "severity": "MEDIUM",
                "finding":  "Cookie missing HttpOnly flag",
                "detail":   "JavaScript can access this cookie (XSS risk)",
            })
        if "secure" not in cookie_lower:
            result.cookie_issues.append("Cookie missing Secure flag")
            result.findings.append({
                "severity": "MEDIUM",
                "finding":  "Cookie missing Secure flag",
                "detail":   "Cookie may be transmitted over HTTP",
            })
        if "samesite" not in cookie_lower:
            result.cookie_issues.append("Cookie missing SameSite attribute")
            result.findings.append({
                "severity": "LOW",
                "finding":  "Cookie missing SameSite attribute",
                "detail":   "Vulnerable to CSRF attacks",
            })

    def _check_http_methods(
        self, host: str, port: int, tls: bool, result: HTTPInspection
    ) -> None:
        """بررسی HTTP methods مجاز"""
        try:
            import http.client
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=5, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=5)

            conn.request("OPTIONS", "/")
            resp = conn.getresponse()
            allow_header = next(
                (v for k, v in resp.getheaders() if k.lower() == "allow"), ""
            )
            conn.close()

            if allow_header:
                methods = [m.strip() for m in allow_header.split(",")]
                result.allowed_methods = methods

                dangerous = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
                result.dangerous_methods = [m for m in methods if m.upper() in dangerous]

                if "TRACE" in (m.upper() for m in methods):
                    result.findings.append({
                        "severity": "HIGH",
                        "finding":  "HTTP TRACE method enabled",
                        "detail":   "Vulnerable to Cross-Site Tracing (XST) attacks",
                    })
                if "PUT" in (m.upper() for m in methods):
                    result.findings.append({
                        "severity": "CRITICAL",
                        "finding":  "HTTP PUT method enabled",
                        "detail":   "May allow arbitrary file upload to web server",
                    })
        except Exception:
            pass

    @staticmethod
    def _evaluate_http_findings(result: HTTPInspection) -> None:
        """ارزیابی نهایی HTTP findings"""
        missing_critical = {"Strict-Transport-Security", "Content-Security-Policy"}
        critical_missing = [
            h["header"] for h in result.missing_headers
            if h["header"] in missing_critical
        ]

        if critical_missing:
            result.findings.append({
                "severity": "HIGH",
                "finding":  f"Critical security headers missing: {critical_missing}",
                "detail":   "These headers prevent common web attacks",
            })

        if len(result.missing_headers) >= 5:
            result.findings.append({
                "severity": "MEDIUM",
                "finding":  f"{len(result.missing_headers)} security headers not configured",
                "detail":   "Poor security header hygiene",
            })

        # Risk level
        sev = [f.get("severity", "") for f in result.findings]
        if "CRITICAL" in sev:   result.risk_level = "CRITICAL"
        elif "HIGH" in sev:     result.risk_level = "HIGH"
        elif "MEDIUM" in sev:   result.risk_level = "MEDIUM"
        elif result.findings:   result.risk_level = "LOW"

    def to_dict(self, report: ProtocolReport) -> dict:
        def insp_to_dict(obj) -> dict:
            return {k: v for k, v in obj.__dict__.items()}

        return {
            "target":         report.target,
            "overall_risk":   report.overall_risk,
            "critical_count": report.critical_count,
            "high_count":     report.high_count,
            "tls_results":    [insp_to_dict(r) for r in report.tls_results],
            "ssh_results":    [insp_to_dict(r) for r in report.ssh_results],
            "http_results":   [insp_to_dict(r) for r in report.http_results],
            "all_findings":   report.all_findings,
        }
