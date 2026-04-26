# aegis-scanner/modules/port_analyzer.py
"""
ماژول تحلیل پورت‌های باز.
وظیفه: تبدیل لیست خام پورت‌های باز به تحلیل ساختارمند امنیتی.
تمام داده‌ها از خروجی واقعی Nmap استخراج می‌شوند.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from config.constants import (
    CVSS_CRITICAL, CVSS_HIGH, CVSS_MEDIUM, CVSS_LOW
)

logger = logging.getLogger(__name__)


# ─── Known dangerous service signatures ──────────────────────────────────────
# این داده‌ها از SANS و CIS benchmarks گردآوری شده‌اند
RISKY_SERVICES = {
    "ftp":       {"risk": "HIGH",   "reason": "Plaintext credentials, anonymous login risk"},
    "telnet":    {"risk": "CRITICAL","reason": "Unencrypted remote access"},
    "rsh":       {"risk": "CRITICAL","reason": "No authentication, remote shell"},
    "rlogin":    {"risk": "CRITICAL","reason": "Trust-based auth, no encryption"},
    "rexec":     {"risk": "CRITICAL","reason": "Unencrypted remote execution"},
    "smtp":      {"risk": "MEDIUM",  "reason": "Open relay, user enumeration"},
    "snmp":      {"risk": "HIGH",    "reason": "Community string exposure, network info leak"},
    "netbios-ssn":{"risk":"HIGH",    "reason": "SMB attacks, null session, EternalBlue"},
    "microsoft-ds":{"risk":"HIGH",   "reason": "SMB, EternalBlue, ransomware vector"},
    "rdp":       {"risk": "HIGH",    "reason": "BlueKeep, brute force, man-in-the-middle"},
    "vnc":       {"risk": "HIGH",    "reason": "Often misconfigured, no auth or weak auth"},
    "x11":       {"risk": "HIGH",    "reason": "Display hijacking if exposed"},
    "mysql":     {"risk": "MEDIUM",  "reason": "Exposed DB, credential attacks"},
    "mssql":     {"risk": "MEDIUM",  "reason": "SA account abuse, xp_cmdshell"},
    "postgresql": {"risk": "MEDIUM", "reason": "pg_hba.conf misconfig"},
    "mongodb":   {"risk": "HIGH",    "reason": "Often no auth by default"},
    "redis":     {"risk": "HIGH",    "reason": "No auth by default, RCE via config write"},
    "memcache":  {"risk": "HIGH",    "reason": "No auth, DDoS amplification vector"},
    "elasticsearch":{"risk":"HIGH",  "reason": "Unauthenticated data access, RCE scripts"},
    "http":      {"risk": "MEDIUM",  "reason": "Web attack surface, check for CMS vulns"},
    "https":     {"risk": "LOW",     "reason": "Encrypted but check TLS version and certs"},
    "ssh":       {"risk": "LOW",     "reason": "Check version, key-only auth recommended"},
    "nfs":       {"risk": "HIGH",    "reason": "exports misconfiguration, file system access"},
    "rpcbind":   {"risk": "MEDIUM",  "reason": "RPC service exposure, pivot point"},
    "ldap":      {"risk": "MEDIUM",  "reason": "Directory info leak, anonymous bind"},
    "kerberos":  {"risk": "MEDIUM",  "reason": "AS-REP roasting, Kerberoasting"},
    "smb":       {"risk": "HIGH",    "reason": "Multiple critical RCE vulnerabilities"},
    "msrpc":     {"risk": "MEDIUM",  "reason": "RPC endpoint mapper, DCOM attacks"},
    "winrm":     {"risk": "HIGH",    "reason": "Remote PowerShell execution"},
    # ─── Databases ───────────────────────────────────────────────────────
    "oracle":    {"risk": "MEDIUM",  "reason": "DB exposure, default accounts (scott/tiger)"},
    "postgresql":{"risk": "MEDIUM",  "reason": "pg_hba.conf misconfig, trust auth"},
    "cassandra": {"risk": "HIGH",    "reason": "No auth by default, RCE via UDF"},
    "couchdb":   {"risk": "HIGH",    "reason": "Admin party mode (no auth) on default install"},
    "rethinkdb": {"risk": "HIGH",    "reason": "No auth by default, web admin exposed"},
    "arangodb":  {"risk": "HIGH",    "reason": "Default no-auth, web UI exposed"},
    "neo4j":     {"risk": "HIGH",    "reason": "No auth default, bolt protocol exposed"},
    # ─── Message Queues ──────────────────────────────────────────────────
    "amqp":      {"risk": "MEDIUM",  "reason": "RabbitMQ — guest/guest default creds"},
    "mqtt":      {"risk": "HIGH",    "reason": "IoT protocol, often no auth, data interception"},
    "kafka":     {"risk": "HIGH",    "reason": "No auth by default, data access, pivot"},
    "zookeeper": {"risk": "HIGH",    "reason": "No auth, full cluster control exposure"},
    "activemq":  {"risk": "HIGH",    "reason": "CVE-2023-46604 RCE, default admin/admin"},
    # ─── DevOps / Cloud ──────────────────────────────────────────────────
    "docker":    {"risk": "CRITICAL","reason": "Unauthenticated Docker API = full host RCE"},
    "kubernetes":{"risk": "CRITICAL","reason": "K8s API server — cluster takeover"},
    "etcd":      {"risk": "CRITICAL","reason": "No auth default, full cluster secrets exposure"},
    "prometheus":{"risk": "MEDIUM",  "reason": "Metrics exposure, potential SSRF"},
    "grafana":   {"risk": "MEDIUM",  "reason": "CVE-2021-43798 path traversal, default creds"},
    # ─── Industrial ──────────────────────────────────────────────────────
    "modbus":    {"risk": "CRITICAL","reason": "SCADA/ICS — no auth, direct PLC control"},
    "s7comm":    {"risk": "CRITICAL","reason": "Siemens S7 — Stuxnet vector, no auth"},
    "dnp3":      {"risk": "CRITICAL","reason": "Industrial control, no encryption/auth"},
    "bacnet":    {"risk": "HIGH",    "reason": "Building automation, no auth"},
    # ─── Network ─────────────────────────────────────────────────────────
    "rsync":     {"risk": "HIGH",    "reason": "File system access, anonymous read/write"},
    "nfs":       {"risk": "HIGH",    "reason": "exports misconfiguration, host mount"},
    "tftp":      {"risk": "HIGH",    "reason": "No auth, read/write arbitrary files"},
    "finger":    {"risk": "MEDIUM",  "reason": "User enumeration"},
    "rpcbind":   {"risk": "MEDIUM",  "reason": "RPC pivot, NFS/NIS exposure"},
    "ident":     {"risk": "LOW",     "reason": "User identification, info disclosure"},
    "sip":       {"risk": "MEDIUM",  "reason": "VoIP interception, toll fraud"},
}

STANDARD_PORTS = {
    # ─── Remote Access ──────────────────────────────────────────────────
    21:    "ftp",          22:    "ssh",          23:    "telnet",
    513:   "rlogin",       514:   "rsh",          512:   "rexec",
    3389:  "rdp",          5900:  "vnc",          5901:  "vnc",
    5902:  "vnc",          5800:  "vnc-http",     2222:  "ssh-alt",
    2200:  "ssh-alt",      8022:  "ssh-alt",      4444:  "krb524",
    # ─── Web ────────────────────────────────────────────────────────────
    80:    "http",         443:   "https",         8080:  "http-proxy",
    8443:  "https-alt",    8000:  "http-alt",      8008:  "http-alt",
    8888:  "http-alt",     8888:  "http-alt",      9090:  "http-alt",
    3000:  "http-dev",     3001:  "http-dev",      4000:  "http-dev",
    5000:  "http-dev",     7000:  "http-dev",      7001:  "http-dev",
    8180:  "http-alt",     8181:  "http-alt",      8282:  "http-alt",
    8383:  "http-alt",     8484:  "http-alt",      8585:  "http-alt",
    9443:  "https-alt",    10443: "https-alt",     4848:  "glassfish",
    # ─── Mail ───────────────────────────────────────────────────────────
    25:    "smtp",         465:   "smtps",          587:   "smtp",
    110:   "pop3",         995:   "pop3s",           143:   "imap",
    993:   "imaps",
    # ─── DNS ────────────────────────────────────────────────────────────
    53:    "dns",          5353:  "mdns",            853:   "dns-over-tls",
    # ─── File Transfer ──────────────────────────────────────────────────
    20:    "ftp-data",     69:    "tftp",             989:   "ftps",
    990:   "ftps",         115:   "sftp",             2049:  "nfs",
    445:   "microsoft-ds", 139:   "netbios-ssn",      137:   "netbios-ns",
    138:   "netbios-dgm",
    # ─── Database ───────────────────────────────────────────────────────
    1433:  "mssql",        1434:  "mssql-monitor",   1521:  "oracle",
    1526:  "oracle-alt",   3306:  "mysql",            5432:  "postgresql",
    5433:  "postgresql",   27017: "mongodb",          27018: "mongodb",
    27019: "mongodb",      6379:  "redis",            6380:  "redis",
    7379:  "redis-alt",    11211: "memcache",         9042:  "cassandra",
    9160:  "cassandra",    7000:  "cassandra-inter",  7001:  "cassandra-ssl",
    9200:  "elasticsearch",9300:  "elasticsearch",    5984:  "couchdb",
    5985:  "couchdb-alt",  28015: "rethinkdb",        28080: "rethinkdb",
    3050:  "firebird",     5000:  "sybase",           50000: "db2",
    50001: "db2",          1583:  "pervasivedb",      8529:  "arangodb",
    7473:  "neo4j-https",  7474:  "neo4j",            6432:  "pgbouncer",
    # ─── Message Queues / Middleware ───────────────────────────────────
    5672:  "amqp",         5671:  "amqps",            15672: "rabbitmq-mgmt",
    9092:  "kafka",        2181:  "zookeeper",        2182:  "zookeeper",
    4369:  "epmd",         61613: "stomp",            61614: "stomp-ssl",
    61616: "activemq",     8161:  "activemq-web",     1883:  "mqtt",
    8883:  "mqtts",        4222:  "nats",             8222:  "nats-monitor",
    # ─── Monitoring / DevOps ───────────────────────────────────────────
    9090:  "prometheus",   3000:  "grafana",           9091:  "prometheus-push",
    9093:  "alertmanager", 9094:  "alertmanager",      8086:  "influxdb",
    8088:  "influxdb-rpc", 2003:  "graphite",          2004:  "graphite",
    4242:  "opentsdb",     8125:  "statsd",            8126:  "statsd",
    9200:  "kibana",       5601:  "kibana",            9600:  "logstash",
    24224: "fluentd",      2379:  "etcd-client",       2380:  "etcd-peer",
    6443:  "kubernetes",   10250: "kubelet",           10255: "kubelet-ro",
    10256: "kube-proxy",   30000: "nodeport-min",      32767: "nodeport-max",
    2376:  "docker-tls",   2375:  "docker",            5000:  "docker-reg",
    5001:  "docker-reg",
    # ─── Directory / Auth ──────────────────────────────────────────────
    389:   "ldap",         636:   "ldaps",             88:    "kerberos",
    464:   "kerberos-chpw",3268:  "ldap-gc",           3269:  "ldaps-gc",
    # ─── Windows / AD ──────────────────────────────────────────────────
    135:   "msrpc",        593:   "http-rpc-epmap",    5985:  "winrm",
    5986:  "winrm-ssl",    49152: "msrpc-ephem",       47001: "winrm-alt",
    # ─── Network Services ──────────────────────────────────────────────
    161:   "snmp",         162:   "snmp-trap",          111:   "rpcbind",
    179:   "bgp",          520:   "rip",                521:   "ripng",
    1723:  "pptp",         1194:  "openvpn",            500:   "isakmp",
    4500:  "ipsec-nat",    1701:  "l2tp",               1080:  "socks",
    3128:  "squid",        8118:  "privoxy",
    # ─── Industrial / SCADA ────────────────────────────────────────────
    102:   "s7comm",       502:   "modbus",             503:   "modbus",
    2404:  "iec-104",      20000: "dnp3",               44818: "ethernetip",
    47808: "bacnet",       1911:  "niagara-fox",        4911:  "niagara-fox-ssl",
    # ─── VoIP ──────────────────────────────────────────────────────────
    5060:  "sip",          5061:  "sip-tls",            1720:  "h323",
    2427:  "mgcp",         2727:  "mgcp-gateway",
    # ─── Game / P2P ────────────────────────────────────────────────────
    25565: "minecraft",    27015: "steam",              27016: "steam",
    # ─── Misc ───────────────────────────────────────────────────────────
    79:    "finger",       113:   "ident",              177:   "xdmcp",
    6000:  "x11",          6001:  "x11",                6002:  "x11",
    514:   "syslog",       6514:  "syslog-tls",         873:   "rsync",
    9418:  "git",          3690:  "svn",                8834:  "nessus",
    9390:  "openvas",      9391:  "openvas",
}

NON_STANDARD_PORTS = set(range(49152, 65536))  # ephemeral range

# ─── پورت‌هایی که معمولاً نشانه backdoor یا C2 هستند ───────────────────────
SUSPICIOUS_PORTS = {
    4444, 4445, 1234, 1337, 31337, 12345, 54321, 6666, 6667, 6668, 6669,
    1024, 1025, 5555, 7777, 8888, 9999, 2323, 2332, 4321, 9876, 65535,
    666, 1111, 2222, 3333, 4321, 9001, 9002, 9003,
}


@dataclass
class PortFinding:
    """نتیجه تحلیل یک پورت"""
    host: str
    port: int
    proto: str
    service: str
    product: str
    version: str
    risk_level: str
    risk_reasons: list
    is_non_standard: bool
    has_scripts: bool
    script_findings: dict
    cpe: str
    notes: list = field(default_factory=list)


@dataclass
class PortAnalysisResult:
    """نتیجه کامل تحلیل تمام پورت‌ها"""
    total_open: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: list
    attack_surface_score: float     # 0-10
    non_standard_ports: list
    exposed_databases: list
    exposed_remote_access: list
    summary: str


class PortAnalyzer:
    """
    تحلیل عمیق پورت‌های باز بر اساس داده‌های واقعی Nmap.
    
    هیچ CVE یا آسیب‌پذیری مصنوعی تولید نمی‌کند.
    تمام ریسک‌ها از پایگاه داده ثابت RISKY_SERVICES استخراج می‌شوند.
    """

    def analyze(self, open_ports: list) -> dict:
        """
        تحلیل کامل لیست پورت‌های باز.
        
        Args:
            open_ports: لیست dict از NmapController.run_scan()
        Returns:
            dict قابل serialization با تمام یافته‌ها
        """
        if not open_ports:
            return self._empty_result()

        findings  = []
        non_std   = []
        databases = []
        remote_access = []

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for port_data in open_ports:
            finding = self._analyze_single_port(port_data)
            findings.append(finding)

            # counter update
            lvl = finding.risk_level
            counts[lvl] = counts.get(lvl, 0) + 1

            # categorization
            if finding.is_non_standard:
                non_std.append({"port": finding.port, "service": finding.service})

            if finding.service in {"mysql", "mssql", "postgresql", "mongodb",
                                   "redis", "elasticsearch", "memcache", "oracle"}:
                databases.append({
                    "port": finding.port,
                    "service": finding.service,
                    "version": finding.version,
                    "risk": finding.risk_level,
                })

            if finding.service in {"ssh", "rdp", "vnc", "telnet",
                                   "rsh", "rlogin", "winrm", "x11"}:
                remote_access.append({
                    "port": finding.port,
                    "service": finding.service,
                    "version": finding.version,
                    "risk": finding.risk_level,
                })

        # سورت بر اساس ریسک
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: risk_order.get(f.risk_level, 5))

        attack_score = self._compute_attack_surface_score(counts, len(open_ports))
        summary      = self._generate_summary(counts, len(open_ports), attack_score)

        result = PortAnalysisResult(
            total_open=len(open_ports),
            critical_count=counts["CRITICAL"],
            high_count=counts["HIGH"],
            medium_count=counts["MEDIUM"],
            low_count=counts["LOW"],
            findings=findings,
            attack_surface_score=attack_score,
            non_standard_ports=non_std,
            exposed_databases=databases,
            exposed_remote_access=remote_access,
            summary=summary,
        )

        return self._to_dict(result)

    # ─── Single port analysis ──────────────────────────────────────────────
    def _analyze_single_port(self, port_data: dict) -> PortFinding:
        port    = port_data.get("port", 0)
        proto   = port_data.get("proto", "tcp")
        service = port_data.get("service", "unknown")
        product = port_data.get("product", "")
        version = port_data.get("version", "")
        cpe     = port_data.get("cpe", "")
        scripts = port_data.get("scripts", {})
        host    = port_data.get("host", "")

        # ریسک از پایگاه داده
        svc_lower = service.lower()
        risk_info = RISKY_SERVICES.get(svc_lower, None)

        # بررسی با نام product نیز
        if not risk_info and product:
            for svc_key in RISKY_SERVICES:
                if svc_key in product.lower():
                    risk_info = RISKY_SERVICES[svc_key]
                    break

        risk_level   = risk_info["risk"] if risk_info else "INFO"
        risk_reasons = [risk_info["reason"]] if risk_info else []

        # بررسی پورت‌های non-standard
        expected_svc = STANDARD_PORTS.get(port)
        is_non_std   = False
        if expected_svc and expected_svc != svc_lower:
            is_non_std = True
            risk_reasons.append(
                f"Port {port} typically runs {expected_svc}, "
                f"but detected as {service} — possible port knocking or misconfiguration"
            )
            # بالا بردن ریسک
            if risk_level in ("LOW", "INFO"):
                risk_level = "MEDIUM"

        if port in NON_STANDARD_PORTS:
            is_non_std = True
            risk_reasons.append("Non-standard/ephemeral port range — investigate purpose")

        # تشخیص پورت‌های مشکوک (backdoor / C2 شناخته‌شده)
        if port in SUSPICIOUS_PORTS:
            is_non_std = True
            if risk_level in ("INFO", "LOW", "MEDIUM"):
                risk_level = "CRITICAL"
            risk_reasons.append(
                f"Port {port} is commonly used by backdoors, RATs, or C2 frameworks "
                "(e.g. Meterpreter default listeners, netcat) — investigate immediately"
            )

        # تحلیل script results
        script_findings = self._analyze_scripts(scripts)
        has_scripts = bool(script_findings)
        if script_findings.get("critical_scripts"):
            risk_level = "CRITICAL"
            risk_reasons.extend(script_findings["critical_scripts"])

        # نکات نسخه
        notes = []
        if version:
            notes.append(f"Detected version: {product} {version} — check NVD for CVEs")
        if cpe:
            notes.append(f"CPE: {cpe} — use for precise CVE lookup")

        return PortFinding(
            host=host, port=port, proto=proto,
            service=service, product=product, version=version,
            risk_level=risk_level, risk_reasons=risk_reasons,
            is_non_standard=is_non_std, has_scripts=has_scripts,
            script_findings=script_findings, cpe=cpe, notes=notes
        )

    # ─── Script analysis ──────────────────────────────────────────────────
    @staticmethod
    def _analyze_scripts(scripts: dict) -> dict:
        """تحلیل نتایج Nmap scripts برای یافتن یافته‌های حیاتی"""
        if not scripts:
            return {}

        result: dict = {"raw": scripts, "critical_scripts": []}

        # بررسی نشانه‌های حیاتی در خروجی scripts
        critical_keywords = [
            "VULNERABLE", "CVE-", "RCE", "remote code execution",
            "authentication bypass", "SQL injection", "unauthenticated",
        ]

        for script_name, output in scripts.items():
            output_str = str(output).lower()
            for kw in critical_keywords:
                if kw.lower() in output_str:
                    result["critical_scripts"].append(
                        f"Script '{script_name}' found: {kw}"
                    )
                    break

        return result

    # ─── Scoring ──────────────────────────────────────────────────────────
    @staticmethod
    def _compute_attack_surface_score(counts: dict, total: int) -> float:
        """
        محاسبه امتیاز attack surface (0-10).
        فرمول: وزن‌دهی بر اساس severity + تعداد پورت‌های باز
        """
        score = (
            counts.get("CRITICAL", 0) * 3.0 +
            counts.get("HIGH", 0)     * 2.0 +
            counts.get("MEDIUM", 0)   * 1.0 +
            counts.get("LOW", 0)      * 0.5
        )
        # نرمال‌سازی به 0-10
        normalized = min(score / max(total, 1) * 3, 10.0)
        return round(normalized, 1)

    @staticmethod
    def _generate_summary(counts: dict, total: int, score: float) -> str:
        """تولید خلاصه متنی"""
        if total == 0:
            return "No open ports detected."
        parts = []
        if counts.get("CRITICAL"):
            parts.append(f"{counts['CRITICAL']} CRITICAL")
        if counts.get("HIGH"):
            parts.append(f"{counts['HIGH']} HIGH")
        if counts.get("MEDIUM"):
            parts.append(f"{counts['MEDIUM']} MEDIUM")
        severity_str = ", ".join(parts) if parts else "no high-risk"
        return (
            f"{total} open port(s) found with {severity_str} severity findings. "
            f"Attack surface score: {score}/10."
        )

    # ─── Serialization ────────────────────────────────────────────────────
    @staticmethod
    def _to_dict(result: PortAnalysisResult) -> dict:
        """تبدیل PortAnalysisResult به dict ساده"""
        findings_dicts = []
        for f in result.findings:
            findings_dicts.append({
                "host":           f.host,
                "port":           f.port,
                "proto":          f.proto,
                "service":        f.service,
                "product":        f.product,
                "version":        f.version,
                "risk_level":     f.risk_level,
                "risk_reasons":   f.risk_reasons,
                "is_non_standard":f.is_non_standard,
                "has_scripts":    f.has_scripts,
                "script_findings":f.script_findings,
                "cpe":            f.cpe,
                "notes":          f.notes,
            })
        return {
            "total_open":           result.total_open,
            "critical_count":       result.critical_count,
            "high_count":           result.high_count,
            "medium_count":         result.medium_count,
            "low_count":            result.low_count,
            "attack_surface_score": result.attack_surface_score,
            "non_standard_ports":   result.non_standard_ports,
            "exposed_databases":    result.exposed_databases,
            "exposed_remote_access":result.exposed_remote_access,
            "summary":              result.summary,
            "findings":             findings_dicts,
        }

    @staticmethod
    def _empty_result() -> dict:
        return {
            "total_open": 0, "critical_count": 0, "high_count": 0,
            "medium_count": 0, "low_count": 0,
            "attack_surface_score": 0.0,
            "non_standard_ports": [], "exposed_databases": [],
            "exposed_remote_access": [],
            "summary": "No open ports detected.",
            "findings": [],
        }
