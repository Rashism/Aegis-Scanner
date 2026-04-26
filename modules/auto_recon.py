# aegis-scanner/modules/auto_recon.py
"""
Smart Auto-Recon Loop — Aegis-Scanner v4
=========================================
بعد از اسکن اولیه، ابزار خودش تصمیم می‌گیرد قدم بعدی چیست.
هر سرویس یافت‌شده یک handler دارد که اسکن عمیق‌تر انجام می‌دهد.

مثال:
  Redis یافت شد → بررسی authentication + دسترسی بدون رمز
  SMB یافت شد   → MS17-010 + enum shares + enum users
  HTTP یافت شد  → screenshot + admin panel hunt + dir bruteforce hint
"""

import logging
import subprocess
import socket
import ssl
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class ReconFinding:
    service:     str
    port:        int
    check_name:  str
    severity:    str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    result:      str
    raw_output:  str = ""
    command_run: str = ""


@dataclass
class AutoReconResult:
    target:      str
    total_checks: int = 0
    findings:    list = field(default_factory=list)
    critical_findings: list = field(default_factory=list)
    high_findings:     list = field(default_factory=list)
    skipped:     list = field(default_factory=list)
    errors:      list = field(default_factory=list)


class AutoReconEngine:
    """
    موتور recon خودکار — هر سرویس handler اختصاصی دارد.
    تمام چک‌ها passive یا حداقل-invasive هستند.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        # نگاشت service → handler
        self._handlers: dict[str, Callable] = {
            "redis":         self._check_redis,
            "mongodb":       self._check_mongodb,
            "elasticsearch": self._check_elasticsearch,
            "mysql":         self._check_mysql,
            "postgresql":    self._check_postgresql,
            "ftp":           self._check_ftp,
            "smtp":          self._check_smtp,
            "smb":           self._check_smb,
            "microsoft-ds":  self._check_smb,
            "http":          self._check_http,
            "https":         self._check_https,
            "ssh":           self._check_ssh,
            "telnet":        self._check_telnet,
            "vnc":           self._check_vnc,
            "snmp":          self._check_snmp,
            "docker":        self._check_docker,
            "kubernetes":    self._check_kubernetes,
            "memcache":      self._check_memcached,
            "cassandra":     self._check_cassandra,
            "zookeeper":     self._check_zookeeper,
        }

    def run(
        self, target: str, open_ports: list,
        progress_cb: Optional[Callable] = None
    ) -> AutoReconResult:
        """اجرای recon خودکار روی تمام سرویس‌های یافت‌شده"""
        result = AutoReconResult(target=target)

        if not open_ports:
            return result

        for port_info in open_ports:
            port    = port_info.get("port", 0)
            service = port_info.get("service", "").lower()

            handler = self._find_handler(service)
            if not handler:
                result.skipped.append(f"{service}:{port}")
                continue

            if progress_cb:
                progress_cb(f"Auto-recon: {service}:{port}...")

            try:
                findings = handler(target, port, port_info)
                result.total_checks += 1
                for f in findings:
                    result.findings.append(asdict(f))
                    if f.severity == "CRITICAL":
                        result.critical_findings.append(asdict(f))
                    elif f.severity == "HIGH":
                        result.high_findings.append(asdict(f))
            except Exception as e:
                result.errors.append(f"{service}:{port} — {e}")
                logger.debug(f"[AutoRecon] {service}:{port} error: {e}")

        return result

    def _find_handler(self, service: str) -> Optional[Callable]:
        """پیدا کردن handler مناسب برای یک سرویس"""
        if service in self._handlers:
            return self._handlers[service]
        # partial match
        for key, handler in self._handlers.items():
            if key in service or service in key:
                return handler
        return None

    # ─── Service Handlers ─────────────────────────────────────────────────

    def _check_redis(self, target: str, port: int, info: dict) -> list:
        """بررسی Redis: auth bypass، اطلاعات پیکربندی"""
        findings = []
        try:
            sock = socket.create_connection((target, port), timeout=self.timeout)
            sock.sendall(b"PING\r\n")
            resp = sock.recv(128).decode(errors="ignore")
            sock.close()

            if "+PONG" in resp:
                findings.append(ReconFinding(
                    service="redis", port=port,
                    check_name="No Authentication",
                    severity="CRITICAL",
                    result="Redis responds to PING without authentication",
                    raw_output=resp.strip(),
                    command_run=f"echo 'PING' | nc {target} {port}",
                ))

            # info server
            try:
                sock2 = socket.create_connection((target, port), timeout=self.timeout)
                sock2.sendall(b"INFO server\r\n")
                info_resp = sock2.recv(2048).decode(errors="ignore")
                sock2.close()
                if "redis_version" in info_resp:
                    ver_line = [l for l in info_resp.split("\n") if "redis_version" in l]
                    ver = ver_line[0].split(":")[1].strip() if ver_line else "unknown"
                    findings.append(ReconFinding(
                        service="redis", port=port,
                        check_name="Version Disclosure",
                        severity="INFO",
                        result=f"Redis version: {ver}",
                        raw_output=ver,
                        command_run=f"echo 'INFO server' | nc {target} {port}",
                    ))
            except Exception:
                pass
        except Exception:
            pass
        return findings

    def _check_mongodb(self, target: str, port: int, info: dict) -> list:
        findings = []
        try:
            # MongoDB wire protocol: isMaster command
            msg = (
                b"\x41\x00\x00\x00"  # msg length
                b"\x00\x00\x00\x00"  # requestID
                b"\x00\x00\x00\x00"  # responseTo
                b"\xd4\x07\x00\x00"  # opcode OP_QUERY
                b"\x00\x00\x00\x00"  # flags
                b"admin.$cmd\x00"     # collection
                b"\x00\x00\x00\x00"  # skip
                b"\x01\x00\x00\x00"  # return 1
                b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
            )
            sock = socket.create_connection((target, port), timeout=self.timeout)
            sock.sendall(msg)
            resp = sock.recv(512)
            sock.close()
            if resp and len(resp) > 20:
                findings.append(ReconFinding(
                    service="mongodb", port=port,
                    check_name="No Authentication",
                    severity="CRITICAL",
                    result="MongoDB accessible without authentication",
                    raw_output=f"{len(resp)} bytes received",
                    command_run=f"mongo --host {target} --port {port} --eval 'db.isMaster()'",
                ))
        except Exception:
            pass
        return findings

    def _check_elasticsearch(self, target: str, port: int, info: dict) -> list:
        findings = []
        try:
            import urllib.request
            url = f"http://{target}:{port}/"
            req = urllib.request.urlopen(url, timeout=self.timeout)
            body = req.read(512).decode(errors="ignore")
            if "cluster_name" in body or "version" in body:
                findings.append(ReconFinding(
                    service="elasticsearch", port=port,
                    check_name="Unauthenticated Access",
                    severity="CRITICAL",
                    result="Elasticsearch cluster info accessible without auth",
                    raw_output=body[:200],
                    command_run=f"curl http://{target}:{port}/",
                ))
            # شاخص‌ها
            try:
                req2 = urllib.request.urlopen(
                    f"http://{target}:{port}/_cat/indices", timeout=self.timeout
                )
                idx = req2.read(512).decode(errors="ignore")
                if idx.strip():
                    findings.append(ReconFinding(
                        service="elasticsearch", port=port,
                        check_name="Index Enumeration",
                        severity="HIGH",
                        result=f"Indices visible: {idx[:100]}",
                        raw_output=idx[:200],
                        command_run=f"curl http://{target}:{port}/_cat/indices",
                    ))
            except Exception:
                pass
        except Exception:
            pass
        return findings

    def _check_ftp(self, target: str, port: int, info: dict) -> list:
        findings = []
        try:
            sock = socket.create_connection((target, port), timeout=self.timeout)
            banner = sock.recv(256).decode(errors="ignore")
            # test anonymous login
            sock.sendall(b"USER anonymous\r\n")
            resp1 = sock.recv(128).decode(errors="ignore")
            if "331" in resp1:
                sock.sendall(b"PASS anonymous@\r\n")
                resp2 = sock.recv(128).decode(errors="ignore")
                if "230" in resp2:
                    findings.append(ReconFinding(
                        service="ftp", port=port,
                        check_name="Anonymous Login",
                        severity="HIGH",
                        result="FTP anonymous login accepted",
                        raw_output=resp2.strip(),
                        command_run=f"ftp -n {target} {port}",
                    ))
            sock.close()
            if banner:
                findings.append(ReconFinding(
                    service="ftp", port=port,
                    check_name="Banner",
                    severity="INFO",
                    result=f"FTP banner: {banner.strip()[:100]}",
                    raw_output=banner.strip(),
                    command_run=f"nc {target} {port}",
                ))
        except Exception:
            pass
        return findings

    def _check_smtp(self, target: str, port: int, info: dict) -> list:
        findings = []
        try:
            sock = socket.create_connection((target, port), timeout=self.timeout)
            banner = sock.recv(256).decode(errors="ignore")
            # VRFY test
            sock.sendall(b"VRFY root\r\n")
            vrfy = sock.recv(128).decode(errors="ignore")
            if vrfy.startswith("2"):
                findings.append(ReconFinding(
                    service="smtp", port=port,
                    check_name="User Enumeration (VRFY)",
                    severity="MEDIUM",
                    result="SMTP VRFY command enabled — user enumeration possible",
                    raw_output=vrfy.strip(),
                    command_run=f"echo 'VRFY root' | nc {target} {port}",
                ))
            sock.close()
        except Exception:
            pass
        return findings

    def _check_smb(self, target: str, port: int, info: dict) -> list:
        """بررسی SMB با nmap NSE scripts"""
        findings = []
        scripts = [
            "smb-vuln-ms17-010",
            "smb-security-mode",
            "smb-enum-shares",
        ]
        script_str = ",".join(scripts)
        cmd = ["nmap", "-p", str(port), f"--script={script_str}",
               "--script-timeout", "10s", target]
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            ).stdout

            if "VULNERABLE" in out:
                vuln_lines = [l for l in out.split("\n") if "VULN" in l.upper()]
                findings.append(ReconFinding(
                    service="smb", port=port,
                    check_name="SMB Vulnerability",
                    severity="CRITICAL",
                    result="\n".join(vuln_lines[:5]),
                    raw_output=out[:500],
                    command_run=" ".join(cmd),
                ))
            if "guest" in out.lower() or "anonymous" in out.lower():
                findings.append(ReconFinding(
                    service="smb", port=port,
                    check_name="Guest/Anonymous SMB",
                    severity="HIGH",
                    result="SMB accessible as guest/anonymous",
                    raw_output=out[:300],
                    command_run=" ".join(cmd),
                ))
        except Exception:
            pass
        return findings

    def _check_http(self, target: str, port: int, info: dict) -> list:
        findings = []
        import urllib.request
        import urllib.error
        base = f"http://{target}:{port}"
        # admin panels
        admin_paths = [
            "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
            "/manager/html", "/.env", "/.git/config",
            "/api/v1", "/actuator", "/console", "/debug",
        ]
        for path in admin_paths:
            try:
                req = urllib.request.urlopen(
                    base + path, timeout=self.timeout
                )
                code = req.getcode()
                if code in (200, 301, 302, 401, 403):
                    sev = "HIGH" if code in (200, 301) else "MEDIUM"
                    findings.append(ReconFinding(
                        service="http", port=port,
                        check_name=f"Interesting Path: {path}",
                        severity=sev,
                        result=f"HTTP {code} at {path}",
                        command_run=f"curl -I {base}{path}",
                    ))
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    findings.append(ReconFinding(
                        service="http", port=port,
                        check_name=f"Protected Path: {path}",
                        severity="MEDIUM",
                        result=f"HTTP {e.code} — auth required at {path}",
                        command_run=f"curl -I {base}{path}",
                    ))
            except Exception:
                pass
        return findings

    def _check_https(self, target: str, port: int, info: dict) -> list:
        findings = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    ver  = ssock.version()
                    if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                        findings.append(ReconFinding(
                            service="https", port=port,
                            check_name="Weak TLS Version",
                            severity="HIGH",
                            result=f"Server supports {ver} — considered weak",
                            command_run=f"openssl s_client -connect {target}:{port}",
                        ))
                    if cert:
                        import datetime as dt
                        exp_str = cert.get("notAfter", "")
                        if exp_str:
                            exp = dt.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                            days_left = (exp - dt.datetime.utcnow()).days
                            if days_left < 30:
                                findings.append(ReconFinding(
                                    service="https", port=port,
                                    check_name="Certificate Expiry",
                                    severity="MEDIUM" if days_left > 0 else "HIGH",
                                    result=f"Certificate expires in {days_left} days",
                                    command_run=f"openssl s_client -connect {target}:{port}",
                                ))
        except Exception:
            pass
        # HTTP checks هم اجرا می‌کنیم
        findings += self._check_http(target, port, info)
        return findings

    def _check_ssh(self, target: str, port: int, info: dict) -> list:
        findings = []
        try:
            sock = socket.create_connection((target, port), timeout=self.timeout)
            banner = sock.recv(256).decode(errors="ignore")
            sock.close()
            if banner:
                # نسخه قدیمی OpenSSH
                if "OpenSSH_" in banner:
                    ver_part = banner.split("OpenSSH_")[1].split()[0].rstrip(",")
                    try:
                        major = int(ver_part.split(".")[0])
                        if major < 7:
                            findings.append(ReconFinding(
                                service="ssh", port=port,
                                check_name="Outdated OpenSSH",
                                severity="HIGH",
                                result=f"OpenSSH {ver_part} — multiple known CVEs",
                                raw_output=banner.strip(),
                                command_run=f"nc {target} {port}",
                            ))
                    except Exception:
                        pass
                findings.append(ReconFinding(
                    service="ssh", port=port,
                    check_name="SSH Banner",
                    severity="INFO",
                    result=f"Banner: {banner.strip()[:100]}",
                    raw_output=banner.strip(),
                    command_run=f"nc {target} {port}",
                ))
        except Exception:
            pass
        return findings

    def _check_telnet(self, target: str, port: int, info: dict) -> list:
        return [ReconFinding(
            service="telnet", port=port,
            check_name="Telnet Exposed",
            severity="CRITICAL",
            result="Telnet transmits credentials in plaintext — immediately exploitable",
            command_run=f"telnet {target} {port}",
        )]

    def _check_vnc(self, target: str, port: int, info: dict) -> list:
        findings = []
        try:
            sock = socket.create_connection((target, port), timeout=self.timeout)
            banner = sock.recv(64).decode(errors="ignore")
            sock.close()
            if "RFB" in banner:
                findings.append(ReconFinding(
                    service="vnc", port=port,
                    check_name="VNC Accessible",
                    severity="HIGH",
                    result=f"VNC server detected: {banner.strip()}",
                    raw_output=banner.strip(),
                    command_run=f"vncviewer {target}::{port}",
                ))
        except Exception:
            pass
        return findings

    def _check_snmp(self, target: str, port: int, info: dict) -> list:
        """بررسی SNMP community string پیش‌فرض"""
        findings = []
        cmd = ["nmap", "-sU", "-p", str(port),
               "--script=snmp-info,snmp-sysdescr",
               "--script-timeout", "8s", target]
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=20
            ).stdout
            if "SNMPv2" in out or "community" in out.lower() or "sysDescr" in out:
                findings.append(ReconFinding(
                    service="snmp", port=port,
                    check_name="SNMP Community String",
                    severity="HIGH",
                    result="SNMP responding — 'public' community string may work",
                    raw_output=out[:300],
                    command_run=" ".join(cmd),
                ))
        except Exception:
            pass
        return findings

    def _check_docker(self, target: str, port: int, info: dict) -> list:
        import urllib.request
        findings = []
        try:
            resp = urllib.request.urlopen(
                f"http://{target}:{port}/version", timeout=self.timeout
            )
            body = resp.read(512).decode(errors="ignore")
            if "Version" in body or "ApiVersion" in body:
                findings.append(ReconFinding(
                    service="docker", port=port,
                    check_name="Unauthenticated Docker API",
                    severity="CRITICAL",
                    result="Docker API accessible — full container/host control possible",
                    raw_output=body[:300],
                    command_run=f"curl http://{target}:{port}/version",
                ))
        except Exception:
            pass
        return findings

    def _check_kubernetes(self, target: str, port: int, info: dict) -> list:
        import urllib.request
        findings = []
        for path in ["/api", "/apis", "/version"]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                resp = urllib.request.urlopen(
                    urllib.request.Request(
                        f"https://{target}:{port}{path}",
                        headers={"User-Agent": "kubectl/v1.28"}
                    ),
                    context=ctx, timeout=self.timeout
                )
                body = resp.read(256).decode(errors="ignore")
                if "apiVersion" in body or "kind" in body:
                    findings.append(ReconFinding(
                        service="kubernetes", port=port,
                        check_name="K8s API Exposed",
                        severity="CRITICAL",
                        result=f"Kubernetes API accessible at {path}",
                        raw_output=body[:200],
                        command_run=f"kubectl --server=https://{target}:{port} get pods",
                    ))
                    break
            except Exception:
                pass
        return findings

    def _check_memcached(self, target: str, port: int, info: dict) -> list:
        findings = []
        try:
            sock = socket.create_connection((target, port), timeout=self.timeout)
            sock.sendall(b"stats\r\n")
            resp = sock.recv(1024).decode(errors="ignore")
            sock.close()
            if "STAT" in resp:
                findings.append(ReconFinding(
                    service="memcache", port=port,
                    check_name="No Authentication",
                    severity="HIGH",
                    result="Memcached accessible without auth — cache poisoning / data theft",
                    raw_output=resp[:200],
                    command_run=f"echo 'stats' | nc {target} {port}",
                ))
        except Exception:
            pass
        return findings

    def _check_cassandra(self, target: str, port: int, info: dict) -> list:
        findings = []
        try:
            sock = socket.create_connection((target, port), timeout=self.timeout)
            # CQL STARTUP message
            startup = (
                b"\x04\x00\x00\x01\x01\x00\x00\x00\x16"
                b"\x00\x01\x00\x0bCQL_VERSION\x00\x053.0.0"
            )
            sock.sendall(startup)
            resp = sock.recv(128)
            sock.close()
            if resp:
                findings.append(ReconFinding(
                    service="cassandra", port=port,
                    check_name="Cassandra Accessible",
                    severity="HIGH",
                    result="Cassandra CQL port responding — may lack authentication",
                    raw_output=f"{len(resp)} bytes",
                    command_run=f"cqlsh {target} {port}",
                ))
        except Exception:
            pass
        return findings

    def _check_zookeeper(self, target: str, port: int, info: dict) -> list:
        findings = []
        try:
            sock = socket.create_connection((target, port), timeout=self.timeout)
            sock.sendall(b"stat\n")
            resp = sock.recv(512).decode(errors="ignore")
            sock.close()
            if "Zookeeper version" in resp or "Latency" in resp:
                findings.append(ReconFinding(
                    service="zookeeper", port=port,
                    check_name="No Authentication",
                    severity="CRITICAL",
                    result="ZooKeeper responding to 'stat' — full cluster control possible",
                    raw_output=resp[:200],
                    command_run=f"echo 'stat' | nc {target} {port}",
                ))
        except Exception:
            pass
        return findings

    def _check_mysql(self, target: str, port: int, info: dict) -> list:
        findings = []
        try:
            sock = socket.create_connection((target, port), timeout=self.timeout)
            banner = sock.recv(256)
            sock.close()
            if banner and len(banner) > 4:
                # MySQL پروتکل: اولین بایت‌ها version string
                text = banner[4:].decode(errors="ignore")
                ver = text.split("\x00")[0]
                if ver:
                    findings.append(ReconFinding(
                        service="mysql", port=port,
                        check_name="MySQL Banner",
                        severity="INFO",
                        result=f"MySQL version: {ver}",
                        raw_output=ver,
                        command_run=f"nc {target} {port}",
                    ))
                    if any(v in ver for v in ["5.0", "5.1", "5.5", "5.6"]):
                        findings.append(ReconFinding(
                            service="mysql", port=port,
                            check_name="Outdated MySQL",
                            severity="HIGH",
                            result=f"MySQL {ver} — end-of-life, multiple known CVEs",
                            command_run=f"mysql -h {target} -P {port} -u root",
                        ))
        except Exception:
            pass
        return findings

    def _check_postgresql(self, target: str, port: int, info: dict) -> list:
        findings = []
        try:
            # PostgreSQL startup message
            startup = b"\x00\x00\x00\x08\x00\x03\x00\x00"
            sock = socket.create_connection((target, port), timeout=self.timeout)
            sock.sendall(startup)
            resp = sock.recv(128)
            sock.close()
            if resp:
                findings.append(ReconFinding(
                    service="postgresql", port=port,
                    check_name="PostgreSQL Accessible",
                    severity="MEDIUM",
                    result="PostgreSQL port responding — check for trust authentication",
                    raw_output=f"{len(resp)} bytes",
                    command_run=f"psql -h {target} -p {port} -U postgres",
                ))
        except Exception:
            pass
        return findings

    def to_dict(self, result: AutoReconResult) -> dict:
        return {
            "target":           result.target,
            "total_checks":     result.total_checks,
            "findings":         result.findings,
            "critical_count":   len(result.critical_findings),
            "high_count":       len(result.high_findings),
            "critical_findings": result.critical_findings,
            "high_findings":    result.high_findings,
            "skipped":          result.skipped,
            "errors":           result.errors,
        }
