# aegis-scanner/modules/attack_chain_mapper.py
"""
نگاشت یافته‌های اسکن به MITRE ATT&CK kill chain.

این ماژول بر اساس پورت‌های باز، آسیب‌پذیری‌ها، و سرویس‌های شناسایی‌شده،
مسیرهای احتمالی حمله را از Initial Access تا Impact ترسیم می‌کند.

منبع داده: MITRE ATT&CK Enterprise Framework v14
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ─── MITRE ATT&CK Tactic definitions ─────────────────────────────────────────
TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


# ─── Service → ATT&CK technique mapping ──────────────────────────────────────
# بر اساس MITRE ATT&CK Enterprise v14 (attack.mitre.org)
SERVICE_TECHNIQUE_MAP = {
    # ─── Initial Access ───────────────────────────────────────────────────
    "ssh": [
        {
            "tactic":       "Initial Access",
            "technique_id": "T1078",
            "technique":    "Valid Accounts",
            "sub_technique":"T1078.001",
            "name":         "Default Accounts",
            "description":  "Use default/weak SSH credentials for initial access",
            "severity":     "HIGH",
        },
        {
            "tactic":       "Initial Access",
            "technique_id": "T1110",
            "technique":    "Brute Force",
            "sub_technique":"T1110.001",
            "name":         "Password Guessing",
            "description":  "Brute force SSH login using credential lists",
            "severity":     "HIGH",
            "tools":        ["Hydra", "Medusa", "Metasploit ssh_login"],
        },
    ],
    "rdp": [
        {
            "tactic":       "Initial Access",
            "technique_id": "T1021",
            "technique":    "Remote Services",
            "sub_technique":"T1021.001",
            "name":         "Remote Desktop Protocol",
            "description":  "Exploit exposed RDP for initial access",
            "severity":     "HIGH",
            "tools":        ["xfreerdp", "rdesktop", "BlueKeep (CVE-2019-0708)"],
        },
        {
            "tactic":       "Lateral Movement",
            "technique_id": "T1021",
            "technique":    "Remote Services",
            "sub_technique":"T1021.001",
            "name":         "RDP Lateral Movement",
            "description":  "Move laterally using RDP with harvested credentials",
            "severity":     "HIGH",
        },
    ],
    "smb": [
        {
            "tactic":       "Initial Access",
            "technique_id": "T1190",
            "technique":    "Exploit Public-Facing Application",
            "name":         "SMB Exploitation",
            "description":  "EternalBlue (MS17-010) or PrintNightmare for RCE",
            "severity":     "CRITICAL",
            "tools":        ["Metasploit ms17_010_eternalblue", "impacket"],
            "cves":         ["CVE-2017-0144", "CVE-2021-1675"],
        },
        {
            "tactic":       "Credential Access",
            "technique_id": "T1003",
            "technique":    "OS Credential Dumping",
            "sub_technique":"T1003.002",
            "name":         "SAM Hash Extraction via SMB",
            "description":  "Use authenticated SMB to extract NTLM hashes",
            "severity":     "HIGH",
            "tools":        ["impacket secretsdump", "CrackMapExec"],
        },
        {
            "tactic":       "Lateral Movement",
            "technique_id": "T1021",
            "technique":    "Remote Services",
            "sub_technique":"T1021.002",
            "name":         "SMB/Windows Admin Shares",
            "description":  "Move laterally using SMB admin shares (C$, ADMIN$)",
            "severity":     "HIGH",
            "tools":        ["CrackMapExec", "PsExec", "impacket smbexec"],
        },
    ],
    "microsoft-ds": [
        {
            "tactic":       "Initial Access",
            "technique_id": "T1190",
            "technique":    "Exploit Public-Facing Application",
            "name":         "SMB RCE (port 445)",
            "description":  "Direct SMB exploitation via port 445",
            "severity":     "CRITICAL",
            "tools":        ["Metasploit", "impacket"],
        },
    ],
    "http": [
        {
            "tactic":       "Initial Access",
            "technique_id": "T1190",
            "technique":    "Exploit Public-Facing Application",
            "name":         "Web Application Attack",
            "description":  "SQLi, XSS, RCE via web application vulnerabilities",
            "severity":     "MEDIUM",
            "tools":        ["sqlmap", "nuclei", "burpsuite", "nikto"],
        },
        {
            "tactic":       "Discovery",
            "technique_id": "T1083",
            "technique":    "File and Directory Discovery",
            "name":         "Web Directory Enumeration",
            "description":  "Enumerate hidden files, directories, and endpoints",
            "severity":     "LOW",
            "tools":        ["gobuster", "feroxbuster", "dirb"],
        },
    ],
    "https": [
        {
            "tactic":       "Initial Access",
            "technique_id": "T1190",
            "technique":    "Exploit Public-Facing Application",
            "name":         "HTTPS Application Exploitation",
            "description":  "Exploit HTTPS web app; check for TLS vuln (Heartbleed, POODLE)",
            "severity":     "MEDIUM",
            "tools":        ["burpsuite", "nuclei", "sslscan"],
            "cves":         ["CVE-2014-0160 (Heartbleed)", "CVE-2014-3566 (POODLE)"],
        },
    ],
    "mysql": [
        {
            "tactic":       "Initial Access",
            "technique_id": "T1078",
            "technique":    "Valid Accounts",
            "name":         "MySQL Default/Weak Credentials",
            "description":  "Access MySQL with default root credentials",
            "severity":     "HIGH",
            "tools":        ["mysql client", "Metasploit mysql_login"],
        },
        {
            "tactic":       "Execution",
            "technique_id": "T1059",
            "technique":    "Command and Scripting Interpreter",
            "name":         "MySQL UDF Code Execution",
            "description":  "Load malicious UDF library for OS command execution",
            "severity":     "CRITICAL",
            "tools":        ["raptor_udf", "Metasploit mysql_udf_payload"],
        },
        {
            "tactic":       "Collection",
            "technique_id": "T1005",
            "technique":    "Data from Local System",
            "name":         "Database Exfiltration",
            "description":  "Export all database contents via SELECT INTO OUTFILE",
            "severity":     "HIGH",
        },
    ],
    "redis": [
        {
            "tactic":       "Initial Access",
            "technique_id": "T1133",
            "technique":    "External Remote Services",
            "name":         "Redis Unauthenticated Access",
            "description":  "Redis running without AUTH — full access to all keys",
            "severity":     "CRITICAL",
            "tools":        ["redis-cli"],
        },
        {
            "tactic":       "Persistence",
            "technique_id": "T1098",
            "technique":    "Account Manipulation",
            "name":         "Redis SSH Key Injection",
            "description":  "Write SSH public key to authorized_keys via Redis CONFIG SET",
            "severity":     "CRITICAL",
            "tools":        ["redis-cli CONFIG SET dir/dbfilename"],
        },
        {
            "tactic":       "Execution",
            "technique_id": "T1059",
            "technique":    "Command and Scripting Interpreter",
            "name":         "Redis Cron Job RCE",
            "description":  "Write malicious crontab via Redis for code execution",
            "severity":     "CRITICAL",
        },
    ],
    "mongodb": [
        {
            "tactic":       "Initial Access",
            "technique_id": "T1133",
            "technique":    "External Remote Services",
            "name":         "MongoDB No-Auth Access",
            "description":  "MongoDB with no authentication — full DB access",
            "severity":     "CRITICAL",
            "tools":        ["mongosh", "Metasploit mongodb_login"],
        },
    ],
    "vnc": [
        {
            "tactic":       "Initial Access",
            "technique_id": "T1021",
            "technique":    "Remote Services",
            "sub_technique":"T1021.005",
            "name":         "VNC Remote Desktop",
            "description":  "VNC access — often no auth or weak password",
            "severity":     "HIGH",
            "tools":        ["vncviewer", "Metasploit vnc_login"],
        },
    ],
    "telnet": [
        {
            "tactic":       "Initial Access",
            "technique_id": "T1078",
            "technique":    "Valid Accounts",
            "name":         "Telnet Unencrypted Access",
            "description":  "Telnet transmits credentials in plaintext — easy to sniff",
            "severity":     "CRITICAL",
            "tools":        ["telnet", "Wireshark (passive sniff)"],
        },
        {
            "tactic":       "Credential Access",
            "technique_id": "T1040",
            "technique":    "Network Sniffing",
            "name":         "Telnet Credential Capture",
            "description":  "Sniff Telnet session to capture plaintext credentials",
            "severity":     "CRITICAL",
        },
    ],
    "ftp": [
        {
            "tactic":       "Initial Access",
            "technique_id": "T1078",
            "technique":    "Valid Accounts",
            "name":         "FTP Anonymous Login",
            "description":  "Check FTP for anonymous access or weak credentials",
            "severity":     "HIGH",
            "tools":        ["ftp client", "Metasploit ftp_login"],
        },
        {
            "tactic":       "Exfiltration",
            "technique_id": "T1048",
            "technique":    "Exfiltration Over Alternative Protocol",
            "sub_technique":"T1048.003",
            "name":         "FTP Data Exfiltration",
            "description":  "Use FTP as covert exfiltration channel",
            "severity":     "MEDIUM",
        },
    ],
    "snmp": [
        {
            "tactic":       "Reconnaissance",
            "technique_id": "T1046",
            "technique":    "Network Service Discovery",
            "name":         "SNMP Community String Enumeration",
            "description":  "Use default community strings (public/private) to dump MIB",
            "severity":     "HIGH",
            "tools":        ["snmpwalk", "onesixtyone", "snmpenum"],
        },
        {
            "tactic":       "Discovery",
            "technique_id": "T1082",
            "technique":    "System Information Discovery",
            "name":         "SNMP Network Topology Leak",
            "description":  "SNMP MIB reveals ARP tables, routing, interfaces, users",
            "severity":     "HIGH",
        },
    ],
    "ldap": [
        {
            "tactic":       "Discovery",
            "technique_id": "T1018",
            "technique":    "Remote System Discovery",
            "name":         "LDAP Anonymous Bind",
            "description":  "Enumerate AD users, groups, computers via anonymous LDAP",
            "severity":     "HIGH",
            "tools":        ["ldapsearch", "BloodHound", "ldapdomaindump"],
        },
        {
            "tactic":       "Credential Access",
            "technique_id": "T1558",
            "technique":    "Steal or Forge Kerberos Tickets",
            "sub_technique":"T1558.003",
            "name":         "Kerberoasting via LDAP",
            "description":  "Query LDAP for SPNs to perform Kerberoasting",
            "severity":     "HIGH",
            "tools":        ["GetUserSPNs.py", "Rubeus"],
        },
    ],
    "winrm": [
        {
            "tactic":       "Lateral Movement",
            "technique_id": "T1021",
            "technique":    "Remote Services",
            "sub_technique":"T1021.006",
            "name":         "WinRM PowerShell Remoting",
            "description":  "Use WinRM for remote PowerShell command execution",
            "severity":     "HIGH",
            "tools":        ["evil-winrm", "Invoke-Command", "CrackMapExec"],
        },
    ],
    "elasticsearch": [
        {
            "tactic":       "Collection",
            "technique_id": "T1213",
            "technique":    "Data from Information Repositories",
            "name":         "Elasticsearch Unauthorized Data Access",
            "description":  "No-auth Elasticsearch → dump all indices",
            "severity":     "CRITICAL",
            "tools":        ["curl", "elasticdump"],
        },
    ],
}

# CVE → ATT&CK technique mapping
CVE_TECHNIQUE_MAP = {
    "CVE-2017-0144": {
        "technique_id": "T1210",
        "technique":    "Exploitation of Remote Services",
        "tactic":       "Lateral Movement",
        "name":         "EternalBlue SMB RCE",
    },
    "CVE-2021-44228": {
        "technique_id": "T1190",
        "technique":    "Exploit Public-Facing Application",
        "tactic":       "Initial Access",
        "name":         "Log4Shell JNDI RCE",
    },
    "CVE-2021-41773": {
        "technique_id": "T1190",
        "technique":    "Exploit Public-Facing Application",
        "tactic":       "Initial Access",
        "name":         "Apache Path Traversal RCE",
    },
    "CVE-2019-0708": {
        "technique_id": "T1210",
        "technique":    "Exploitation of Remote Services",
        "tactic":       "Initial Access",
        "name":         "BlueKeep RDP Pre-Auth RCE",
    },
    "CVE-2014-0160": {
        "technique_id": "T1552",
        "technique":    "Unsecured Credentials",
        "sub_technique":"T1552.004",
        "tactic":       "Credential Access",
        "name":         "Heartbleed Memory Disclosure",
    },
}


@dataclass
class AttackStep:
    """یک قدم در زنجیره حمله"""
    tactic:         str
    technique_id:   str
    technique:      str
    sub_technique:  Optional[str]
    name:           str
    description:    str
    severity:       str
    tools:          list
    cves:           list
    affected_port:  int
    affected_service: str
    source:         str    # "service_map" / "cve_map"


@dataclass
class KillChain:
    """زنجیره کامل حمله برای یک target"""
    target:          str
    total_steps:     int
    critical_paths:  list        # لیستی از path‌های از IA به Impact
    steps_by_tactic: dict        # tactic → [AttackStep]
    critical_count:  int
    high_count:      int
    highest_impact:  str
    attack_surface:  list        # سرویس‌هایی که attack vector هستند
    pivot_points:    list        # سرویس‌هایی که lateral movement ممکن می‌کنند
    mitre_summary:   str


class AttackChainMapper:
    """
    نگاشت یافته‌های Aegis به MITRE ATT&CK kill chain.

    خروجی: گراف attack path از Initial Access تا Impact
    که به red team کمک می‌کند بهترین مسیر نفوذ را انتخاب کند.
    """

    def map(self, target: str, open_ports: list, vulnerabilities: list) -> KillChain:
        """
        ساخت kill chain کامل برای target.
        """
        all_steps: list = []

        # نگاشت از سرویس‌های شناسایی‌شده
        for port_data in open_ports:
            service = port_data.get("service", "").lower()
            port    = port_data.get("port", 0)
            techs   = SERVICE_TECHNIQUE_MAP.get(service, [])
            for tech in techs:
                all_steps.append(AttackStep(
                    tactic=tech.get("tactic", ""),
                    technique_id=tech.get("technique_id", ""),
                    technique=tech.get("technique", ""),
                    sub_technique=tech.get("sub_technique"),
                    name=tech.get("name", ""),
                    description=tech.get("description", ""),
                    severity=tech.get("severity", "MEDIUM"),
                    tools=tech.get("tools", []),
                    cves=tech.get("cves", []),
                    affected_port=port,
                    affected_service=service,
                    source="service_map",
                ))

        # نگاشت از CVE‌های یافت‌شده
        for vuln in vulnerabilities:
            cve_id  = vuln.get("cve_id", "")
            port    = vuln.get("port", 0)
            service = vuln.get("service", "")
            tech    = CVE_TECHNIQUE_MAP.get(cve_id)
            if tech:
                all_steps.append(AttackStep(
                    tactic=tech.get("tactic", ""),
                    technique_id=tech.get("technique_id", ""),
                    technique=tech.get("technique", ""),
                    sub_technique=tech.get("sub_technique"),
                    name=tech.get("name", cve_id),
                    description=f"Exploitation of {cve_id}",
                    severity=vuln.get("severity", "HIGH"),
                    tools=[],
                    cves=[cve_id],
                    affected_port=port,
                    affected_service=service,
                    source="cve_map",
                ))

        # گروه‌بندی بر اساس tactic
        steps_by_tactic: dict = {t: [] for t in TACTICS}
        for step in all_steps:
            if step.tactic in steps_by_tactic:
                steps_by_tactic[step.tactic].append(step)

        # شمارش severity
        crit_count = sum(1 for s in all_steps if s.severity == "CRITICAL")
        high_count = sum(1 for s in all_steps if s.severity == "HIGH")

        # شناسایی attack surface و pivot points
        attack_surface = self._find_attack_surface(steps_by_tactic)
        pivot_points   = self._find_pivot_points(steps_by_tactic)

        # ساخت critical paths (از IA به Lateral Movement یا Impact)
        critical_paths = self._build_critical_paths(steps_by_tactic)

        # بالاترین impact
        highest_impact = "CRITICAL" if crit_count else ("HIGH" if high_count else "MEDIUM")

        summary = self._generate_summary(
            target, all_steps, crit_count, high_count,
            attack_surface, pivot_points
        )

        return KillChain(
            target=target,
            total_steps=len(all_steps),
            critical_paths=critical_paths,
            steps_by_tactic=steps_by_tactic,
            critical_count=crit_count,
            high_count=high_count,
            highest_impact=highest_impact,
            attack_surface=attack_surface,
            pivot_points=pivot_points,
            mitre_summary=summary,
        )

    # ─── Helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _find_attack_surface(steps_by_tactic: dict) -> list:
        """سرویس‌هایی که initial access vector هستند"""
        ia_steps = steps_by_tactic.get("Initial Access", [])
        seen     = set()
        surface  = []
        for step in ia_steps:
            key = f"{step.affected_service}:{step.affected_port}"
            if key not in seen:
                seen.add(key)
                surface.append({
                    "service": step.affected_service,
                    "port":    step.affected_port,
                    "severity": step.severity,
                    "technique": step.technique_id,
                })
        return surface

    @staticmethod
    def _find_pivot_points(steps_by_tactic: dict) -> list:
        """سرویس‌هایی که lateral movement از طریق آن‌ها ممکن است"""
        lm_steps = steps_by_tactic.get("Lateral Movement", [])
        seen     = set()
        pivots   = []
        for step in lm_steps:
            key = f"{step.affected_service}:{step.affected_port}"
            if key not in seen:
                seen.add(key)
                pivots.append({
                    "service":   step.affected_service,
                    "port":      step.affected_port,
                    "technique": step.technique_id,
                    "name":      step.name,
                })
        return pivots

    @staticmethod
    def _build_critical_paths(steps_by_tactic: dict) -> list:
        """ساخت critical attack paths از IA به Impact"""
        paths    = []
        ia_steps = steps_by_tactic.get("Initial Access", [])
        ex_steps = steps_by_tactic.get("Execution", [])
        lm_steps = steps_by_tactic.get("Lateral Movement", [])
        im_steps = steps_by_tactic.get("Impact", [])

        for ia in ia_steps[:3]:   # حداکثر ۳ path
            path = {
                "initial_access": {
                    "technique": ia.technique_id,
                    "name":      ia.name,
                    "service":   f"{ia.affected_service}:{ia.affected_port}",
                    "severity":  ia.severity,
                },
                "steps": [],
            }

            # Execution
            if ex_steps:
                path["steps"].append({
                    "tactic":    "Execution",
                    "technique": ex_steps[0].technique_id,
                    "name":      ex_steps[0].name,
                })

            # Lateral Movement
            if lm_steps:
                path["steps"].append({
                    "tactic":    "Lateral Movement",
                    "technique": lm_steps[0].technique_id,
                    "name":      lm_steps[0].name,
                })

            # Impact (simulated)
            path["potential_impact"] = (
                "Full system compromise, data exfiltration, ransomware deployment"
                if ia.severity == "CRITICAL"
                else "Partial access, credential theft, persistence"
            )
            paths.append(path)

        return paths

    @staticmethod
    def _generate_summary(
        target: str, steps: list,
        crit: int, high: int,
        attack_surface: list, pivots: list
    ) -> str:
        total = len(steps)
        ia_count = len(attack_surface)
        piv_count = len(pivots)
        return (
            f"Target {target} has {total} mapped ATT&CK techniques across "
            f"{ia_count} initial access vector(s) and {piv_count} lateral movement "
            f"pivot point(s). {crit} CRITICAL and {high} HIGH severity techniques identified."
        )

    def to_dict(self, chain: KillChain) -> dict:
        def step_to_dict(s: AttackStep) -> dict:
            return {
                "tactic":            s.tactic,
                "technique_id":      s.technique_id,
                "technique":         s.technique,
                "sub_technique":     s.sub_technique,
                "name":              s.name,
                "description":       s.description,
                "severity":          s.severity,
                "tools":             s.tools,
                "cves":              s.cves,
                "affected_port":     s.affected_port,
                "affected_service":  s.affected_service,
                "mitre_url":         f"https://attack.mitre.org/techniques/{s.technique_id.replace('.','/')}",
            }

        tactic_dict = {}
        for tactic, steps in chain.steps_by_tactic.items():
            if steps:
                tactic_dict[tactic] = [step_to_dict(s) for s in steps]

        return {
            "target":          chain.target,
            "total_techniques":chain.total_steps,
            "critical_count":  chain.critical_count,
            "high_count":      chain.high_count,
            "highest_impact":  chain.highest_impact,
            "attack_surface":  chain.attack_surface,
            "pivot_points":    chain.pivot_points,
            "critical_paths":  chain.critical_paths,
            "kill_chain":      tactic_dict,
            "summary":         chain.mitre_summary,
        }
