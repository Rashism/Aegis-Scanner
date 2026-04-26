# aegis-scanner/config/constants.py
"""
ثابت‌های پروژه Aegis-Scanner
تمامی مقادیر hard-coded اینجا تعریف می‌شوند
"""

PROJECT_NAME = "Aegis-Scanner"
VERSION = "4.0.0"
AUTHOR = "Red Team Framework"

# ─── Ollama / LLM ───────────────────────────────────────────────────────────
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3"
OLLAMA_TIMEOUT = 120
OLLAMA_MAX_TOKENS = 2048

# ─── Nmap ────────────────────────────────────────────────────────────────────
NMAP_DEFAULT_ARGS = "-sV -sC --open"
NMAP_TIMING_PROFILES = {
    "paranoid":   "-T0",
    "sneaky":     "-T1",
    "polite":     "-T2",
    "normal":     "-T3",
    "aggressive": "-T4",
    "insane":     "-T5",
}

# ─── NSE Script Categories ───────────────────────────────────────────────────
# اسکریپت‌های غیرپیش‌فرض که باید صریحاً فراخوانی شوند
NSE_SCRIPTS_AUTH = [
    "ftp-anon", "ftp-brute", "ssh-brute", "ssh-auth-methods",
    "http-auth-finder", "http-default-accounts",
    "smtp-open-relay", "smtp-enum-users",
    "snmp-brute", "snmp-info", "snmp-sysdescr", "snmp-interfaces",
    "mysql-empty-password", "mysql-info", "mysql-brute",
    "mssql-info", "mssql-empty-password", "mssql-brute", "mssql-config",
    "rdp-enum-encryption", "rdp-vuln-ms12-020",
    "vnc-info", "vnc-brute",
    "telnet-ntlm-info", "telnet-brute",
    "pop3-brute", "imap-brute",
    "ldap-brute", "ldap-rootdse",
    "smb-security-mode",
]

NSE_SCRIPTS_DISCOVERY = [
    "http-title", "http-headers", "http-methods", "http-server-header",
    "http-robots.txt", "http-sitemap-generator",
    "http-auth", "http-open-redirect",
    "banner", "finger",
    "dns-brute", "dns-zone-transfer", "dns-srv-enum",
    "nbstat", "smb-os-discovery", "smb-enum-shares", "smb-enum-users",
    "nfs-ls", "nfs-showmount",
    "rpcinfo",
    "mongodb-info", "redis-info",
    "cassandra-info",
    "ssl-cert", "ssl-enum-ciphers", "ssl-dh-params", "ssl-date",
    "tls-alpn", "tls-nextprotoneg",
    "sshv1", "ssh2-enum-algos",
]

NSE_SCRIPTS_VULN = [
    # SMB
    "smb-vuln-ms17-010", "smb-vuln-ms08-067", "smb-vuln-ms10-061",
    "smb-vuln-ms10-054", "smb-vuln-ms06-025", "smb-vuln-ms07-029",
    "smb-vuln-cve2009-3103", "smb-double-pulsar-backdoor",
    # HTTP
    "http-shellshock", "http-slowloris-check", "http-csrf",
    "http-dombased-xss", "http-stored-xss", "http-sql-injection",
    "http-vuln-cve2017-5638", "http-vuln-cve2014-2128",
    "http-vuln-cve2015-1635", "http-vuln-cve2017-1001000",
    "http-vuln-cve2011-3192",
    # SSL/TLS
    "ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection",
    "ssl-dh-params", "ssl-known-key",
    "sslv2-drown",
    # FTP
    "ftp-vsftpd-backdoor", "ftp-proftpd-backdoor",
    # RDP
    "rdp-vuln-ms12-020",
    # Misc
    "irc-botnet-channels", "irc-unrealircd-backdoor",
    "distcc-cve2004-2687",
    "realvnc-auth-bypass",
    "ms-sql-nmap-use-afmss",
]

NSE_SCRIPTS_EXPLOIT_SAFE = [
    "http-phpmyadmin-dir-traversal",
    "http-shellshock",
    "smb-vuln-ms17-010",
    "ssl-heartbleed",
    "ftp-vsftpd-backdoor",
]

# ─── اسکن‌های سطح‌بندی‌شده با NSE کامل ────────────────────────────────────
NMAP_SCAN_LEVELS = {
    1: {
        "args":  "-sV -T3 --open -F --version-intensity 3",
        "label": "Quick",
        "desc":  "اسکن سریع پورت‌های رایج — بدون NSE",
    },
    2: {
        "args":  (
            "-sV -sC -T3 --open --version-intensity 5 "
            "--script=" + ",".join(NSE_SCRIPTS_DISCOVERY[:12])
        ),
        "label": "Standard",
        "desc":  "اسکن استاندارد با اسکریپت‌های کشف سرویس",
    },
    3: {
        "args":  (
            "-sV -sC -O -T4 --open --version-intensity 7 "
            "--script=" + ",".join(NSE_SCRIPTS_DISCOVERY + NSE_SCRIPTS_AUTH[:10])
        ),
        "label": "Aggressive",
        "desc":  "اسکن تهاجمی با OS detection و احراز هویت",
    },
    4: {
        "args":  (
            "-sV -sC -O -A -T4 --open --version-intensity 9 "
            "--script=" + ",".join(
                NSE_SCRIPTS_DISCOVERY + NSE_SCRIPTS_AUTH + NSE_SCRIPTS_VULN
            )
        ),
        "label": "Full Vuln",
        "desc":  "اسکن کامل با تمام اسکریپت‌های آسیب‌پذیری",
    },
    5: {
        "args":  (
            "-sV -sC -O -A -T2 --open --version-intensity 9 -p- "
            "--script=" + ",".join(
                NSE_SCRIPTS_DISCOVERY + NSE_SCRIPTS_AUTH + NSE_SCRIPTS_VULN
            ) + " --randomize-hosts --data-length 15"
        ),
        "label": "Stealth Full",
        "desc":  "اسکن مخفی کامل — همه پورت‌ها، همه اسکریپت‌ها، evasion فعال",
    },
}

# ─── NVD / CVE ───────────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY_ENV = "NVD_API_KEY"           # optional env var
NVD_RESULTS_PER_PAGE = 20
NVD_CACHE_TTL_HOURS = 24

# ─── CVSS Severity Thresholds ────────────────────────────────────────────────
CVSS_CRITICAL = 9.0
CVSS_HIGH     = 7.0
CVSS_MEDIUM   = 4.0
CVSS_LOW      = 0.1

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "cyan",
    "UNKNOWN":  "white",
}

# ─── Files / Paths ───────────────────────────────────────────────────────────
DATA_DIR          = "data"
REPORTS_DIR       = "reports"
KB_FILE           = "data/knowledge_base.json"
SCAN_HISTORY_FILE = "data/scan_history.json"
CVE_CACHE_FILE    = "data/cve_cache.json"

# ─── MTU / Timing ────────────────────────────────────────────────────────────
MTU_ETHERNET   = 1500
MTU_VPN        = 1400
MTU_TUNNEL     = 1280
RTT_THRESHOLDS = {          # RTT ms → Nmap timing
    "fast":   50,
    "medium": 200,
    "slow":   1000,
}
