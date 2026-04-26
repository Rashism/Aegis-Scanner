<div align="center">

```
    ___                _      ____
   /   | ___  ____ _(_)____/ ___/_________ _____  ____  ___  _____
  / /| |/ _ \/ __ `/ / ___/\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / ___ /  __/ /_/ / (__  )___/ / /__/ /_/ / / / / / / /  __/ /
/_/  |_\___/\__, /_/____//____/\___/\__,_/_/ /_/_/ /_/\___/_/
           /____/
```

**AI-Powered Network Scanner — Red Team Edition**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Version](https://img.shields.io/badge/Version-4.0.0-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Modules](https://img.shields.io/badge/Modules-17-purple?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-18%20passing-brightgreen?style=flat-square)

> ⚠️ **Legal Warning:** This tool is designed exclusively for authorized penetration testing and red team operations on systems you have explicit written permission to test. Unauthorized use is illegal.

</div>

---

## 🎯 What Makes Aegis v4 Unique

Most scanners just collect data. **Aegis v4 thinks, learns, and decides.**

| Feature | Description |
|---------|-------------|
| 🧠 **Adaptive Intelligence** | Learns from every scan — predicts ports, detects changes, recommends evasion |
| 🔍 **Auto-Recon Loop** | After initial scan, automatically deep-dives each service (20 handlers) |
| 👁️ **Stealth Scoring** | Answers "was I detected?" and gives a better command for next time |
| 🎯 **Campaign Mode** | Parallel multi-target scanning with smart prioritization |
| 🤖 **Local AI** | Ollama/Llama3 runs 100% locally — no cloud, no cost, no data leakage |
| 🛡️ **Honeypot Detection** | Checks for honeypots before scanning to protect operator identity |

---

## 🏗️ Architecture — 17 Modules

```
aegis-scanner/
├── core/
│   ├── aegis_engine.py        # Orchestrator — 17-phase pipeline
│   ├── nmap_controller.py     # Nmap wrapper with retry + validation
│   └── llm_connector.py       # Ollama (local) — BaseLLMProvider abstraction
│
├── intelligence/
│   ├── adaptive_engine.py     # ★ v4 — Learns from every scan
│   ├── knowledge_base.py      # Session persistence
│   └── cve_mapper.py          # CPE normalization
│
├── modules/
│   ├── auto_recon.py          # ★ v4 — Service deep-dive (20 handlers)
│   ├── stealth_advisor.py     # ★ v4 — Was I detected? + better next command
│   ├── campaign.py            # ★ v4 — Multi-target parallel scanning
│   ├── realtime_analyzer.py   # TCP fingerprint + middlebox detection
│   ├── osint_engine.py        # DNS / GeoIP / Shodan / VirusTotal / AbuseIPDB
│   ├── evasion_engine.py      # IDS/FW evasion profile builder
│   ├── honeypot_detector.py   # Pre-scan honeypot detection
│   ├── port_analyzer.py       # Risk scoring (182 known ports)
│   ├── vuln_engine.py         # NVD API 2.0 → CVE mapping
│   ├── exploit_suggestor.py   # searchsploit + Metasploit module lookup
│   ├── protocol_inspector.py  # TLS/SSH/HTTP deep inspection
│   ├── attack_chain_mapper.py # MITRE ATT&CK kill chain
│   ├── lateral_movement.py    # Pivot point analysis
│   ├── opset_scorer.py        # OPSEC scoring
│   └── packet_optimizer.py    # RTT-based scan optimization
│
├── reporting/
│   ├── json_reporter.py       # Full JSON report (all 17 modules)
│   └── markdown_reporter.py   # Human-readable Markdown report
│
├── ui/
│   └── tui.py                 # Rich TUI (1100+ lines)
│
└── tests/
    └── test_integration.py    # 18 unit + integration tests
```

★ = New in v4

---

## 📊 Scan Levels

| Level | Name | Description | NSE Scripts |
|-------|------|-------------|-------------|
| 1 | Quick | Top ports, no NSE | — |
| 2 | Standard | Services + discovery | 12 |
| 3 | Aggressive | OS detection + auth | 22 |
| 4 | Full Vuln | All vulnerability scripts | 50+ |
| 5 | Stealth Full | All ports + evasion active | 50+ |

---

## 🚀 Installation

### System Requirements

```bash
# Required
sudo apt install -y nmap

# Recommended
sudo apt install -y tcpdump exploitdb

# For accurate realtime analysis (requires root)
pip install scapy
```

### Python Dependencies

```bash
pip install -r requirements.txt
```

### Local AI (Ollama — free, no cloud)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Download a model (choose one)
ollama pull llama3        # 4.7 GB — recommended
ollama pull mistral       # 4.1 GB — lighter
ollama pull phi3          # 2.3 GB — very light

# Start server
ollama serve
```

---

## ⚡ Quick Start

```bash
# Interactive TUI (recommended)
python main.py

# Direct scan
python main.py --target 192.168.1.1

# Aggressive scan
python main.py --target 192.168.1.1 --level 3

# Scan a subnet
python main.py --target 10.0.0.0/24 --level 2

# Campaign mode (multiple targets)
python main.py --campaign targets.txt --level 2 --workers 3

# No AI (faster)
python main.py --target 192.168.1.1 --no-ai

# System health check
python main.py --health
```

### Campaign File Format (`targets.txt`)

```
# Comments start with #
192.168.1.1
192.168.1.2  priority=1  level=3
10.0.0.0/24
example.com  ports=80,443  priority=2
```

---

## 🔧 Configuration (`aegis_config.json`)

```json
{
  "llm": {
    "base_url": "http://localhost:11434",
    "model": "llama3",
    "timeout": 120,
    "enabled": true
  },
  "nmap": {
    "privileged": false,
    "max_retries": 2,
    "default_timeout": 300
  },
  "report": {
    "output_dir": "reports",
    "max_cves_per_service": 5
  },
  "api_keys": {
    "nvd_api_key": "",
    "shodan_api_key": "",
    "virustotal_api_key": "",
    "abuseipdb_api_key": ""
  }
}
```

### Environment Variables

```bash
export NVD_API_KEY="..."        # Free: nvd.nist.gov/developers
export SHODAN_API_KEY="..."     # shodan.io
export VIRUSTOTAL_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export OLLAMA_URL="http://localhost:11434"
export OLLAMA_MODEL="llama3"
```

---

## 🧠 Adaptive Intelligence (v4)

After scanning the same target multiple times, Aegis builds intelligence:

```
Scan #1: 3 ports found → learned
Scan #2: Prediction → "Port 22 (87% confidence), Port 80 (91%)"
         Change alert → "Port 3306 closed since last scan"
         Evasion rec  → "Use -T2 --mtu 1280 (best OPSEC from history)"
```

The adaptive database (`data/adaptive_intelligence.json`) stores:
- Per-target port/service history
- Per-subnet frequency patterns
- Per-service CVE associations
- Best evasion profiles per target

---

## 🔍 Auto-Recon Handlers (v4)

After the main scan, Aegis automatically deep-dives each found service:

| Service | Check |
|---------|-------|
| Redis | Auth bypass (PING test), version disclosure |
| MongoDB | Unauthenticated access (wire protocol) |
| Elasticsearch | Cluster info, index enumeration |
| SMB | MS17-010, guest access, share enumeration |
| FTP | Anonymous login, banner |
| HTTP/S | Admin panels, `.env`, `.git`, weak TLS |
| SSH | Outdated OpenSSH, banner grabbing |
| Docker | Unauthenticated API access |
| Kubernetes | API server exposure |
| MySQL/PostgreSQL | Banner + version check |
| Cassandra/ZooKeeper | No-auth check |
| Memcached | No-auth stats |
| VNC | Accessibility check |
| SNMP | Community string (public) |
| Telnet | Always CRITICAL (plaintext) |

---

## 👁️ Stealth Scoring (v4)

After every scan, Aegis scores your stealth (0–100):

```
Score: 45/100  ████░░░░░░
Detection Risk: HIGH
Likely Detected: ⚠️ YES

Risk Factors:
  [-20] Aggressive Timing (T4/T5)
  [-25] IDS Detected
  [-10] Middlebox/DPI Detected

Better Next Command:
  nmap -sS -T1 --mtu 24 --randomize-hosts --data-length 25 -D RND:5 192.168.1.1
```

---

## 📁 Output Reports

```
reports/
├── aegis_192-168-1-1_20260424.json    ← Complete data (all 17 modules)
└── aegis_192-168-1-1_20260424.md      ← Human-readable report
```

JSON report sections:
- Nmap results + NSE scripts
- CVEs (NVD API)
- Exploit candidates
- MITRE ATT&CK kill chain
- OSINT (DNS/GeoIP/Shodan)
- Real-time network analysis
- AI analysis + attack path triage
- **Adaptive Intelligence predictions** ★
- **Auto-Recon findings** ★
- **Stealth score + recommendations** ★

---

## 🧪 Tests

```bash
# Run all tests (no Nmap/Ollama required — fully mocked)
python tests/test_integration.py

# With pytest
python -m pytest tests/ -v
```

---

## 🛡️ OPSEC Guidelines

- **Level 1-2** for sensitive environments — minimal noise
- **Level 5** only with explicit written permission
- Use `--no-ai` in air-gapped environments
- Protect `reports/` with `chmod 700 reports/`
- Clear `data/adaptive_intelligence.json` for non-attribution

---

## 📜 License

MIT License — See [LICENSE](LICENSE) file.

**This tool is for authorized security testing only. The authors are not responsible for misuse.**

---

<div align="center">

*Aegis-Scanner v4.0 — Built for authorized red team operations*

</div>
