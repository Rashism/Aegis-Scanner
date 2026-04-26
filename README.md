<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=14&duration=3000&pause=1000&color=00FF41&center=true&vCenter=true&width=600&lines=AI-Powered+Network+Scanner;Red+Team+Edition+v4.0;Adaptive+Intelligence+%2B+Auto-Recon+%2B+Stealth+Scoring" alt="Typing SVG" />

```
                                                ___                _      ____
                                               /   | ___  ____ _(_)____/ ___/_________ _____  ____  ___  _____
                                              / /| |/ _ \/ __ `/ / ___/\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
                                             / ___ /  __/ /_/ / (__  )___/ / /__/ /_/ / / / / / / /  __/ /
                                            /_/  |_\___/\__, /_/____//____/\___/\__,_/_/ /_/_/ /_/\___/_/
                                                       /____/
```

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Version](https://img.shields.io/badge/Version-4.0.0-red?style=for-the-badge)](https://github.com/Rashism/Aegis-Scanner)
[![Modules](https://img.shields.io/badge/Modules-17-purple?style=for-the-badge)](https://github.com/Rashism/Aegis-Scanner)
[![Tests](https://img.shields.io/badge/Tests-18%20Passing-brightgreen?style=for-the-badge)](https://github.com/Rashism/Aegis-Scanner)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)](https://github.com/Rashism/Aegis-Scanner)

**Aegis-Scanner is an AI-powered network reconnaissance and vulnerability assessment tool built for authorized red team operations. It doesn't just collect data — it thinks, learns, and decides.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [Screenshots](#-what-it-looks-like)

</div>

---

> ⚠️ **Legal Disclaimer:** This tool is designed **exclusively** for authorized penetration testing and red team operations on systems you have **explicit written permission** to test. Unauthorized use against systems you do not own or have permission to test is illegal and unethical. The authors assume no liability for misuse.

---

## 🧠 The Core Idea

Most network scanners are dumb — they fire packets, collect responses, and dump a report. You do the thinking.

**Aegis is different.** After every scan, it gets smarter:

```
First scan of 192.168.1.100:
  → Found: SSH:22, HTTP:80, MySQL:3306, Redis:6379
  → CVE-2021-41773 detected on Apache 2.4.49
  → Redis has no authentication — immediate CRITICAL

Second scan (one week later):
  🧠 Predicts: SSH (91%), HTTP (88%), Redis (85%) — before scanning
  ⚠️  Change alert: Port 8080 is NEW since last scan
  ⚠️  Change alert: MySQL is CLOSED — something changed
  🛡️  Recommends: Use -T2 --mtu 1280 (best evasion for this target)
  🔍  Auto-recon: Redis connected without auth → immediate exploit path
  👁️  Stealth score: 42/100 — you were probably detected, here's a better command
```

---

## ✨ Features

### 🧠 Adaptive Intelligence Engine *(v4 — Unique)*
The most advanced feature. Aegis builds a persistent intelligence database from every scan:
- **Port prediction** — Before scanning, predicts which ports are likely open based on historical data
- **Change detection** — Alerts when new ports appear, ports close, or service versions change
- **Evasion memory** — Remembers which Nmap args achieved the best OPSEC score against each target
- **Subnet patterns** — Learns patterns across entire subnets, not just individual IPs
- **Time decay** — Old data loses weight automatically, keeping predictions accurate

### 🔍 Smart Auto-Recon Loop *(v4 — Unique)*
After the initial scan, Aegis automatically deep-dives every discovered service:

| Service | What it checks |
|---------|---------------|
| Redis | Auth bypass (PING without password) |
| MongoDB | Unauthenticated wire protocol access |
| Elasticsearch | Cluster info + index enumeration |
| SMB | MS17-010 (EternalBlue), guest access, share enum |
| Docker | Unauthenticated API → full host RCE |
| Kubernetes | API server exposure |
| FTP | Anonymous login |
| HTTP/S | Admin panels, `.env`, `.git`, weak TLS, cert expiry |
| SSH | Outdated OpenSSH detection |
| MySQL / PostgreSQL | Banner + version + EOL detection |
| Cassandra / ZooKeeper | No-auth access |
| Memcached | Unauthenticated stats |
| Telnet | Always CRITICAL (plaintext credentials) |
| VNC | Open access detection |
| SNMP | Default community string (public) |

### 👁️ Stealth Scoring & Advisor *(v4 — Unique)*
After every scan, answers the question *"Was I detected?"*:
- Scores your stealth from 0–100 based on 10 risk factors
- Identifies what hurt your score (aggressive timing, no MTU fragmentation, etc.)
- Generates an optimized Nmap command for the next attempt

```
Score: 42/100  ████░░░░░░
Detection Risk: HIGH
Likely Detected: ⚠️ YES (confidence: 78%)

Risk Factors:
  [-20] Aggressive Timing (T4) — burst traffic easily detected by IDS
  [-25] IDS Detected — active monitoring confirmed
  [-10] Middlebox/DPI detected — deep packet inspection in path

Better Next Command:
  nmap -sS -T1 --mtu 24 --randomize-hosts --data-length 25 -D RND:5 -p 1-1024 target
```

### 🎯 Multi-Target Campaign Mode *(v4)*
Scan an entire list of targets in parallel:
```bash
python main.py --campaign targets.txt --level 2 --workers 3
```

Supports: IP addresses, hostnames, CIDR ranges, per-target priority and scan level.

### 🤖 Local AI Analysis (Ollama — No Cloud)
- Runs 100% locally via Ollama + Llama3/Mistral
- No data sent to external services
- Analyzes scan results and prioritizes attack paths
- Suggests next best Nmap command
- Triage attack vectors by difficulty and impact

### 🛡️ Pre-Scan Safety
- **Honeypot detection** before main scan to protect operator identity
- **Real-time TCP fingerprinting** — detects middleboxes, firewalls, DPI
- **Automatic evasion profiling** — adapts Nmap args to the target environment

### 🌐 OSINT Intelligence
- GeoIP + ASN + organization lookup
- DNS enumeration + subdomain discovery
- Shodan integration (optional API key)
- VirusTotal reputation check
- AbuseIPDB abuse confidence score
- CDN detection (Cloudflare, Fastly, Akamai) with bypass guidance

### 📊 NSE Scripts — Full Coverage
94 Nmap scripts organized by category:

| Category | Count | Examples |
|----------|-------|---------|
| Vulnerability | 33 | `smb-vuln-ms17-010`, `ssl-heartbleed`, `http-shellshock` |
| Authentication | 30 | `ftp-anon`, `ssh-brute`, `mysql-empty-password` |
| Discovery | 31 | `ssl-cert`, `dns-brute`, `http-title` |

---

## 🏗️ Architecture

```
Aegis-Scanner v4.0
├── core/
│   ├── aegis_engine.py          # 17-phase orchestration pipeline
│   ├── nmap_controller.py       # Nmap wrapper (validation, retry, parsing)
│   └── llm_connector.py         # Local AI (BaseLLMProvider → OllamaProvider)
│
├── intelligence/
│   ├── adaptive_engine.py       # ★ Learns from every scan
│   ├── knowledge_base.py        # Session persistence
│   └── cve_mapper.py            # CPE normalization + NVD API
│
├── modules/
│   ├── auto_recon.py            # ★ 20 service deep-dive handlers
│   ├── stealth_advisor.py       # ★ Stealth scoring + evasion advice
│   ├── campaign.py              # ★ Multi-target parallel scanning
│   ├── realtime_analyzer.py     # TCP fingerprint + middlebox detection
│   ├── osint_engine.py          # DNS/GeoIP/Shodan/VirusTotal/AbuseIPDB
│   ├── evasion_engine.py        # IDS/FW evasion profile builder
│   ├── honeypot_detector.py     # Pre-scan honeypot detection
│   ├── port_analyzer.py         # Risk scoring (182 known ports)
│   ├── vuln_engine.py           # NVD API 2.0 CVE mapping + cache
│   ├── exploit_suggestor.py     # searchsploit + Metasploit DB lookup
│   ├── protocol_inspector.py    # TLS/SSH/HTTP deep inspection
│   ├── attack_chain_mapper.py   # MITRE ATT&CK kill chain mapping
│   ├── lateral_movement.py      # Pivot point + lateral path analysis
│   ├── opset_scorer.py          # OPSEC scoring
│   └── packet_optimizer.py      # RTT-based scan parameter optimization
│
├── reporting/
│   ├── json_reporter.py         # Full JSON report (all 17 modules)
│   └── markdown_reporter.py     # Human-readable Markdown report
│
├── ui/
│   └── tui.py                   # Rich terminal UI (1,100+ lines)
│
└── tests/
    └── test_integration.py      # 18 unit + integration tests (fully mocked)
```

★ = New in v4

---

## 🚀 Installation

### Requirements

```bash
# Required
sudo apt install -y nmap

# Highly recommended
sudo apt install -y tcpdump exploitdb

# For accurate real-time TCP analysis (requires root/sudo)
pip install scapy
```

### Python

```bash
pip install -r requirements.txt
```

### Local AI — Ollama (Free, No Cloud)

```bash
# Install
curl -fsSL https://ollama.com/install.sh | sh    # Linux/Mac
# Windows: https://ollama.com/download/windows

# Download a model (choose based on your RAM)
ollama pull llama3        # 4.7 GB — best quality
ollama pull mistral       # 4.1 GB — lighter
ollama pull phi3          # 2.3 GB — minimum specs

# Start the server
ollama serve
```

---

## 🎮 Usage

### Interactive TUI (Recommended)
```bash
python main.py
```

### Direct Scan
```bash
# Basic scan
python main.py --target 192.168.1.1

# Aggressive scan with full NSE
python main.py --target 192.168.1.1 --level 3

# Full vulnerability scan
python main.py --target 192.168.1.1 --level 4 --ports 1-65535

# Subnet scan
python main.py --target 10.0.0.0/24 --level 2

# Campaign mode (multiple targets)
python main.py --campaign targets.txt --level 2 --workers 3

# Without AI (faster)
python main.py --target 192.168.1.1 --no-ai

# Skip OSINT (faster)
python main.py --target 192.168.1.1 --skip-osint

# Health check
python main.py --health
```

### Campaign File Format
```
# targets.txt
# Comments start with #

192.168.1.1
192.168.1.2    priority=1  level=3
10.0.0.0/24
example.com    ports=80,443  priority=2
```

---

## ⚙️ Configuration

Copy `aegis_config.example.json` to `aegis_config.json` and edit:

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
    "max_retries": 2
  },
  "report": {
    "output_dir": "reports",
    "max_cves_per_service": 5
  },
  "api_keys": {
    "nvd_api_key":        "",
    "shodan_api_key":     "",
    "virustotal_api_key": "",
    "abuseipdb_api_key":  ""
  }
}
```

All API keys are **optional** — Aegis works without any of them.

| API | Cost | What it adds |
|-----|------|-------------|
| NVD | Free | Higher CVE rate limit (50 vs 5 req/30s) |
| Shodan | Paid | Banner grabbing, historical port data |
| VirusTotal | Free (limited) | IP reputation |
| AbuseIPDB | Free | Abuse confidence score |

---

## 📈 Scan Levels

| Level | Name | Timing | NSE Scripts | Use Case |
|-------|------|--------|-------------|----------|
| 1 | Quick | T3 | None | Fast recon, minimal noise |
| 2 | Standard | T3 | 12 discovery | Default — balanced |
| 3 | Aggressive | T4 | 22 (auth+disc) | Internal networks |
| 4 | Full Vuln | T4 | 50+ (all) | Full assessment |
| 5 | Stealth Full | T2 | 50+ + evasion | All ports, IDS evasion |

---

## 📊 Stats

```
Lines of Python:  12,976
Python files:     35
Modules:          17
NSE Scripts:      94 (33 vuln + 30 auth + 31 discovery)
Known ports DB:   182
Tests:            18 (all passing, fully mocked)
Auto-recon:       20 service handlers
```

---

## 🧪 Testing

All tests run without Nmap, Ollama, or internet — everything is mocked:

```bash
python tests/test_integration.py

# With pytest
python -m pytest tests/ -v
```

---

## 📁 Output

Every scan generates two reports:

```
reports/
├── aegis_192-168-1-1_20260424_120000.json   ← Complete machine-readable data
└── aegis_192-168-1-1_20260424_120000.md     ← Human-readable report
```

**JSON report includes all 17 module outputs:**
Nmap results · CVE mapping · Exploit candidates · MITRE ATT&CK ·
OSINT · Real-time network analysis · AI triage ·
Adaptive Intelligence predictions · Auto-Recon findings · Stealth score

---

## 🛡️ OPSEC Guidelines

- Use **Level 1-2** in sensitive environments — minimal noise
- Use **Level 5** only with explicit written permission
- Use `--no-ai` in air-gapped environments
- Protect reports: `chmod 700 reports/`
- For non-attribution: delete `data/adaptive_intelligence.json` before operations
- Never scan targets without written authorization

---

## 📜 License

[MIT License](LICENSE) — See LICENSE file for details.

**This software is provided for authorized security testing only. The authors are not responsible for any misuse or damage caused by this tool.**

---

<div align="center">

**Built for the red team. Powered by AI. Runs locally.**

*Aegis-Scanner v4.0 — Think before you scan.*

</div>
