# aegis-scanner/reporting/markdown_reporter.py
"""
تولید گزارش Markdown شکیل از نتایج اسکن.
رتبه‌بندی آسیب‌پذیری‌ها بر اساس CVSS score.
"""

import logging
from datetime import datetime
from pathlib import Path
from config.settings import ReportSettings
from config.constants import PROJECT_NAME, VERSION, SEVERITY_COLORS

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
    "UNKNOWN":  "⚪",
}


class MarkdownReporter:
    def __init__(self, settings: ReportSettings):
        self.settings = settings
        Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    def generate(self, session) -> str:
        """تولید گزارش Markdown و برگرداندن مسیر"""
        content = self._build_markdown(session)

        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = session.target.replace("/", "_").replace(".", "-")
        filename   = f"aegis_{target_safe}_{timestamp}.md"
        filepath   = Path(self.settings.output_dir) / filename

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info(f"[MDReporter] Report saved: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"[MDReporter] Save failed: {e}")
            return ""

    def _build_markdown(self, session) -> str:
        scan      = session.scan_result
        pa        = session.port_analysis or {}
        vulns     = session.vulnerabilities or []
        exploits  = session.exploit_suggestions or []
        ai        = session.ai_analysis or {}
        opt       = session.optimized_params or {}
        nba       = session.next_best_action or {}
        # Advanced
        honeypot  = getattr(session, "honeypot_analysis", None) or {}
        evasion   = getattr(session, "evasion_profile", None) or {}
        proto     = getattr(session, "protocol_inspection", None) or {}
        chain     = getattr(session, "attack_chain", None) or {}
        opsec     = getattr(session, "opsec_report", None) or {}
        lateral   = getattr(session, "lateral_movement", None) or {}
        # v3 — new sections
        realtime  = getattr(session, "realtime_analysis", None) or {}
        osint     = getattr(session, "osint_data", None) or {}
        triage    = getattr(session, "ai_triage", None) or {}
        # v4
        intel     = getattr(session, "intelligence", None) or {}
        auto_recon = getattr(session, "auto_recon", None) or {}
        stealth   = getattr(session, "stealth_score", None) or {}

        lines = []

        # ─── Header ───────────────────────────────────────────────────────
        lines += [
            f"# {PROJECT_NAME} — Penetration Test Report",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Session ID** | `{session.session_id}` |",
            f"| **Target** | `{session.target}` |",
            f"| **Ports** | `{session.ports}` |",
            f"| **Scan Level** | {session.scan_level} |",
            f"| **Generated** | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |",
            f"| **Duration** | {session.duration:.1f}s |",
            f"| **Tool Version** | {VERSION} |",
            "",
            "---",
            "",
        ]

        # ─── Executive Summary ─────────────────────────────────────────────
        lines += ["## 📊 Executive Summary", ""]

        if scan:
            rtt_info = f"{scan.rtt_ms:.0f}ms RTT, {scan.packet_loss_pct:.0f}% packet loss"
            lines += [
                f"- **Hosts Up:** {scan.hosts_up}",
                f"- **Open Ports:** {len(scan.open_ports)}",
                f"- **Network:** {rtt_info}",
            ]

        if pa:
            score = pa.get("attack_surface_score", 0)
            score_bar = self._score_bar(score)
            lines += [
                f"- **Attack Surface Score:** {score}/10 {score_bar}",
                f"- **Critical Findings:** {pa.get('critical_count', 0)}",
                f"- **High Findings:** {pa.get('high_count', 0)}",
                f"- **Medium Findings:** {pa.get('medium_count', 0)}",
                f"- **Total Vulnerabilities:** {len(vulns)}",
                f"- **Exploit Candidates:** {len(exploits)}",
                "",
                f"> {pa.get('summary', '')}",
            ]

        lines += ["", "---", ""]

        # ─── Network Optimization ──────────────────────────────────────────
        if opt:
            lines += [
                "## ⚙️ Scan Optimization",
                "",
                f"| Parameter | Value |",
                f"|-----------|-------|",
                f"| Timing | `{opt.get('timing', 'N/A')}` |",
                f"| MTU | `{opt.get('mtu', 'N/A')}` bytes |",
                f"| Min Rate | `{opt.get('min_rate', 'N/A')}` pkt/s |",
                f"| Max Retries | `{opt.get('max_retries', 'N/A')}` |",
                "",
                f"**Reasoning:** {opt.get('reasoning', 'N/A')}",
                "",
                "---", "",
            ]

        # ─── Open Ports ───────────────────────────────────────────────────
        if scan and scan.open_ports:
            lines += ["## 🔌 Open Ports", ""]
            lines += ["| Port | Proto | Service | Product | Version |",
                      "|------|-------|---------|---------|---------|"]
            for p in sorted(scan.open_ports, key=lambda x: x["port"]):
                lines.append(
                    f"| {p['port']} | {p.get('proto','tcp').upper()} | "
                    f"{p['service']} | {p.get('product', '')} | {p.get('version', '')} |"
                )
            lines += ["", "---", ""]

        # ─── Port Risk Analysis ────────────────────────────────────────────
        findings = pa.get("findings", [])
        if findings:
            lines += ["## 🚨 Risk Analysis by Port", ""]
            for f in findings:
                emoji = SEVERITY_EMOJI.get(f["risk_level"], "⚪")
                lines += [
                    f"### {emoji} Port {f['port']}/{f['proto'].upper()} — "
                    f"{f['service']} [{f['risk_level']}]",
                    "",
                ]
                if f.get("product") or f.get("version"):
                    lines.append(f"**Detected:** {f.get('product','')} {f.get('version','')}")
                if f.get("cpe"):
                    lines.append(f"**CPE:** `{f['cpe']}`")
                if f.get("risk_reasons"):
                    lines += ["", "**Risk Reasons:**"]
                    for r in f["risk_reasons"]:
                        lines.append(f"- {r}")
                if f.get("notes"):
                    lines += ["", "**Notes:**"]
                    for n in f["notes"]:
                        lines.append(f"- {n}")
                if f.get("script_findings", {}).get("critical_scripts"):
                    lines += ["", "**⚠️ Script Findings:**"]
                    for s in f["script_findings"]["critical_scripts"]:
                        lines.append(f"- `{s}`")
                lines += [""]
            lines += ["---", ""]

        # ─── Vulnerabilities (sorted by CVSS) ─────────────────────────────
        if vulns:
            lines += [
                "## 🔓 Vulnerabilities (Sorted by CVSS Score)",
                "",
                "| CVE ID | Service | Port | CVSS | Severity | Published |",
                "|--------|---------|------|------|----------|-----------|",
            ]
            for v in vulns[:self.settings.max_cves_per_service * 10]:
                emoji = SEVERITY_EMOJI.get(v.get("severity", ""), "⚪")
                lines.append(
                    f"| [{v.get('cve_id','')}](https://nvd.nist.gov/vuln/detail/{v.get('cve_id','')}) "
                    f"| {v.get('service','')} | {v.get('port','')} "
                    f"| **{v.get('cvss_score',0):.1f}** "
                    f"| {emoji} {v.get('severity','')} "
                    f"| {v.get('published','')} |"
                )
            lines += [""]

            # Top 5 آسیب‌پذیری با جزئیات
            lines += ["### 📋 Top Vulnerability Details", ""]
            for v in vulns[:5]:
                emoji = SEVERITY_EMOJI.get(v.get("severity", ""), "⚪")
                lines += [
                    f"#### {emoji} {v.get('cve_id','')} — CVSS {v.get('cvss_score',0):.1f}",
                    "",
                    f"**Affected:** {v.get('service','')} on port {v.get('port','')}",
                    f"**Severity:** {v.get('severity','')}",
                    f"**Published:** {v.get('published','')}",
                    "",
                    f"**Description:** {v.get('description', 'N/A')}",
                    "",
                ]
                if v.get("references"):
                    lines.append("**References:**")
                    for ref in v["references"][:2]:
                        lines.append(f"- {ref}")
                    lines.append("")

            lines += ["---", ""]

        # ─── Exploit Suggestions ──────────────────────────────────────────
        if exploits:
            lines += ["## 💥 Exploit Candidates", ""]
            for e in exploits:
                emoji = "✅" if e.get("verified") else "⚠️"
                lines += [
                    f"### {emoji} {e.get('cve_id','')}",
                    f"**Title:** {e.get('title','')}",
                    f"**Host:** `{e.get('host','')}:{e.get('port','')}`",
                    f"**Service:** {e.get('service','')}",
                    f"**CVSS:** {e.get('cvss_score',0):.1f}",
                ]
                if e.get("metasploit_module"):
                    lines += [
                        "",
                        "**Metasploit:**",
                        f"```",
                        f"use {e['metasploit_module']}",
                        f"set RHOSTS {e.get('host','')}",
                        f"set RPORT {e.get('port','')}",
                        f"run",
                        f"```",
                    ]
                if e.get("exploit_db_id"):
                    lines += [
                        f"**EDB-ID:** `{e['exploit_db_id']}`",
                        f"**Copy:** `searchsploit -m {e['exploit_db_id']}`",
                    ]
                lines += [f"**Notes:** {e.get('notes','')}", ""]
            lines += ["---", ""]

        # ─── AI Analysis ──────────────────────────────────────────────────
        if ai and self.settings.include_ai_analysis:
            lines += ["## 🤖 AI Analysis (Llama 3)", ""]
            if ai.get("risk_level"):
                lines.append(f"**Overall Risk:** {SEVERITY_EMOJI.get(ai['risk_level'],'')} {ai['risk_level']}")
            if ai.get("attack_surface_summary"):
                lines += ["", f"**Summary:** {ai['attack_surface_summary']}"]
            lines += [""]

        # ─── Next Best Action ─────────────────────────────────────────────
        if nba:
            lines += [
                "## 🎯 Recommended Next Action",
                "",
                f"**Command:**",
                "```bash",
                nba.get("recommended_command", ""),
                "```",
                f"**Timing Template:** `{nba.get('timing_template','')}`",
                f"**Rationale:** {nba.get('rationale','')}",
                "",
                "---", "",
            ]

        # ─── Exposed Resources Summary ─────────────────────────────────────
        lines += ["## 📌 Exposed Resources", ""]

        dbs = pa.get("exposed_databases", [])
        if dbs:
            lines += ["### 🗄️ Databases", ""]
            for db in dbs:
                lines.append(
                    f"- **{db['service'].upper()}** on port `{db['port']}` "
                    f"— Risk: {SEVERITY_EMOJI.get(db['risk'],'')} {db['risk']}"
                )
            lines.append("")

        ra = pa.get("exposed_remote_access", [])
        if ra:
            lines += ["### 🖥️ Remote Access Services", ""]
            for r in ra:
                lines.append(
                    f"- **{r['service'].upper()}** on port `{r['port']}` "
                    f"— Risk: {SEVERITY_EMOJI.get(r['risk'],'')} {r['risk']}"
                )
            lines.append("")

        nsp = pa.get("non_standard_ports", [])
        if nsp:
            lines += ["### ❓ Non-Standard Ports", ""]
            for p in nsp:
                lines.append(f"- Port `{p['port']}` running `{p['service']}`")
            lines.append("")

        lines += ["---", ""]

        # ─── Honeypot Analysis ────────────────────────────────────────────
        if honeypot:
            verdict = honeypot.get("verdict", "CLEAN")
            conf    = honeypot.get("confidence", 0)
            emoji   = "🍯" if honeypot.get("is_honeypot") else "✅"
            lines += [
                "## 🍯 Honeypot Detection", "",
                f"| Field | Value |", f"|-------|-------|",
                f"| **Verdict** | {emoji} {verdict} |",
                f"| **Confidence** | {conf:.0%} |",
                f"| **Risk** | {honeypot.get('risk_of_proceeding','')} |",
                "", f"**Recommendation:** {honeypot.get('recommendation','')}", "",
            ]
            for s in honeypot.get("matched_signatures", []):
                lines.append(f"- Port `{s.get('port')}` → **{s.get('honeypot')}** ({s.get('confidence',0):.0%})")
            lines += ["", "---", ""]

        # ─── Evasion Profile ──────────────────────────────────────────────
        if evasion and evasion.get("final_nmap_args"):
            lines += [
                "## 🛡️ Evasion Profile", "",
                f"| Parameter | Value |", f"|-----------|-------|",
                f"| Firewall | {'✅ Detected' if evasion.get('firewall_detected') else 'Not detected'} |",
                f"| IDS | {'✅ Detected' if evasion.get('ids_detected') else 'Not detected'} |",
                f"| Detection Risk | **{evasion.get('detection_risk','')}** |",
                f"| Evasion Score | `{evasion.get('evasion_score',0)}/10` |",
                f"| Timing | `{evasion.get('recommended_timing','')}` |",
                f"| MTU | `{evasion.get('recommended_mtu','')}` bytes |",
                "", "**Optimized Nmap Command:**",
                "```bash", evasion.get("final_nmap_args",""), "```", "",
            ]
            for t in evasion.get("techniques_applied", []):
                lines.append(f"- {t}")
            lines += ["", "---", ""]

        # ─── Protocol Deep Inspection ─────────────────────────────────────
        if proto and proto.get("all_findings"):
            lines += [
                "## 🔬 Protocol Deep Inspection", "",
                f"**Overall Risk:** {SEVERITY_EMOJI.get(proto.get('overall_risk','INFO'),'🔵')} {proto.get('overall_risk','')}", "",
            ]
            for t in proto.get("tls_results", []):
                lines += [
                    f"### TLS — Port {t.get('port','')}",
                    f"- Version: `{t.get('tls_version','')}` {'⚠️ WEAK' if t.get('weak_version') else '✅'}",
                    f"- Cipher: `{t.get('cipher_suite','')}` {'⚠️ WEAK' if t.get('weak_cipher') else ''}",
                    f"- TLS 1.3: {'✅' if t.get('supports_tls13') else '❌'}",
                    f"- Cert: `{t.get('cert_subject','')}` {'⛔ EXPIRED' if t.get('cert_expired') else ''}{'⚠️ SELF-SIGNED' if t.get('cert_self_signed') else ''}",
                    "",
                ]
            for s in proto.get("ssh_results", []):
                lines += [f"### SSH — Port {s.get('port','')} [{s.get('risk_level','')}]",
                          f"- Banner: `{s.get('server_banner','')}`"]
                if s.get("weak_kex"):    lines.append(f"- ⚠️ Weak KEX: `{', '.join(s['weak_kex'])}`")
                if s.get("weak_ciphers"):lines.append(f"- ⚠️ Weak Ciphers: `{', '.join(s['weak_ciphers'])}`")
                if s.get("weak_macs"):   lines.append(f"- ⚠️ Weak MACs: `{', '.join(s['weak_macs'])}`")
                lines.append("")
            for h_r in proto.get("http_results", []):
                lines += [f"### HTTP — Port {h_r.get('port','')} [{h_r.get('risk_level','')}]"]
                missing = h_r.get("missing_headers", [])
                if missing: lines.append(f"- Missing headers: `{', '.join(m['header'] for m in missing[:4])}`")
                if h_r.get("dangerous_methods"): lines.append(f"- ⚠️ Dangerous Methods: `{', '.join(h_r['dangerous_methods'])}`")
                lines.append("")
            lines += ["---", ""]

        # ─── MITRE ATT&CK Kill Chain ──────────────────────────────────────
        if chain and chain.get("total_techniques", 0) > 0:
            lines += [
                "## ⚔️ MITRE ATT&CK Kill Chain", "",
                chain.get("summary", ""), "",
                f"| Total Techniques | CRITICAL | HIGH | Highest Impact |",
                f"|-----------------|----------|------|----------------|",
                f"| {chain.get('total_techniques',0)} | {chain.get('critical_count',0)} | {chain.get('high_count',0)} | **{chain.get('highest_impact','')}** |",
                "",
            ]
            # Initial access vectors
            surface = chain.get("attack_surface", [])
            if surface:
                lines += ["### 🎯 Initial Access Vectors", ""]
                for s in surface:
                    lines.append(f"- {SEVERITY_EMOJI.get(s.get('severity',''),'⚪')} `{s.get('service','')}:{s.get('port','')}` — `{s.get('technique','')}`")
                lines.append("")
            # Kill chain
            kc = chain.get("kill_chain", {})
            tactic_order = ["Initial Access","Execution","Persistence","Privilege Escalation",
                            "Credential Access","Lateral Movement","Collection","Exfiltration","Impact"]
            for tactic in tactic_order:
                steps = kc.get(tactic, [])
                if not steps: continue
                lines.append(f"**{tactic}:**")
                for step in steps[:3]:
                    lines.append(
                        f"- {SEVERITY_EMOJI.get(step.get('severity',''),'⚪')} "
                        f"`{step.get('technique_id','')}` [{step.get('name','')}]"
                        f"({step.get('mitre_url','')}) "
                        f"← `{step.get('affected_service','')}:{step.get('affected_port','')}`"
                    )
                    if step.get("tools"):
                        lines.append(f"  - Tools: `{', '.join(step['tools'][:3])}`")
                lines.append("")
            # Critical paths
            for i, path in enumerate(chain.get("critical_paths", [])[:2], 1):
                ia = path.get("initial_access", {})
                lines.append(f"**Attack Path {i}:** `{ia.get('service','')}` [{ia.get('technique','')}]")
                for step in path.get("steps", []):
                    lines.append(f"  → `{step.get('tactic','')}` `{step.get('technique','')}`")
                lines.append(f"  → 💥 **{path.get('potential_impact','')}**")
                lines.append("")
            lines += ["---", ""]

        # ─── Lateral Movement ─────────────────────────────────────────────
        if lateral and lateral.get("pivot_count", 0) > 0:
            lines += [
                "## 🔀 Lateral Movement", "",
                lateral.get("network_summary", ""), "",
                f"| Pivot Points | Stealth Paths | Easy Paths |",
                f"|-------------|--------------|-----------|",
                f"| {lateral.get('pivot_count',0)} | {lateral.get('stealth_path_count',0)} | {lateral.get('easy_path_count',0)} |",
                "",
            ]
            rec = lateral.get("recommended_pivot")
            if rec:
                lines += [
                    "### 🎯 Recommended Pivot", "",
                    f"**`{rec.get('service','')}:{rec.get('port','')}` | Stealth: {rec.get('stealth','')} | ETA: {rec.get('time_est','')}**",
                    "", f"{rec.get('reason','')}", "",
                ]
                if rec.get("command"):
                    lines += ["```bash", rec["command"], "```", ""]
            pivots = lateral.get("pivot_points", [])
            if pivots:
                lines += ["| Service | Port | Score | Stealth | ETA |",
                          "|---------|------|-------|---------|-----|"]
                for pv in pivots[:6]:
                    lines.append(f"| `{pv.get('service','')}` | `{pv.get('port','')}` | `{pv.get('pivot_score',0)}/10` | {pv.get('stealth_level','')} | {pv.get('estimated_time','')} |")
                lines.append("")
            lines += ["---", ""]

        # ─── OPSEC Score ──────────────────────────────────────────────────
        if opsec:
            grade    = opsec.get("opsec_grade", "?")
            score_op = opsec.get("opsec_score", 0)
            risk_op  = opsec.get("detection_risk", "")
            g_emoji  = {"A+":"🟢","A":"🟢","B":"🟡","C":"🟡","D":"🟠","E":"🔴","F":"🔴"}.get(grade,"⚪")
            lines += [
                "## 🔐 OPSEC Assessment", "",
                f"| OPSEC Score | Grade | Detection Risk |",
                f"|------------|-------|----------------|",
                f"| **{score_op}/10** | {g_emoji} **{grade}** | **{risk_op}** |",
                "", f"{opsec.get('analysis','')}", "",
            ]
            sc = opsec.get("stealth_command","")
            if sc:
                lines += ["**Stealth Command:**", "```bash", sc, "```", ""]
            ci = opsec.get("critical_issues", [])
            if ci:
                lines += ["**⚠️ Critical Issues:**"]
                for issue in ci: lines.append(f"- {issue}")
                lines.append("")
            logs = opsec.get("likely_logs", [])
            if logs:
                lines += ["**Likely Log Artifacts on Target:**", "",
                          "| Source | Level | Likelihood |",
                          "|--------|-------|-----------|"]
                for lg in logs:
                    lines.append(f"| {lg.get('source','')} | `{lg.get('level','')}` | {lg.get('likelihood',0):.0%} |")
                lines.append("")
            lines += ["---", ""]

        # ─── OSINT Intelligence ───────────────────────────────────────────────
        if osint:
            lines += ["## 🌐 OSINT Intelligence", ""]
            geo = osint.get("geo", {})
            if geo:
                lines += [
                    "### 🗺️ Geo / ASN",
                    "",
                    f"| Field | Value |",
                    f"|-------|-------|",
                    f"| **IP** | `{geo.get('ip', 'N/A')}` |",
                    f"| **Country** | {geo.get('country', 'N/A')} ({geo.get('country_code', '')}) |",
                    f"| **City** | {geo.get('city', 'N/A')} |",
                    f"| **ASN** | `{geo.get('asn', 'N/A')}` |",
                    f"| **Org** | {geo.get('org', 'N/A')} |",
                    f"| **ISP** | {geo.get('isp', 'N/A')} |",
                    f"| **Tor Exit** | {'⚠️ YES' if geo.get('is_tor') else 'No'} |",
                    f"| **Proxy/VPN** | {'⚠️ YES' if geo.get('is_proxy') else 'No'} |",
                    f"| **Hosting** | {'Yes' if geo.get('is_hosting') else 'No'} |",
                    "",
                ]
            dns = osint.get("dns", {})
            if dns:
                resolved = dns.get("resolved_ips", [])
                mx       = dns.get("mx_records", [])
                ns       = dns.get("ns_records", [])
                subs     = dns.get("subdomains", [])
                lines += ["### 🔍 DNS Enumeration", ""]
                if resolved:
                    lines += [f"**Resolved IPs:** {', '.join(str(i) for i in resolved[:10])}"]
                if ns:
                    lines += [f"**Nameservers:** {', '.join(str(n) for n in ns[:5])}"]
                if mx:
                    lines += [f"**MX Records:** {', '.join(str(m) for m in mx[:5])}"]
                if subs:
                    lines += ["", f"**Discovered Subdomains ({len(subs)}):**"]
                    for s in subs[:20]:
                        lines.append(f"- `{s}`")
                lines.append("")
            shodan = osint.get("shodan", {})
            if shodan and not shodan.get("error"):
                lines += ["### 📡 Shodan Intelligence", ""]
                if shodan.get("ports"):
                    lines += [f"**Known Open Ports:** {shodan.get('ports', [])}"]
                if shodan.get("vulns"):
                    lines += [f"**Shodan CVEs:** {', '.join(shodan.get('vulns', [])[:10])}"]
                if shodan.get("tags"):
                    lines += [f"**Tags:** {', '.join(shodan.get('tags', []))}"]
                lines.append("")
            rep = osint.get("reputation", {})
            if rep:
                abuse_score = rep.get("abuse_confidence_score", 0)
                vt_malicious = rep.get("vt_malicious", 0)
                if abuse_score or vt_malicious:
                    lines += [
                        "### ⚠️ Reputation / Threat Intel",
                        "",
                        f"| Source | Score | Status |",
                        f"|--------|-------|--------|",
                        f"| AbuseIPDB | {abuse_score}% confidence | "
                        f"{'🔴 MALICIOUS' if abuse_score > 50 else '🟢 CLEAN'} |",
                        f"| VirusTotal | {vt_malicious} detections | "
                        f"{'🔴 FLAGGED' if vt_malicious > 0 else '🟢 CLEAN'} |",
                        "",
                    ]
            risk_indicators = osint.get("risk_indicators", [])
            if risk_indicators:
                lines += ["### 🚩 OSINT Risk Indicators", ""]
                for ri in risk_indicators:
                    lines.append(f"- {ri}")
                lines.append("")
            lines += ["---", ""]

        # ─── Realtime Network Analysis ────────────────────────────────────────
        if realtime:
            lines += ["## 📡 Real-Time Network Analysis", ""]
            hs = realtime.get("handshake", {})
            bh = realtime.get("behavior", {})
            ad = realtime.get("adaptation", {})
            if hs:
                lines += [
                    "### TCP Handshake",
                    "",
                    f"| Metric | Value |",
                    f"|--------|-------|",
                    f"| RTT | `{hs.get('rtt_ms', 'N/A')} ms` |",
                    f"| Server TTL | `{hs.get('server_ttl', 'N/A')}` |",
                    f"| Server Window | `{hs.get('server_window', 'N/A')}` |",
                    f"| MSS | `{hs.get('server_mss', 'N/A')}` |",
                    f"| OS Guess | **{hs.get('os_guess', 'Unknown')}** |",
                    "",
                ]
            if bh:
                middlebox = "⚠️ **YES**" if bh.get("middlebox_detected") else "No"
                throttle  = "⚠️ **YES**" if bh.get("throttling_detected") else "No"
                lines += [
                    "### Network Behavior",
                    "",
                    f"| Metric | Value |",
                    f"|--------|-------|",
                    f"| Avg RTT | `{bh.get('avg_rtt_ms', 'N/A')} ms` |",
                    f"| Std Dev | `{bh.get('std_rtt_ms', 'N/A')} ms` |",
                    f"| RST Injections | `{bh.get('rst_injections', 0)}` |",
                    f"| Middlebox Detected | {middlebox} |",
                    f"| Throttling | {throttle} |",
                    f"| Recommended Timing | **{bh.get('recommended_timing', 'N/A')}** |",
                    f"| Recommended MTU | `{bh.get('recommended_mtu', 'N/A')}` |",
                    "",
                ]
                notes = bh.get("analysis_notes", [])
                if notes:
                    lines += ["**Analysis Notes:**"]
                    for n in notes:
                        lines.append(f"- {n}")
                    lines.append("")
            if ad and ad.get("changes_made"):
                lines += [
                    "### Scan Adaptation",
                    "",
                    f"**Original Args:** `{ad.get('original_args', '')}`",
                    f"**Adapted Args:** `{ad.get('adapted_args', '')}`",
                    f"**Confidence:** {ad.get('confidence', 0):.0%}",
                    "",
                    "**Changes Applied:**",
                ]
                for c in ad.get("changes_made", []):
                    lines.append(f"- {c}")
                lines.append("")
            lines += ["---", ""]

        # ─── AI Attack Path Triage ────────────────────────────────────────────
        if triage:
            lines += ["## 🎯 AI Attack Path Triage", ""]
            priority_targets = triage.get("priority_targets", [])
            if priority_targets:
                lines += [
                    "### Priority Targets",
                    "",
                    "| Port | Service | Attack Vector | Difficulty | Impact |",
                    "|------|---------|---------------|------------|--------|",
                ]
                for pt in priority_targets[:10]:
                    diff_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}.get(
                        pt.get("difficulty", ""), "⚪"
                    )
                    imp_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
                        pt.get("impact", ""), "⚪"
                    )
                    lines.append(
                        f"| {pt.get('port', '')} | {pt.get('service', '')} | "
                        f"{pt.get('attack_vector', '')} | "
                        f"{diff_emoji} {pt.get('difficulty', '')} | "
                        f"{imp_emoji} {pt.get('impact', '')} |"
                    )
                lines.append("")

                # جزئیات هر target
                for pt in priority_targets[:5]:
                    if pt.get("first_step"):
                        lines += [
                            f"**Port {pt.get('port')} — First Step:**",
                            f"```",
                            pt.get("first_step", ""),
                            "```",
                            "",
                        ]

            quick_wins = triage.get("quick_wins", [])
            if quick_wins:
                lines += ["### ⚡ Quick Wins", ""]
                for qw in quick_wins:
                    lines.append(f"- {qw}")
                lines.append("")

            pivot_ops = triage.get("pivot_opportunities", [])
            if pivot_ops:
                lines += ["### 🔄 Pivot Opportunities", ""]
                for po in pivot_ops:
                    lines.append(f"- {po}")
                lines.append("")

            rec_order = triage.get("recommended_order", [])
            if rec_order:
                lines += [f"**Recommended Attack Order:** {' → '.join(str(p) for p in rec_order)}", ""]

            assessment = triage.get("overall_assessment", "")
            if assessment:
                lines += [f"> 🤖 **AI Assessment:** {assessment}", ""]

            lines += ["---", ""]

        # ─── v4: Adaptive Intelligence ───────────────────────────────────────
        if intel and intel.get("prior_scans", 0) > 0:
            lines += ["## 🧠 Adaptive Intelligence (v4)", ""]
            lines += [f"**Prior scans:** {intel.get('prior_scans')} | "
                      f"**Confidence:** {intel.get('confidence_overall',0):.0%}", ""]
            if intel.get("trend_summary"):
                lines += [f"> {intel['trend_summary']}", ""]
            changes = intel.get("change_alerts", [])
            if changes:
                lines += [f"### ⚠️  {len(changes)} Changes Detected", ""]
                for ch in changes[:10]:
                    lines.append(
                        f"- **{ch.get('change_type','').replace('_',' ').title()}** "
                        f"port {ch.get('port','')}: "
                        f"`{ch.get('old_value','')}` → `{ch.get('new_value','')}`"
                    )
                lines.append("")
            preds = intel.get("port_predictions", [])
            if preds:
                lines += ["### 🎯 Port Predictions", ""]
                lines += ["| Port | Service | Confidence | Basis |",
                          "|------|---------|------------|-------|"]
                for p in preds[:8]:
                    lines.append(
                        f"| {p.get('port')} | {p.get('service','')} | "
                        f"{p.get('confidence',0):.0%} | {p.get('basis','')} |"
                    )
                lines.append("")
            lines += ["---", ""]

        # ─── v4: Auto-Recon ───────────────────────────────────────────────────
        if auto_recon and auto_recon.get("total_checks", 0) > 0:
            findings = auto_recon.get("findings", [])
            crits    = auto_recon.get("critical_findings", [])
            highs    = auto_recon.get("high_findings", [])
            lines += [
                f"## 🔍 Auto-Recon Results",
                "",
                f"**Checks:** {auto_recon.get('total_checks')} | "
                f"**Critical:** {len(crits)} | **High:** {len(highs)}",
                "",
            ]
            if findings:
                lines += ["| Service | Port | Check | Severity | Result |",
                          "|---------|------|-------|----------|--------|"]
                for f_item in findings[:20]:
                    sev = f_item.get("severity","")
                    lines.append(
                        f"| {f_item.get('service','')} | {f_item.get('port','')} | "
                        f"{f_item.get('check_name','')} | {sev} | "
                        f"{f_item.get('result','')[:50]} |"
                    )
                lines.append("")
            if crits:
                lines += ["### ⚡ Critical Findings — Immediate Action", ""]
                for cf in crits[:5]:
                    cmd = cf.get("command_run","")
                    lines += [f"**{cf.get('check_name','')}** — {cf.get('result','')}"]
                    if cmd:
                        lines += [f"```\n{cmd}\n```"]
                    lines.append("")
            lines += ["---", ""]

        # ─── v4: Stealth Analysis ─────────────────────────────────────────────
        if stealth:
            s_score = stealth.get("score", 0)
            s_risk  = stealth.get("detection_risk", "UNKNOWN")
            s_det   = stealth.get("estimated_detected", False)
            lines += [
                "## 👁 Stealth Analysis (v4)", "",
                f"| Metric | Value |",
                f"|--------|-------|",
                f"| **Score** | {s_score:.0f}/100 |",
                f"| **Detection Risk** | {s_risk} |",
                f"| **Likely Detected** | {'⚠️ YES' if s_det else '✓ NO'} |",
                f"| **Confidence** | {stealth.get('confidence',0):.0%} |",
                "",
            ]
            deductions = stealth.get("deductions", [])
            if deductions:
                lines += ["### Risk Factors", ""]
                for d in deductions:
                    lines.append(f"- **-{d.get('penalty',0)} pts** {d.get('factor','')}: {d.get('detail','')}")
                lines.append("")
            recs = stealth.get("recommendations", [])
            if recs:
                lines += ["### Improvements for Next Scan", ""]
                for r in recs[:5]:
                    lines.append(f"- [{r.get('priority','')}] **{r.get('action','')}** — {r.get('detail','')}")
                lines.append("")
            better = stealth.get("better_command", "")
            if better:
                lines += ["### Recommended Next Command", "", f"```bash\n{better}\n```", ""]
            lines += ["---", ""]

        # ─── Footer ───────────────────────────────────────────────────────
        if session.errors:
            lines += ["## ⚠️ Errors During Scan", ""]
            for err in session.errors:
                lines.append(f"- {err}")
            lines += [""]

        lines += [
            "---",
            f"*Report generated by {PROJECT_NAME} v{VERSION} — "
            f"For authorized penetration testing only.*",
        ]

        return "\n".join(lines)

    @staticmethod
    def _score_bar(score: float) -> str:
        """نمایش گرافیکی امتیاز با emoji"""
        filled = int(score)
        return "█" * filled + "░" * (10 - filled) + f" ({score}/10)"
