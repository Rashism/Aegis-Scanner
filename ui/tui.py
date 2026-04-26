# aegis-scanner/ui/tui.py
"""
رابط کاربری ترمینال (TUI) — v3 Red Team Edition
بازنویسی کامل با Rich برای نمایش تمام 14 ماژول
"""

import sys
import time
import threading
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn,
        TextColumn, TimeElapsedColumn, TaskProgressColumn
    )
    from rich.prompt import Prompt, IntPrompt, Confirm
    from rich.text import Text
    from rich.rule import Rule
    from rich.columns import Columns
    from rich.padding import Padding
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from config.constants import PROJECT_NAME, VERSION, NMAP_SCAN_LEVELS

console = Console()

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}
SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "dim",
}

BANNER = r"""
    ___                _      ____
   /   | ___  ____ _(_)____/ ___/_________ _____  ____  ___  _____
  / /| |/ _ \/ __ `/ / ___/\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / ___ /  __/ /_/ / (__  )___/ / /__/ /_/ / / / / / / /  __/ /
/_/  |_\___/\__, /_/____//____/\___/\__,_/_/ /_/_/ /_/\___/_/
           /____/
"""


class AegisTUI:

    def __init__(self):
        if not RICH_AVAILABLE:
            raise RuntimeError("Rich not installed. Run: pip install rich")
        self._progress_obj: Optional[Progress] = None
        self._progress_task = None
        self._lock = threading.Lock()

    # ─── Banner ───────────────────────────────────────────────────────────
    def show_banner(self) -> None:
        console.print(Panel(
            Text(BANNER, style="bold cyan", justify="center"),
            subtitle=f"[dim]v{VERSION} | AI-Powered Network Scanner | Red Team Framework[/dim]",
            border_style="cyan",
            padding=(0, 2),
        ))
        console.print()

    # ─── Health check ─────────────────────────────────────────────────────
    def show_health(self, health: dict) -> None:
        # جداسازی: ابزارهای سیستم / API keys
        system_items = {
            "nmap", "llm", "knowledge_base",
            "searchsploit", "tcpdump", "ping", "scapy"
        }
        api_items = {
            "nvd_api_key", "shodan_key",
            "virustotal_key", "abuseipdb_key"
        }

        # جدول سیستم
        sys_table = Table(
            title="[bold]🔧 System Tools[/bold]",
            box=box.ROUNDED, border_style="cyan", expand=False
        )
        sys_table.add_column("Tool", style="bold", min_width=16)
        sys_table.add_column("Status", justify="center", min_width=12)

        for k, ok in health.items():
            if k in system_items:
                label = k.replace("_", " ").title()
                if ok:
                    status = "[bold green]✓ Ready[/bold green]"
                else:
                    if k in ("searchsploit", "tcpdump", "scapy"):
                        status = "[yellow]○ Optional[/yellow]"
                    elif k == "llm":
                        # چک: سرور بالاست ولی مدل نیست؟
                        llm_server_up = health.get("llm_server_up", False)
                        if llm_server_up:
                            status = "[yellow]⚠ Model Missing[/yellow]"
                        else:
                            status = "[bold red]✗ Offline[/bold red]"
                    else:
                        status = "[bold red]✗ Missing[/bold red]"
                sys_table.add_row(label, status)

        # جدول API keys
        # Adaptive Intelligence stats
        adaptive_stats = health.get("adaptive_stats", {})
        if adaptive_stats and adaptive_stats.get("total_scans", 0) > 0:
            ai_stats_text = (
                f"[cyan]{adaptive_stats.get('total_scans', 0)}[/cyan] scans | "
                f"[cyan]{adaptive_stats.get('targets_known', 0)}[/cyan] targets | "
                f"[cyan]{adaptive_stats.get('subnets_known', 0)}[/cyan] subnets | "
                f"[cyan]{adaptive_stats.get('services_known', 0)}[/cyan] services"
            )
            console.print(Panel(
                ai_stats_text,
                title="[bold magenta]🧠 Adaptive Intelligence Database[/bold magenta]",
                border_style="magenta",
                padding=(0, 2),
            ))
            console.print()

        api_table = Table(
            title="[bold]🔑 API Keys[/bold]",
            box=box.ROUNDED, border_style="yellow", expand=False
        )
        api_table.add_column("Service", style="bold", min_width=16)
        api_table.add_column("Status", justify="center", min_width=12)

        api_labels = {
            "nvd_api_key":    "NVD (CVE)",
            "shodan_key":     "Shodan",
            "virustotal_key": "VirusTotal",
            "abuseipdb_key":  "AbuseIPDB",
        }
        for k, label in api_labels.items():
            ok = health.get(k, False)
            if ok:
                status = "[bold green]✓ Active[/bold green]"
            else:
                status = "[dim]○ Optional[/dim]"
            api_table.add_row(label, status)

        console.print(Columns([sys_table, api_table], equal=False, expand=False))
        console.print()

    # ─── Input collection ─────────────────────────────────────────────────
    def collect_scan_params(self) -> dict:
        console.print(Rule("[bold cyan]⚙  Scan Configuration[/bold cyan]"))
        console.print()

        # Target
        target = Prompt.ask(
            "  [bold cyan]Target[/bold cyan] [dim](IP / hostname / CIDR)[/dim]",
            default="192.168.1.1"
        ).strip()

        # Ports
        console.print()
        console.print("  [dim]Examples: 22,80,443 | 1-1024 | 1-65535 | top100[/dim]")
        ports = Prompt.ask(
            "  [bold cyan]Port range[/bold cyan]",
            default="1-1024"
        ).strip()

        # Scan level
        console.print()
        level_table = Table(
            box=box.SIMPLE, show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        level_table.add_column("  #", justify="center", style="bold cyan", width=4)
        level_table.add_column("Name",        style="bold",  width=14)
        level_table.add_column("Description", style="dim",   width=50)
        level_table.add_column("NSE Scripts", justify="center", width=12)

        nse_counts = {1: "—", 2: "12", 3: "22", 4: "50+", 5: "50+"}
        for lvl, data in NMAP_SCAN_LEVELS.items():
            level_table.add_row(
                str(lvl),
                data["label"],
                data.get("desc", ""),
                nse_counts.get(lvl, "—"),
            )
        console.print(Padding(level_table, (0, 2)))
        console.print()

        scan_level = IntPrompt.ask(
            "  [bold cyan]Scan level[/bold cyan]",
            default=2,
            choices=["1", "2", "3", "4", "5"],
        )

        # AI
        console.print()
        use_ai = Confirm.ask(
            "  [bold cyan]Enable AI analysis[/bold cyan] [dim](local Ollama)[/dim]",
            default=True
        )

        # Skip flags
        console.print()
        skip_osint = not Confirm.ask(
            "  [bold cyan]Enable OSINT[/bold cyan] [dim](DNS / GeoIP / reputation)[/dim]",
            default=True
        )
        skip_realtime = not Confirm.ask(
            "  [bold cyan]Enable Realtime analysis[/bold cyan] [dim](TCP fingerprint / middlebox)[/dim]",
            default=True
        )

        console.print()
        console.print(Rule("[bold green]  Scan starting...[/bold green]"))
        console.print()

        return {
            "target":        target,
            "ports":         ports,
            "scan_level":    int(scan_level),
            "use_ai":        use_ai,
            "skip_osint":    skip_osint,
            "skip_realtime": skip_realtime,
        }

    # ─── Progress ─────────────────────────────────────────────────────────
    def progress_callback(self, message: str, pct: int) -> None:
        with self._lock:
            if self._progress_obj and self._progress_task is not None:
                self._progress_obj.update(
                    self._progress_task,
                    completed=pct,
                    description=f"[cyan]{message[:65]}[/cyan]"
                )

    def start_progress(self) -> Progress:
        self._progress_obj = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=38, style="cyan", complete_style="bold green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        self._progress_task = self._progress_obj.add_task(
            "[cyan]Initializing...[/cyan]", total=100
        )
        return self._progress_obj

    # ─── Results display ──────────────────────────────────────────────────
    def show_results(self, session) -> None:
        console.print()
        console.print(Rule("[bold green]━━  Scan Results  ━━[/bold green]"))
        console.print()

        scan    = session.scan_result
        pa      = session.port_analysis or {}
        vulns   = session.vulnerabilities or []
        exploits = session.exploit_suggestions or []
        ai      = session.ai_analysis or {}
        triage  = session.ai_triage or {}
        nba     = session.next_best_action or {}
        chain   = session.attack_chain or {}
        lateral = session.lateral_movement or {}
        evasion = session.evasion_profile or {}
        honeypot = session.honeypot_analysis or {}
        opsec   = session.opsec_report or {}
        realtime = session.realtime_analysis or {}
        osint   = session.osint_data or {}
        proto   = session.protocol_inspection or {}

        # ── 1. Executive Summary ──────────────────────────────────────────
        score = pa.get("attack_surface_score", 0)
        score_color = "red" if score >= 8 else "yellow" if score >= 5 else "green"

        # چپ: اعداد
        left = Text()
        left.append("  Session ID  ", style="dim")
        left.append(f"{session.session_id}\n", style="bold cyan")
        left.append("  Target      ", style="dim")
        left.append(f"{session.target}\n", style="bold white")
        if scan:
            left.append("  Hosts Up    ", style="dim")
            host_style = "bold green" if scan.hosts_up > 0 else "bold red"
            left.append(f"{scan.hosts_up}\n", style=host_style)
            left.append("  Open Ports  ", style="dim")
            port_style = "bold yellow" if len(scan.open_ports) > 0 else "dim"
            left.append(f"{len(scan.open_ports)}\n", style=port_style)
            left.append("  RTT         ", style="dim")
            left.append(f"{scan.rtt_ms:.0f} ms\n", style="white")
        left.append("  Duration    ", style="dim")
        left.append(f"{session.duration:.1f}s\n", style="white")

        # راست: scores
        right = Text()
        right.append("  Attack Surface  ", style="dim")
        right.append(f"{score}/10\n", style=f"bold {score_color}")
        right.append("  CVEs Found      ", style="dim")
        crit = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
        vuln_style = "bold red" if crit > 0 else "white"
        right.append(f"{len(vulns)}  ", style=vuln_style)
        if crit:
            right.append(f"({crit} CRITICAL)\n", style="bold red")
        else:
            right.append("\n")
        right.append("  Exploit Hits    ", style="dim")
        right.append(f"{len(exploits)}\n", style="bold yellow" if exploits else "white")
        right.append("  Phases Done     ", style="dim")
        right.append(f"{len(session.phases_completed)}/14\n", style="cyan")

        # OPSEC score
        if opsec:
            opsec_score = opsec.get("opsec_score", 0)
            opsec_color = "green" if opsec_score >= 7 else "yellow" if opsec_score >= 4 else "red"
            right.append("  OPSEC Score     ", style="dim")
            right.append(f"{opsec_score}/10\n", style=f"bold {opsec_color}")

        console.print(Panel(
            Columns([left, right], equal=True, expand=True),
            title="[bold]📊 Executive Summary[/bold]",
            border_style=score_color,
            padding=(1, 2),
        ))
        console.print()

        # ── 2. Realtime Network Analysis ─────────────────────────────────
        if realtime:
            bh = realtime.get("behavior", {})
            hs = realtime.get("handshake", {})
            ad = realtime.get("adaptation", {})
            if bh or hs:
                rt_text = Text()
                if hs.get("os_guess") and hs["os_guess"] != "Unknown":
                    rt_text.append("  OS Fingerprint  ", style="dim")
                    rt_text.append(f"{hs['os_guess']}\n", style="bold cyan")
                if hs.get("rtt_ms"):
                    rt_text.append("  TCP RTT         ", style="dim")
                    rt_text.append(f"{hs['rtt_ms']} ms\n", style="white")
                if bh.get("middlebox_detected"):
                    rt_text.append("  Middlebox       ", style="dim")
                    rt_text.append("⚠️  DETECTED\n", style="bold yellow")
                if bh.get("throttling_detected"):
                    rt_text.append("  Throttling      ", style="dim")
                    rt_text.append("⚠️  DETECTED\n", style="bold yellow")
                if bh.get("recommended_timing"):
                    rt_text.append("  Best Timing     ", style="dim")
                    rt_text.append(f"{bh['recommended_timing']}\n", style="green")
                if ad.get("changes_made"):
                    rt_text.append("  Adaptations     ", style="dim")
                    rt_text.append(f"{len(ad['changes_made'])} applied\n", style="cyan")
                for note in bh.get("analysis_notes", [])[:3]:
                    rt_text.append(f"  ⚡ {note}\n", style="dim yellow")
                console.print(Panel(
                    rt_text,
                    title="[bold cyan]📡 Real-Time Network Analysis[/bold cyan]",
                    border_style="cyan",
                    padding=(0, 2),
                ))
                console.print()

        # ── 3. OSINT ─────────────────────────────────────────────────────
        if osint:
            geo = osint.get("geo", {})
            dns = osint.get("dns", {})
            rep = osint.get("reputation", {})
            if geo or dns:
                osint_text = Text()
                if geo.get("country"):
                    osint_text.append("  Country    ", style="dim")
                    osint_text.append(f"{geo.get('country', '?')} ({geo.get('country_code', '')})\n", style="white")
                if geo.get("org"):
                    osint_text.append("  Org / ISP  ", style="dim")
                    osint_text.append(f"{geo.get('org', '?')}\n", style="white")
                if geo.get("asn"):
                    osint_text.append("  ASN        ", style="dim")
                    osint_text.append(f"{geo.get('asn')}\n", style="white")
                if geo.get("is_tor"):
                    osint_text.append("  ⚠️  TOR Exit Node detected\n", style="bold red")
                if geo.get("is_proxy"):
                    osint_text.append("  ⚠️  Proxy / VPN detected\n", style="bold yellow")
                if dns.get("subdomains"):
                    osint_text.append("  Subdomains ", style="dim")
                    osint_text.append(f"{len(dns['subdomains'])} discovered\n", style="cyan")
                if rep and rep.get("abuse_confidence_score", 0) > 0:
                    abuse = rep["abuse_confidence_score"]
                    color = "red" if abuse > 50 else "yellow"
                    osint_text.append("  AbuseIPDB  ", style="dim")
                    osint_text.append(f"{abuse}% abuse confidence\n", style=color)
                risk = osint.get("risk_indicators", [])
                for ri in risk[:3]:
                    osint_text.append(f"  🚩 {ri}\n", style="yellow")
                console.print(Panel(
                    osint_text,
                    title="[bold blue]🌐 OSINT Intelligence[/bold blue]",
                    border_style="blue",
                    padding=(0, 2),
                ))
                console.print()

        # ── 4. Honeypot ───────────────────────────────────────────────────
        if honeypot and honeypot.get("is_honeypot"):
            console.print(Panel(
                f"[bold red]⚠️  HONEYPOT DETECTED[/bold red]\n"
                f"Verdict: {honeypot.get('verdict', '')}\n"
                f"Confidence: {honeypot.get('confidence', 0):.0%}",
                border_style="red",
                title="[bold red]🍯 Honeypot Warning[/bold red]",
            ))
            console.print()

        # ── 5. Evasion Profile ────────────────────────────────────────────
        if evasion:
            ev_text = Text()
            if evasion.get("firewall_detected"):
                ev_text.append("  Firewall     ", style="dim")
                ev_text.append("Detected\n", style="bold yellow")
            if evasion.get("ids_detected"):
                ev_text.append("  IDS/IPS      ", style="dim")
                ev_text.append("Detected\n", style="bold red")
            ev_text.append("  Evasion Score ", style="dim")
            es = evasion.get("evasion_score", 0)
            ev_text.append(f"{es}/10\n", style="bold green" if es >= 7 else "yellow")
            ev_text.append("  Risk Level    ", style="dim")
            ev_text.append(f"{evasion.get('detection_risk', 'N/A')}\n", style="white")
            techs = evasion.get("techniques_applied", [])
            if techs:
                ev_text.append("  Techniques   ", style="dim")
                ev_text.append(f"{', '.join(techs[:4])}\n", style="cyan")
            console.print(Panel(
                ev_text,
                title="[bold yellow]🛡️  Evasion Profile[/bold yellow]",
                border_style="yellow",
                padding=(0, 2),
            ))
            console.print()

        # ── 6. Open Ports ─────────────────────────────────────────────────
        findings = pa.get("findings", [])
        if findings:
            pt = Table(
                title=f"[bold]🔌 Open Ports & Risk Analysis ({len(findings)} found)[/bold]",
                box=box.ROUNDED,
                border_style="blue",
                show_lines=True,
            )
            pt.add_column("Port",     style="bold cyan",  justify="right",  width=7)
            pt.add_column("Proto",    justify="center",   width=6)
            pt.add_column("Service",  style="bold",       width=14)
            pt.add_column("Version",                      width=28)
            pt.add_column("Risk",     justify="center",   width=14)
            pt.add_column("Reason",   style="dim",        width=40)

            for f in findings:
                pv  = f"{f.get('product', '')} {f.get('version', '')}".strip()
                rl  = f.get("risk_level", "INFO")
                em  = SEVERITY_EMOJI.get(rl, "⚪")
                sty = SEVERITY_STYLE.get(rl, "dim")
                reasons = f.get("risk_reasons", [])
                first_reason = reasons[0][:38] + "…" if reasons and len(reasons[0]) > 38 else (reasons[0] if reasons else "")
                pt.add_row(
                    str(f["port"]),
                    f["proto"].upper(),
                    f["service"],
                    pv or "[dim]—[/dim]",
                    f"{em} [{sty}]{rl}[/{sty}]",
                    first_reason,
                )
            console.print(pt)
            console.print()

            # خلاصه دیتابیس‌ها و remote access
            dbs = pa.get("exposed_databases", [])
            ra  = pa.get("exposed_remote_access", [])
            if dbs or ra:
                warn_text = Text()
                if dbs:
                    warn_text.append("  🗄️  Exposed Databases: ", style="bold red")
                    warn_text.append(
                        ", ".join(f"{d['service']}:{d['port']}" for d in dbs) + "\n",
                        style="red"
                    )
                if ra:
                    warn_text.append("  🖥️  Remote Access:      ", style="bold yellow")
                    warn_text.append(
                        ", ".join(f"{r['service']}:{r['port']}" for r in ra) + "\n",
                        style="yellow"
                    )
                console.print(Panel(
                    warn_text,
                    title="[bold red]⚠️  High-Risk Services[/bold red]",
                    border_style="red",
                    padding=(0, 2),
                ))
                console.print()

        # ── 7. Protocol Inspection ────────────────────────────────────────
        if proto:
            tls = proto.get("tls", {})
            ssh = proto.get("ssh", {})
            if tls or ssh:
                proto_text = Text()
                if tls:
                    version = tls.get("version", "")
                    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
                        proto_text.append(f"  TLS Version  {version}  ⚠️  WEAK\n", style="bold red")
                    elif version:
                        proto_text.append("  TLS Version  ", style="dim")
                        proto_text.append(f"{version}\n", style="green")
                    if tls.get("heartbleed"):
                        proto_text.append("  Heartbleed   ", style="dim")
                        proto_text.append("VULNERABLE ⚠️\n", style="bold red")
                    if tls.get("weak_ciphers"):
                        proto_text.append("  Weak Ciphers ", style="dim")
                        proto_text.append(f"{len(tls['weak_ciphers'])} found\n", style="yellow")
                if ssh:
                    proto_text.append("  SSH Version  ", style="dim")
                    proto_text.append(f"{ssh.get('version', 'unknown')}\n", style="white")
                    if ssh.get("auth_methods"):
                        proto_text.append("  SSH Auth     ", style="dim")
                        proto_text.append(f"{', '.join(ssh['auth_methods'])}\n", style="cyan")
                    if "password" in str(ssh.get("auth_methods", [])).lower():
                        proto_text.append("  ⚠️  Password auth enabled — brute force risk\n", style="yellow")
                console.print(Panel(
                    proto_text,
                    title="[bold]🔐 Protocol Inspection[/bold]",
                    border_style="cyan",
                    padding=(0, 2),
                ))
                console.print()

        # ── 8. Vulnerabilities ────────────────────────────────────────────
        if vulns:
            vt = Table(
                title=f"[bold]🔓 Vulnerabilities — {len(vulns)} found[/bold]",
                box=box.ROUNDED,
                border_style="red",
                show_lines=False,
            )
            vt.add_column("CVE ID",   style="cyan",       no_wrap=True, width=18)
            vt.add_column("Service",                       width=10)
            vt.add_column("Port",     justify="right",    width=6)
            vt.add_column("CVSS",     justify="center",   width=7)
            vt.add_column("Severity", justify="center",   width=12)
            vt.add_column("Published",                     width=12)

            for v in vulns[:25]:
                sev   = v.get("severity", "")
                score_v = v.get("cvss_score", 0)
                sty   = SEVERITY_STYLE.get(sev, "")
                em    = SEVERITY_EMOJI.get(sev, "⚪")
                vt.add_row(
                    v.get("cve_id", ""),
                    v.get("service", ""),
                    str(v.get("port", "")),
                    f"[{sty}]{score_v:.1f}[/{sty}]" if sty else f"{score_v:.1f}",
                    f"{em} [{sty}]{sev}[/{sty}]" if sty else sev,
                    v.get("published", ""),
                )
            if len(vulns) > 25:
                console.print(f"[dim]  … and {len(vulns) - 25} more (see JSON report)[/dim]")
            console.print(vt)
            console.print()

        # ── 9. Exploit Suggestions ────────────────────────────────────────
        if exploits:
            et = Table(
                title=f"[bold]💣 Exploit Candidates — {len(exploits)} found[/bold]",
                box=box.ROUNDED,
                border_style="yellow",
            )
            et.add_column("CVE",      style="cyan", no_wrap=True, width=18)
            et.add_column("Service",                width=10)
            et.add_column("Port",     justify="right", width=6)
            et.add_column("CVSS",     justify="center", width=7)
            et.add_column("✓",        justify="center", width=4)
            et.add_column("Module / EDB",           width=52)
            for e in exploits:
                module = e.get("metasploit_module") or f"EDB-{e.get('exploit_db_id', '?')}"
                vfied  = "[green]✓[/green]" if e.get("verified") else "[yellow]~[/yellow]"
                et.add_row(
                    e.get("cve_id", ""),
                    e.get("service", ""),
                    str(e.get("port", "")),
                    f"{e.get('cvss_score', 0):.1f}",
                    vfied,
                    module[:50],
                )
            console.print(et)
            console.print()

        # ── 10. MITRE ATT&CK ─────────────────────────────────────────────
        if chain:
            techniques = chain.get("techniques", []) or chain.get("kill_chain", [])
            if techniques:
                chain_text = Text()
                for i, t in enumerate(techniques[:8]):
                    name = t.get("name") or t.get("technique") or str(t)
                    tid  = t.get("id") or t.get("technique_id") or ""
                    chain_text.append(f"  [{tid}] " if tid else "  ", style="dim")
                    chain_text.append(f"{name}\n", style="cyan")
                console.print(Panel(
                    chain_text,
                    title="[bold red]⛓️  MITRE ATT&CK Kill Chain[/bold red]",
                    border_style="red",
                    padding=(0, 2),
                ))
                console.print()

        # ── 11. Lateral Movement ─────────────────────────────────────────
        if lateral:
            pivots = lateral.get("pivot_points", []) or lateral.get("paths", [])
            if pivots:
                lat_text = Text()
                for p in pivots[:6]:
                    service = p.get("service") or p.get("path") or str(p)
                    port    = p.get("port", "")
                    reason  = p.get("reason") or p.get("note") or ""
                    lat_text.append(f"  → {service}", style="bold yellow")
                    if port:
                        lat_text.append(f":{port}", style="yellow")
                    if reason:
                        lat_text.append(f"  {reason}", style="dim")
                    lat_text.append("\n")
                console.print(Panel(
                    lat_text,
                    title="[bold yellow]🔄 Lateral Movement Paths[/bold yellow]",
                    border_style="yellow",
                    padding=(0, 2),
                ))
                console.print()

        # ── 12. AI Triage ─────────────────────────────────────────────────
        if triage:
            targets = triage.get("priority_targets", [])
            if targets:
                tt = Table(
                    title="[bold magenta]🎯 AI Attack Path Triage[/bold magenta]",
                    box=box.ROUNDED,
                    border_style="magenta",
                )
                tt.add_column("Port",    justify="right", width=6)
                tt.add_column("Service",                  width=12)
                tt.add_column("Attack Vector",            width=32)
                tt.add_column("Difficulty", justify="center", width=10)
                tt.add_column("Impact",    justify="center", width=10)
                diff_style = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}
                imp_style  = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
                for pt_item in targets[:8]:
                    diff = pt_item.get("difficulty", "")
                    imp  = pt_item.get("impact", "")
                    tt.add_row(
                        str(pt_item.get("port", "")),
                        pt_item.get("service", ""),
                        pt_item.get("attack_vector", ""),
                        f"[{diff_style.get(diff, 'white')}]{diff}[/{diff_style.get(diff, 'white')}]",
                        f"[{imp_style.get(imp, 'white')}]{imp}[/{imp_style.get(imp, 'white')}]",
                    )
                console.print(tt)

                quick_wins = triage.get("quick_wins", [])
                if quick_wins:
                    console.print()
                    console.print("  [bold]⚡ Quick Wins:[/bold]")
                    for qw in quick_wins[:4]:
                        console.print(f"  [green]•[/green] {qw}")

                assessment = triage.get("overall_assessment", "")
                if assessment:
                    console.print()
                    console.print(Panel(
                        f"[dim]{assessment}[/dim]",
                        title="[magenta]AI Assessment[/magenta]",
                        border_style="magenta",
                        padding=(0, 2),
                    ))
                console.print()

        # ── 13. AI Analysis ──────────────────────────────────────────────
        if ai:
            ai_text = Text()
            if ai.get("risk_level"):
                rl  = ai["risk_level"]
                em  = SEVERITY_EMOJI.get(rl, "")
                sty = SEVERITY_STYLE.get(rl, "white")
                ai_text.append("  Risk Level  ", style="dim")
                ai_text.append(f"{em} ", style="")
                ai_text.append(f"{rl}\n", style=f"bold {sty}")
            if ai.get("attack_surface_summary"):
                ai_text.append(f"\n  {ai['attack_surface_summary']}\n", style="white")
            if ai.get("kill_chain_stage"):
                ai_text.append("\n  Kill Chain Stage  ", style="dim")
                ai_text.append(f"{ai['kill_chain_stage']}\n", style="cyan")
            findings_ai = ai.get("findings", [])
            if findings_ai:
                ai_text.append("\n  Top Findings:\n", style="bold")
                for f_ai in findings_ai[:4]:
                    port = f_ai.get("port", "")
                    svc  = f_ai.get("service", "")
                    risk = f_ai.get("risk", "")
                    conf = f_ai.get("confidence", "")
                    mitre = f_ai.get("mitre_technique", "")
                    ai_text.append(
                        f"    [{risk}] Port {port}/{svc}",
                        style=SEVERITY_STYLE.get(risk, "white")
                    )
                    if mitre:
                        ai_text.append(f" [{mitre}]", style="dim")
                    ai_text.append("\n")
            console.print(Panel(
                ai_text,
                title="[bold magenta]🤖 AI Analysis (local Ollama)[/bold magenta]",
                border_style="magenta",
                padding=(0, 2),
            ))
            console.print()

        # ── 14. Next Best Action ─────────────────────────────────────────
        if nba and nba.get("recommended_command"):
            console.print(Panel(
                f"[bold green]$ {nba['recommended_command']}[/bold green]\n\n"
                f"[dim]{nba.get('rationale', nba.get('reasoning', ''))}[/dim]",
                title="[bold green]🎯 Recommended Next Command[/bold green]",
                border_style="green",
                padding=(1, 2),
            ))
            console.print()

        # ── v4: Adaptive Intelligence Pre-scan ───────────────────────────
        if intel and intel.get("prior_scans", 0) > 0:
            pred_ports  = intel.get("port_predictions", [])
            change_alts = intel.get("change_alerts", [])
            pred_cves   = intel.get("cve_predictions", [])
            evasion_rec = intel.get("evasion_recommendation")
            prior       = intel.get("prior_scans", 0)
            conf        = intel.get("confidence_overall", 0)
            trend       = intel.get("trend_summary", "")

            intel_text = Text()
            intel_text.append("  Prior Scans      ", style="dim")
            intel_text.append(f"{prior}\n", style="bold cyan")
            intel_text.append("  Confidence       ", style="dim")
            intel_text.append(f"{conf:.0%}\n", style="cyan")
            if trend:
                intel_text.append(f"\n{trend}\n", style="white")

            if change_alts:
                intel_text.append(f"\n[bold red]⚠  {len(change_alts)} Changes Detected Since Last Scan:[/bold red]\n")
                for ch in change_alts[:5]:
                    sev_color = "red" if ch.get("severity") == "HIGH" else "yellow"
                    ctype     = ch.get("change_type", "").replace("_", " ").title()
                    port      = ch.get("port", "")
                    old_v     = ch.get("old_value", "")
                    new_v     = ch.get("new_value", "")
                    intel_text.append(
                        f"  [{sev_color}]• {ctype}[/{sev_color}]"
                        f"[dim] port {port}: {old_v} → {new_v}[/dim]\n"
                    )

            if pred_ports:
                intel_text.append(f"\n[bold]Predicted Ports ({len(pred_ports)}):[/bold]\n")
                for pp in pred_ports[:6]:
                    conf_p = pp.get("confidence", 0)
                    bar    = "█" * int(conf_p * 5) + "░" * (5 - int(conf_p * 5))
                    color  = "green" if conf_p > 0.7 else "yellow" if conf_p > 0.4 else "dim"
                    intel_text.append(
                        f"  [{color}]{bar}[/{color}] "
                        f"[cyan]{pp.get('port')}[/cyan]"
                        f"[dim]/{pp.get('service','?')} "
                        f"({conf_p:.0%} — {pp.get('basis','')})[/dim]\n"
                    )

            if evasion_rec:
                intel_text.append(f"\n[bold]Recommended Evasion:[/bold]\n")
                intel_text.append(
                    f"  [green]{evasion_rec.get('nmap_args','')[:70]}[/green]\n",
                )
                intel_text.append(
                    f"  [dim]{evasion_rec.get('basis','')}[/dim]\n"
                )

            console.print(Panel(
                intel_text,
                title="[bold magenta]🧠 Adaptive Intelligence (v4)[/bold magenta]",
                border_style="magenta",
                padding=(0, 2),
            ))
            console.print()

        # ── v4: Auto-Recon Findings ───────────────────────────────────────
        if ar and ar.get("total_checks", 0) > 0:
            all_findings = ar.get("findings", [])
            crit_findings = ar.get("critical_findings", [])
            high_findings = ar.get("high_findings", [])
            total_checks  = ar.get("total_checks", 0)

            if all_findings:
                ar_table = Table(
                    title=f"[bold red]🔍 Auto-Recon Results — {total_checks} checks, "
                          f"{len(crit_findings)} CRITICAL, {len(high_findings)} HIGH[/bold red]",
                    box=box.ROUNDED,
                    border_style="red",
                    show_lines=False,
                )
                ar_table.add_column("Service", width=12)
                ar_table.add_column("Port", justify="right", width=6)
                ar_table.add_column("Check", width=26)
                ar_table.add_column("Severity", justify="center", width=12)
                ar_table.add_column("Result", width=40)

                for f_item in all_findings[:15]:
                    sev   = f_item.get("severity", "INFO")
                    em    = SEVERITY_EMOJI.get(sev, "⚪")
                    sty   = SEVERITY_STYLE.get(sev, "dim")
                    res   = f_item.get("result", "")[:38]
                    ar_table.add_row(
                        f_item.get("service", ""),
                        str(f_item.get("port", "")),
                        f_item.get("check_name", ""),
                        f"{em} [{sty}]{sev}[/{sty}]",
                        res,
                    )
                console.print(ar_table)

                # نمایش دستورات برای CRITICAL‌ها
                if crit_findings:
                    console.print()
                    console.print("  [bold red]⚡ Critical — Immediate Action:[/bold red]")
                    for cf in crit_findings[:4]:
                        cmd = cf.get("command_run", "")
                        if cmd:
                            console.print(f"  [bold green]$[/bold green] [green]{cmd}[/green]")
                console.print()

        # ── v4: Stealth Score ─────────────────────────────────────────────
        if stealth:
            s_score = stealth.get("score", 0)
            s_risk  = stealth.get("detection_risk", "UNKNOWN")
            s_det   = stealth.get("estimated_detected", False)
            s_color = {
                "LOW": "green", "MEDIUM": "yellow",
                "HIGH": "red", "CRITICAL": "bold red"
            }.get(s_risk, "white")

            bar_n   = int(s_score / 10)
            bar     = "█" * bar_n + "░" * (10 - bar_n)

            stealth_text = Text()
            stealth_text.append("  Score          ", style="dim")
            stealth_text.append(f"{s_score:.0f}/100  ", style=f"bold {s_color}")
            stealth_text.append(f"{bar}\n", style=s_color)
            stealth_text.append("  Detection Risk  ", style="dim")
            stealth_text.append(f"{s_risk}\n", style=f"bold {s_color}")
            stealth_text.append("  Likely Detected ", style="dim")
            stealth_text.append(
                f"{'⚠️  YES' if s_det else '✓  NO'}\n",
                style="bold red" if s_det else "green"
            )
            stealth_text.append("  Confidence      ", style="dim")
            stealth_text.append(f"{stealth.get('confidence', 0):.0%}\n", style="cyan")

            deductions = stealth.get("deductions", [])
            if deductions:
                stealth_text.append("\n  [bold]Risk Factors:[/bold]\n")
                for d in deductions[:4]:
                    pen   = d.get("penalty", 0)
                    factor = d.get("factor", "")
                    stealth_text.append(f"  [-{pen:2d}] ", style="red")
                    stealth_text.append(f"{factor}\n", style="white")

            recs = stealth.get("recommendations", [])
            if recs:
                stealth_text.append("\n  [bold cyan]Improvements:[/bold cyan]\n")
                for r in recs[:3]:
                    pri = r.get("priority", "")
                    act = r.get("action", "")
                    stealth_text.append(f"  [{pri}] ", style="yellow")
                    stealth_text.append(f"{act}\n", style="white")

            better_cmd = stealth.get("better_command", "")
            if better_cmd:
                stealth_text.append(f"\n[bold green]Better next command:[/bold green]\n")
                stealth_text.append(f"  [green]{better_cmd}[/green]\n")

            console.print(Panel(
                stealth_text,
                title=f"[bold]👁  Stealth Analysis (v4)[/bold]",
                border_style=s_color,
                padding=(0, 2),
            ))
            console.print()

        # ── OPSEC Score ───────────────────────────────────────────────────
        if opsec:
            opsec_score = opsec.get("opsec_score", 0)
            opsec_color = "green" if opsec_score >= 7 else "yellow" if opsec_score >= 4 else "red"
            bar_filled  = "█" * int(opsec_score)
            bar_empty   = "░" * (10 - int(opsec_score))
            risk_level  = opsec.get("detection_risk", "UNKNOWN")
            opsec_text  = Text()
            opsec_text.append(f"  Score        ", style="dim")
            opsec_text.append(f"{opsec_score}/10  ", style=f"bold {opsec_color}")
            opsec_text.append(f"{bar_filled}", style=opsec_color)
            opsec_text.append(f"{bar_empty}\n", style="dim")
            opsec_text.append(f"  Detection    ", style="dim")
            opsec_text.append(f"{risk_level}\n", style=f"{opsec_color}")
            recs = opsec.get("recommendations", [])
            for r in recs[:3]:
                opsec_text.append(f"  • {r}\n", style="dim")
            console.print(Panel(
                opsec_text,
                title="[bold]🕵️  OPSEC Score[/bold]",
                border_style=opsec_color,
                padding=(0, 2),
            ))
            console.print()

        # ── Reports ───────────────────────────────────────────────────────
        if session.report_paths:
            rpt_text = Text()
            for fmt, path in session.report_paths.items():
                if path:
                    rpt_text.append(f"  {fmt.upper():8}", style="bold cyan")
                    rpt_text.append(f"{path}\n", style="white")
            console.print(Panel(
                rpt_text,
                title="[bold]📁 Generated Reports[/bold]",
                border_style="dim",
                padding=(0, 2),
            ))

        # ── Errors ────────────────────────────────────────────────────────
        real_errors = [
            e for e in session.errors
            if "warning" not in e.lower() and e != "Scan failed: None"
        ]
        if real_errors:
            console.print()
            console.print("[bold red]⚠️  Errors:[/bold red]")
            for err in real_errors:
                console.print(f"  [red]• {err}[/red]")

        # ── Phases ────────────────────────────────────────────────────────
        if session.phases_completed:
            console.print()
            phases_str = "  [dim]Completed:[/dim] " + " → ".join(
                f"[cyan]{p.replace('_', ' ')}[/cyan]"
                for p in session.phases_completed
            )
            console.print(phases_str)

        console.print()
        console.print(Rule("[dim]Aegis-Scanner v3 — For authorized testing only[/dim]"))

    # ─── Post-scan menu ──────────────────────────────────────────────────
    def post_scan_menu(self) -> str:
        """منوی بعد از اتمام اسکن — برگشت به منو یا خروج"""
        console.print()
        console.print(Rule("[dim]What would you like to do next?[/dim]"))
        console.print()
        console.print("  [bold cyan][N][/bold cyan]  New scan")
        console.print("  [bold cyan][Q][/bold cyan]  Quit")
        console.print()

        while True:
            try:
                choice = Prompt.ask(
                    "  [bold]Choice[/bold]",
                    choices=["n", "N", "q", "Q"],
                    default="N",
                ).strip().lower()
            except (KeyboardInterrupt, EOFError):
                return "quit"

            if choice == "n":
                console.print()
                return "new"
            elif choice == "q":
                console.print("\n[dim]Goodbye.[/dim]\n")
                return "quit"

    # ─── Cloudflare / filtered host notice ───────────────────────────────
    def show_filtered_notice(self, session) -> None:
        """نمایش راهنما وقتی هاست پشت Cloudflare یا فایروال هست"""
        osint = getattr(session, "osint_data", {}) or {}
        geo   = osint.get("geo", {})
        org   = geo.get("org", "").lower()

        if "cloudflare" in org or "fastly" in org or "akamai" in org:
            cdn_name = "Cloudflare" if "cloudflare" in org else                        "Fastly" if "fastly" in org else "Akamai"
            console.print()
            console.print(Panel(
                f"[bold yellow]Target is behind {cdn_name} CDN[/bold yellow]\n\n"
                f"[dim]این هاست پشت {cdn_name} پنهان شده.\n"
                f"پورت‌های واقعی سرور مستقیماً قابل اسکن نیستند.\n\n"
                f"[bold]راه‌حل‌ها:[/bold]\n"
                f"  • پیدا کردن IP اصلی سرور از طریق DNS history\n"
                f"  • اسکن زیردامنه‌هایی که ممکن است CDN نداشته باشند\n"
                f"  • استفاده از Shodan برای یافتن IP قدیمی‌تر\n"
                f"  • جستجو در certificate transparency logs\n\n"
                f"[dim]دستور: python main.py --target [IP-REAL] --level 2[/dim][/dim]",
                title=f"[bold yellow]⚠️  CDN Detected: {cdn_name}[/bold yellow]",
                border_style="yellow",
                padding=(1, 2),
            ))

    # ─── Ollama help ─────────────────────────────────────────────────────
    @staticmethod
    def show_ollama_help(llm_settings) -> None:
        base_url = llm_settings.base_url
        model    = llm_settings.model
        server_up = False
        try:
            import requests
            r = requests.get(base_url + "/api/tags", timeout=3)
            server_up = r.status_code == 200
        except Exception:
            server_up = False

        if server_up:
            lines = [
                "[bold yellow]Ollama is running but model not found[/bold yellow]",
                "",
                "[white]مدل را دانلود کنید:[/white]",
                "",
                "  [bold green]ollama pull " + model + "[/bold green]",
                "",
                "[dim]مدل‌های سبک‌تر:[/dim]",
                "  [dim]ollama pull llama3:8b   →  4.7 GB[/dim]",
                "  [dim]ollama pull mistral     →  4.1 GB[/dim]",
                "  [dim]ollama pull phi3        →  2.3 GB[/dim]",
                "",
                "[dim]بعد از دانلود، aegis_config.json را آپدیت کنید:[/dim]",
                '  [dim]"model": "mistral"[/dim]',
            ]
            border = "yellow"
        else:
            lines = [
                "[bold red]Ollama not reachable at " + base_url + "[/bold red]",
                "",
                "[bold cyan]مراحل نصب:[/bold cyan]",
                "",
                "  [bold]1. نصب (Linux/Mac):[/bold]",
                "     [green]curl -fsSL https://ollama.com/install.sh | sh[/green]",
                "",
                "  [bold]2. نصب (Windows):[/bold]",
                "     [green]https://ollama.com/download/windows[/green]",
                "",
                "  [bold]3. دانلود مدل:[/bold]",
                "     [green]ollama pull llama3[/green]   [dim](4.7 GB)[/dim]",
                "     [dim]ollama pull mistral      (4.1 GB - سبک‌تر)[/dim]",
                "     [dim]ollama pull phi3         (2.3 GB - خیلی سبک)[/dim]",
                "",
                "  [bold]4. شروع سرور:[/bold]",
                "     [green]ollama serve[/green]",
                "",
                '  [bold]5. مدل را در aegis_config.json تنظیم کنید:[/bold]',
                '     [dim]"model": "llama3"[/dim]',
                "",
                "[dim]بدون AI، همه 14 ماژول دیگر کار می‌کنند.[/dim]",
            ]
            border = "red"

        console.print(Panel(
            "\n".join(lines),
            title="[bold]🤖 AI Setup[/bold]",
            border_style=border,
            padding=(1, 2),
        ))
        console.print()

        # ─── Helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def show_error(message: str) -> None:
        console.print(f"\n[bold red]❌ Error:[/bold red] {message}\n")

    @staticmethod
    def show_warning(message: str) -> None:
        console.print(f"[bold yellow]⚠️  Warning:[/bold yellow] {message}")
