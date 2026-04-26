#!/usr/bin/env python3
# aegis-scanner/main.py
"""
نقطه ورود اصلی Aegis-Scanner.
استفاده:
    python main.py                   # حالت تعاملی (TUI)
    python main.py --target 10.0.0.1 # حالت CLI مستقیم
    python main.py --health          # بررسی وضعیت سیستم
    python main.py --history         # نمایش تاریخچه اسکن‌ها
"""

import sys
import argparse
import logging

# اضافه کردن مسیر پروژه به sys.path
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import AegisSettings
from core.aegis_engine import AegisEngine
from ui.tui import AegisTUI
from intelligence.knowledge_base import KnowledgeBase


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aegis-scanner",
        description="AI-Powered Network Scanner with Nmap + Llama 3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                              # Interactive TUI
  python main.py --target 192.168.1.1         # Quick standard scan
  python main.py --target 10.0.0.0/24 -l 3   # Aggressive scan on subnet
  python main.py --target host.com -p 1-65535 --no-ai   # Full port scan, no AI
  python main.py --health                     # System health check
  python main.py --history                    # Show scan history

WARNING: Only use on systems you own or have explicit permission to scan.
        """
    )

    parser.add_argument("--target",   "-t", help="Target IP / hostname / CIDR")
    parser.add_argument("--ports",    "-p", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("--level",    "-l", type=int, default=2, choices=[1,2,3,4,5],
                        help="Scan level 1-5 (default: 2=Standard)")
    parser.add_argument("--no-ai",    action="store_true", help="Disable AI analysis")
    parser.add_argument("--health",   action="store_true", help="Check system health and exit")
    parser.add_argument("--history",  action="store_true", help="Show scan history and exit")
    parser.add_argument("--config",   default="aegis_config.json", help="Config file path")
    parser.add_argument("--debug",    action="store_true", help="Enable debug logging")
    parser.add_argument("--session-id",    help="Custom session ID")
    parser.add_argument("--skip-osint",    action="store_true",
                        help="Skip OSINT gathering (faster)")
    parser.add_argument("--skip-realtime", action="store_true",
                        help="Skip real-time TCP analysis (faster)")
    parser.add_argument("--no-honeypot",   action="store_true",
                        help="Skip honeypot detection check")

    return parser.parse_args()


def run_interactive(engine: AegisEngine, tui: AegisTUI) -> None:
    """حالت تعاملی با TUI کامل — loop تا کاربر خارج بشه"""
    tui.show_banner()

    # نمایش وضعیت سیستم (فقط یک بار)
    health = engine.health_check()
    tui.show_health(health)

    if not health.get("nmap", False):
        tui.show_error("Nmap not found. Install: sudo apt install nmap")
        sys.exit(1)

    if not health.get("llm", False):
        tui.show_ollama_help(engine.settings.llm)

    # ── main loop ────────────────────────────────────────────────────────
    while True:
        try:
            # جمع‌آوری پارامترها
            params = tui.collect_scan_params()

            # غیرفعال کردن AI اگر کاربر درخواست کرده یا در دسترس نیست
            if not params.get("use_ai") or not health.get("llm", False):
                engine.settings.llm.enabled = False
            else:
                engine.settings.llm.enabled = True

            # اجرای اسکن با progress
            engine.set_progress_callback(tui.progress_callback)
            with tui.start_progress() as progress:
                session = engine.run_full_scan(
                    target=params["target"],
                    ports=params["ports"],
                    scan_level=params["scan_level"],
                    skip_osint=params.get("skip_osint", False),
                    skip_realtime=params.get("skip_realtime", False),
                )

            # نمایش نتایج
            tui.show_results(session)

            # منوی بعد از اسکن
            action = tui.post_scan_menu()
            if action == "quit":
                break
            elif action == "new":
                # reset progress callback
                engine._progress_cb = None
                continue
            # else: "repeat" → loop مجدد با همان تنظیمات

        except KeyboardInterrupt:
            break


def run_cli(engine: AegisEngine, tui: AegisTUI, args: argparse.Namespace) -> None:
    """حالت CLI مستقیم"""
    if args.no_ai:
        engine.settings.llm.enabled = False

    engine.set_progress_callback(tui.progress_callback)

    with tui.start_progress():
        session = engine.run_full_scan(
            target=args.target,
            ports=args.ports,
            scan_level=args.level,
            session_id=args.session_id,
            skip_osint=getattr(args, "skip_osint", False),
            skip_realtime=getattr(args, "skip_realtime", False),
            skip_honeypot_check=getattr(args, "no_honeypot", False),
        )

    tui.show_results(session)


def show_history(tui: AegisTUI) -> None:
    """نمایش تاریخچه اسکن‌ها"""
    from rich.table import Table
    from rich.console import Console
    from rich import box

    kb = KnowledgeBase()
    history = kb.get_recent_scans(20)
    stats   = kb.get_stats()

    c = Console()
    c.print(f"\n[bold]Knowledge Base Stats:[/bold] "
            f"{stats['total_scans']} scans | "
            f"{stats['known_patterns']} patterns | "
            f"{stats['service_profiles']} service profiles\n")

    if not history:
        c.print("[dim]No scan history found.[/dim]")
        return

    t = Table(title="Recent Scans", box=box.ROUNDED)
    t.add_column("Session",  style="cyan", no_wrap=True)
    t.add_column("Timestamp")
    t.add_column("Target")
    t.add_column("Level", justify="center")
    t.add_column("Hosts", justify="center")
    t.add_column("Ports", justify="center")
    t.add_column("Vulns", justify="center")
    t.add_column("Duration")

    for h in history:
        t.add_row(
            h.get("session_id", ""),
            h.get("timestamp", "")[:16],
            h.get("target", ""),
            str(h.get("scan_level", "")),
            str(h.get("hosts_up", "")),
            str(h.get("open_ports", "")),
            str(h.get("vulns_found", "")),
            f"{h.get('duration', 0):.0f}s",
        )
    c.print(t)


def main() -> None:
    args = parse_args()

    # تنظیمات
    settings = AegisSettings.from_file(args.config)
    if args.debug:
        settings.debug    = True
        settings.log_level = "DEBUG"

    tui    = AegisTUI()
    engine = AegisEngine(settings)

    # ─── Health check ─────────────────────────────────────────────────────
    if args.health:
        tui.show_banner()
        health = engine.health_check()
        tui.show_health(health)
        sys.exit(0 if all(health.values()) else 1)

    # ─── History ──────────────────────────────────────────────────────────
    if args.history:
        show_history(tui)
        sys.exit(0)

    # ─── Scan ─────────────────────────────────────────────────────────────
    try:
        if args.target:
            run_cli(engine, tui, args)
        else:
            run_interactive(engine, tui)
    except KeyboardInterrupt:
        print("\n\n[Interrupted by user]")
        sys.exit(0)
    except Exception as e:
        tui.show_error(str(e))
        if args.debug:
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()
