# aegis-scanner/core/aegis_engine.py  (v3 — Red Team Edition)
"""
Orchestrator اصلی Aegis-Scanner.
تمام 14 ماژول متصل و عملیاتی — از جمله realtime_analyzer و osint_engine
که قبلاً disconnect بودند.
"""
import logging
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, Callable

from config.settings import AegisSettings
from core.nmap_controller import NmapController, ScanResult
from core.llm_connector import LLMConnector
from modules.port_analyzer import PortAnalyzer
from modules.vuln_engine import VulnEngine
from modules.exploit_suggestor import ExploitSuggestor
from modules.packet_optimizer import PacketOptimizer
from modules.evasion_engine import EvasionEngine
from modules.honeypot_detector import HoneypotDetector
from modules.protocol_inspector import ProtocolInspector
from modules.attack_chain_mapper import AttackChainMapper
from modules.opset_scorer import OPSECScorer
from modules.lateral_movement import LateralMovementAnalyzer
from modules.realtime_analyzer import RealtimeAnalyzer
from modules.osint_engine import OSINTEngine
from modules.auto_recon import AutoReconEngine
from modules.stealth_advisor import StealthAdvisor
from intelligence.knowledge_base import KnowledgeBase
from intelligence.adaptive_engine import AdaptiveIntelligenceEngine
from intelligence.cve_mapper import CVEMapper
from reporting.json_reporter import JSONReporter
from reporting.markdown_reporter import MarkdownReporter

logger = logging.getLogger(__name__)


@dataclass
class ScanSession:
    session_id: str
    target: str
    ports: str
    scan_level: int
    settings: AegisSettings
    scan_result:         Optional[ScanResult] = None
    port_analysis:       Optional[dict]       = None
    vulnerabilities:     Optional[list]       = None
    exploit_suggestions: Optional[list]       = None
    ai_analysis:         Optional[dict]       = None
    ai_triage:           Optional[dict]       = None
    optimized_params:    Optional[dict]       = None
    next_best_action:    Optional[dict]       = None
    evasion_profile:     Optional[dict]       = None
    honeypot_analysis:   Optional[dict]       = None
    protocol_inspection: Optional[dict]       = None
    attack_chain:        Optional[dict]       = None
    opsec_report:        Optional[dict]       = None
    lateral_movement:    Optional[dict]       = None
    realtime_analysis:   Optional[dict]       = None
    osint_data:          Optional[dict]       = None
    auto_recon:          Optional[dict]       = None   # v4
    stealth_score:       Optional[dict]       = None   # v4
    intelligence:        Optional[dict]       = None   # v4
    start_time:  float = field(default_factory=time.time)
    end_time:    Optional[float] = None
    errors:      list  = field(default_factory=list)
    report_paths: dict = field(default_factory=dict)
    phases_completed: list = field(default_factory=list)

    @property
    def duration(self) -> float:
        return (self.end_time or time.time()) - self.start_time


class AegisEngine:
    """
    Orchestrator — Red Team Edition v3
    14 ماژول فعال:
    1. RTT + Packet Optimization
    2. Realtime Network Analysis  [جدید - وصل شد]
    3. OSINT Intelligence         [جدید - وصل شد]
    4. Honeypot Detection
    5. Evasion Profile Builder
    6. Nmap Scan (با NSE کامل)
    7. Port Analysis + Risk Scoring
    8. Protocol Deep Inspection (TLS/SSH/HTTP)
    9. CVE Mapping (NVD API 2.0)
    10. Exploit Suggestions (searchsploit/MSF)
    11. MITRE ATT&CK Kill Chain
    12. Lateral Movement Analysis
    13. AI Analysis + Triage (Ollama local)
    14. OPSEC Scoring
    """

    def __init__(self, settings: Optional[AegisSettings] = None):
        self.settings = settings or AegisSettings()
        self.settings.configure_logging()
        self.nmap             = NmapController(self.settings.nmap)
        self.llm              = LLMConnector(self.settings.llm)
        self.port_analyzer    = PortAnalyzer()
        self.vuln_engine      = VulnEngine()
        self.exploit_suggest  = ExploitSuggestor()
        self.pkt_optimizer    = PacketOptimizer()
        self.evasion_engine   = EvasionEngine()
        self.honeypot_det     = HoneypotDetector()
        self.proto_inspector  = ProtocolInspector()
        self.attack_mapper    = AttackChainMapper()
        self.opsec_scorer     = OPSECScorer()
        self.lateral_analyzer = LateralMovementAnalyzer()
        self.realtime         = RealtimeAnalyzer()
        self.osint            = OSINTEngine()
        self.cve_mapper       = CVEMapper()
        self.knowledge_base   = KnowledgeBase()
        self.json_reporter    = JSONReporter(self.settings.report)
        self.md_reporter      = MarkdownReporter(self.settings.report)
        # ── v4 modules ────────────────────────────────────────────────────
        self.adaptive_engine  = AdaptiveIntelligenceEngine()
        self.auto_recon       = AutoReconEngine()
        self.stealth_advisor  = StealthAdvisor()
        self._progress_cb: Optional[Callable[[str, int], None]] = None
        logger.info("[AegisEngine v4] All 17 modules initialized")

    def set_progress_callback(self, cb: Callable[[str, int], None]) -> None:
        self._progress_cb = cb

    def _progress(self, msg: str, pct: int) -> None:
        if self._progress_cb:
            self._progress_cb(msg, pct)
        logger.info(f"[{pct:3d}%] {msg}")

    def run_full_scan(
        self,
        target: str,
        ports: str = "1-1024",
        scan_level: int = 2,
        session_id: Optional[str] = None,
        skip_honeypot_check: bool = False,
        skip_osint: bool = False,
        skip_realtime: bool = False,
    ) -> ScanSession:
        sid     = session_id or str(uuid.uuid4())[:8]
        session = ScanSession(
            session_id=sid, target=target, ports=ports,
            scan_level=scan_level, settings=self.settings,
        )
        logger.info(f"[AegisEngine v3] == Session {sid} | {target} | Level {scan_level} ==")
        quick_scan = None

        try:
            # ── Phase 0: Adaptive Intelligence — پیش‌بینی قبل از اسکن ──────
            self._progress("Loading adaptive intelligence for target...", 1)
            try:
                intel_report = self.adaptive_engine.get_intelligence(target)
                session.intelligence = self.adaptive_engine.to_dict(intel_report)
                if intel_report.prior_scans > 0:
                    logger.info(
                        f"[AIE] Prior scans: {intel_report.prior_scans} | "
                        f"Port predictions: {len(intel_report.port_predictions)} | "
                        f"Change alerts: {len(intel_report.change_alerts)}"
                    )
                    if intel_report.change_alerts:
                        logger.warning(
                            f"[AIE] {len(intel_report.change_alerts)} changes detected "
                            f"since last scan!"
                        )
                session.phases_completed.append("adaptive_intelligence")
            except Exception as e:
                session.errors.append(f"Adaptive intelligence warning: {e}")

            # Phase 1: RTT + Packet Optimization
            self._progress("Measuring network conditions (RTT / packet loss)...", 3)
            rtt, pkt_loss = self.nmap.measure_rtt(target)
            session.optimized_params = self.pkt_optimizer.optimize(rtt, pkt_loss, scan_level)
            session.phases_completed.append("packet_optimization")

            # Phase 2: Realtime Network Analysis
            if not skip_realtime:
                self._progress("Real-time TCP analysis (fingerprint + middlebox)...", 7)
                try:
                    handshake = self.realtime.measure_tcp_handshake(target, 80)
                    test_ports = [80, 443, 22, 8080]
                    behavior = self.realtime.analyze_network_behavior(
                        target=target,
                        test_ports=test_ports,
                        duration_sec=5.0,
                    )
                    adaptation = self.realtime.adapt_scan_args(
                        original_args=session.optimized_params.get("nmap_args_override", "-sV -sC"),
                        behavior=behavior,
                        handshake=handshake,
                    )
                    session.realtime_analysis = {
                        "handshake":  self.realtime.handshake_to_dict(handshake),
                        "behavior":   self.realtime.behavior_to_dict(behavior),
                        "adaptation": self.realtime.adaptation_to_dict(adaptation),
                    }
                    if adaptation.adapted_args:
                        session.optimized_params["nmap_args_override"] = adaptation.adapted_args
                    session.phases_completed.append("realtime_analysis")
                    self._progress(
                        f"Network: RTT={behavior.avg_rtt_ms:.0f}ms | "
                        f"Timing={behavior.recommended_timing} | "
                        f"Middlebox={'YES' if behavior.middlebox_detected else 'NO'}", 9
                    )
                except Exception as e:
                    session.errors.append(f"Realtime analysis warning: {e}")
                    logger.warning(f"[Engine] Realtime skipped: {e}")

            # Phase 3: OSINT Intelligence
            if not skip_osint:
                self._progress("Gathering OSINT (DNS / GeoIP / Reputation / Shodan)...", 13)
                try:
                    osint_result = self.osint.gather(target, deep=True)
                    session.osint_data = self.osint.to_dict(osint_result)
                    session.phases_completed.append("osint")
                    geo_org     = osint_result.geo.org     if osint_result.geo else "unknown"
                    geo_country = osint_result.geo.country if osint_result.geo else "unknown"
                    logger.info(f"[Engine] OSINT: org={geo_org} | country={geo_country}")
                except Exception as e:
                    session.errors.append(f"OSINT warning: {e}")
                    logger.warning(f"[Engine] OSINT skipped: {e}")

            # Phase 4: Honeypot Detection
            if not skip_honeypot_check:
                self._progress("Honeypot pre-scan safety check...", 17)
                quick_scan = self.nmap.run_scan(target, "21,22,23,80,443,8080", 1)
                if quick_scan.success:
                    hp = self.honeypot_det.analyze(target, quick_scan.open_ports)
                    session.honeypot_analysis = self.honeypot_det.to_dict(hp)
                    session.phases_completed.append("honeypot_detection")
                    if hp.is_honeypot:
                        session.errors.append(
                            f"HONEYPOT DETECTED ({hp.verdict}, "
                            f"confidence={hp.confidence:.0%}). Scan aborted."
                        )
                        self._progress("HONEYPOT DETECTED — Aborting scan!", 100)
                        return self._finalize_session(session)

            # Phase 5: Evasion Profile
            self._progress("Building evasion profile (IDS/FW fingerprinting)...", 22)
            pre_ports = quick_scan.open_ports if quick_scan and quick_scan.success else []
            ev_obj = self.evasion_engine.analyze_and_build_profile(
                target=target, open_ports=pre_ports,
                rtt_ms=rtt, scan_level=scan_level,
            )
            session.evasion_profile = self.evasion_engine.to_dict(ev_obj)
            session.phases_completed.append("evasion_profiling")

            # Phase 6: Main Nmap Scan
            self._progress("Running evasion-aware Nmap scan with full NSE...", 28)
            final_args = (
                (session.realtime_analysis or {})
                .get("adaptation", {}).get("adapted_args")
                or ev_obj.final_nmap_args
                or session.optimized_params.get("nmap_args_override")
            )
            scan_result = self.nmap.run_scan(
                target=target, ports=ports,
                scan_level=scan_level, custom_args=final_args,
            )
            scan_result.rtt_ms          = rtt
            scan_result.packet_loss_pct = pkt_loss
            session.scan_result         = scan_result

            if not scan_result.success:
                session.errors.append(f"Scan failed: {scan_result.error}")
                return self._finalize_session(session)

            session.phases_completed.append("nmap_scan")
            self._progress(
                f"Scan complete: {scan_result.hosts_up} host(s), "
                f"{len(scan_result.open_ports)} port(s) open", 40
            )

            # Phase 7: Port Analysis
            self._progress("Analyzing services & risk scoring...", 46)
            session.port_analysis = self.port_analyzer.analyze(scan_result.open_ports)
            session.phases_completed.append("port_analysis")

            # Phase 8: Protocol Deep Inspection
            self._progress("Deep protocol inspection (TLS/SSH/HTTP)...", 52)
            try:
                pr = self.proto_inspector.inspect_all(target, scan_result.open_ports)
                session.protocol_inspection = self.proto_inspector.to_dict(pr)
                session.phases_completed.append("protocol_inspection")
            except Exception as e:
                session.errors.append(f"Protocol inspection error: {e}")

            # Phase 9: CVE Mapping
            self._progress("Mapping vulnerabilities via NVD API 2.0...", 58)
            session.vulnerabilities = self.vuln_engine.map_vulnerabilities(
                scan_result.open_ports
            )
            vuln_count = len(session.vulnerabilities or [])
            crit_count = sum(
                1 for v in (session.vulnerabilities or [])
                if v.get("severity") == "CRITICAL"
            )
            session.phases_completed.append("vuln_mapping")
            self._progress(f"CVEs: {vuln_count} total | {crit_count} CRITICAL", 62)

            # Phase 10: Exploit Suggestions
            self._progress("Searching exploit candidates (searchsploit / MSF)...", 65)
            session.exploit_suggestions = self.exploit_suggest.suggest(
                session.vulnerabilities or []
            )
            session.phases_completed.append("exploit_suggestion")

            # Phase 11: MITRE ATT&CK Kill Chain
            self._progress("Building MITRE ATT&CK kill chain...", 70)
            chain = self.attack_mapper.map(
                target=target,
                open_ports=scan_result.open_ports,
                vulnerabilities=session.vulnerabilities or [],
            )
            session.attack_chain = self.attack_mapper.to_dict(chain)
            session.phases_completed.append("attack_chain_mapping")

            # Phase 12: Lateral Movement Analysis
            self._progress("Analyzing lateral movement paths & pivot points...", 75)
            lm = self.lateral_analyzer.analyze(
                primary_target=target,
                open_ports=scan_result.open_ports,
            )
            session.lateral_movement = self.lateral_analyzer.to_dict(lm)
            session.phases_completed.append("lateral_movement")

            # Phase 13: AI Analysis (Ollama local)
            if self.settings.llm.enabled:
                self._progress("AI analysis (local Ollama — no cloud)...", 80)
                ai_r = self.llm.analyze_scan_results(scan_result.raw_data, target)
                if ai_r.success and ai_r.parsed:
                    session.ai_analysis = ai_r.parsed

                nba_r = self.llm.suggest_next_action(
                    open_ports=[p["port"] for p in scan_result.open_ports],
                    services=[p["service"] for p in scan_result.open_ports],
                    target=target, rtt_ms=rtt,
                )
                if nba_r.success and nba_r.parsed:
                    session.next_best_action = nba_r.parsed

                self._progress("AI attack path triage...", 84)
                triage_r = self.llm.triage_attack_paths(
                    open_ports=scan_result.open_ports,
                    vulnerabilities=session.vulnerabilities or [],
                    target=target,
                )
                if triage_r.success and triage_r.parsed:
                    session.ai_triage = triage_r.parsed

                session.phases_completed.append("ai_analysis")

            # Phase 14: OPSEC Scoring
            self._progress("Calculating OPSEC score...", 90)
            op = self.opsec_scorer.score(
                session_id=sid, target=target,
                scan_args=scan_result.scan_args,
                scan_level=scan_level,
                evasion_profile=session.evasion_profile,
                rtt_ms=rtt,
                open_ports_count=len(scan_result.open_ports),
            )
            session.opsec_report = self.opsec_scorer.to_dict(op)
            session.phases_completed.append("opsec_scoring")

            # ── Phase 15: Auto-Recon Loop (v4) ────────────────────────────
            if scan_result.open_ports:
                self._progress(
                    f"Auto-recon: deep-diving {len(scan_result.open_ports)} services...", 88
                )
                try:
                    ar = self.auto_recon.run(
                        target=target,
                        open_ports=scan_result.open_ports,
                        progress_cb=lambda msg: self._progress(msg, 88),
                    )
                    session.auto_recon = self.auto_recon.to_dict(ar)
                    crit_ar = len(ar.critical_findings)
                    high_ar = len(ar.high_findings)
                    session.phases_completed.append("auto_recon")
                    self._progress(
                        f"Auto-recon: {ar.total_checks} checks | "
                        f"{crit_ar} CRITICAL | {high_ar} HIGH", 90
                    )
                except Exception as e:
                    session.errors.append(f"Auto-recon error: {e}")

            # ── Phase 16: Stealth Advisor (v4) ─────────────────────────────
            self._progress("Calculating stealth score...", 92)
            try:
                stealth = self.stealth_advisor.analyze(session)
                session.stealth_score = self.stealth_advisor.to_dict(stealth)
                session.phases_completed.append("stealth_scoring")
                logger.info(
                    f"[Stealth] Score={stealth.score}/100 | "
                    f"Risk={stealth.detection_risk} | "
                    f"Detected={stealth.estimated_detected}"
                )
            except Exception as e:
                session.errors.append(f"Stealth advisor error: {e}")

            # Knowledge Base Update
            self._progress("Updating knowledge base...", 94)
            self.knowledge_base.save_session(session)
            session.phases_completed.append("knowledge_base")

            # ── Adaptive Engine Learning (v4) ───────────────────────────────
            try:
                self.adaptive_engine.learn_from_session(session)
                session.phases_completed.append("adaptive_learning")
            except Exception as e:
                session.errors.append(f"Adaptive learning error: {e}")

        except KeyboardInterrupt:
            session.errors.append("Scan interrupted by user")
            self._progress("Interrupted!", 100)
        except Exception as e:
            session.errors.append(f"Critical error: {e}")
            logger.exception(f"[AegisEngine] Critical: {e}")

        return self._finalize_session(session)

    def _finalize_session(self, session: ScanSession) -> ScanSession:
        session.end_time = time.time()
        try:
            self._progress("Generating reports (JSON + Markdown)...", 97)
            session.report_paths = {
                "json":     self.json_reporter.generate(session),
                "markdown": self.md_reporter.generate(session),
            }
        except Exception as e:
            session.errors.append(f"Report error: {e}")
        self._progress(
            f"Done! {len(session.phases_completed)} phases | "
            f"{session.duration:.1f}s | Errors={len(session.errors)}", 100
        )
        return session

    def health_check(self) -> dict:
        """بررسی وضعیت تمام ابزارها و API key ها"""
        import os
        checks = {
            "nmap":           self._check_tool("nmap"),
            "llm":            self.llm.check_availability(),
            "knowledge_base": self.knowledge_base.is_healthy(),
            "searchsploit":   self._check_tool("searchsploit"),
            "tcpdump":        self._check_tool("tcpdump"),
            "ping":           self._check_tool("ping"),
        }
        try:
            import scapy  # noqa
            checks["scapy"] = True
        except ImportError:
            checks["scapy"] = False

        checks["nvd_api_key"]    = bool(os.getenv("NVD_API_KEY"))
        checks["shodan_key"]     = bool(os.getenv("SHODAN_API_KEY"))
        checks["virustotal_key"] = bool(os.getenv("VIRUSTOTAL_API_KEY"))
        checks["abuseipdb_key"]  = bool(os.getenv("ABUSEIPDB_API_KEY"))
        # v4 stats
        checks["adaptive_stats"] = self.adaptive_engine.get_stats()

        # بررسی جداگانه: آیا سرور Ollama بالاست؟ (حتی اگر مدل نباشه)
        try:
            import requests as _req
            r = _req.get(
                f"{self.settings.llm.base_url}/api/tags",
                timeout=3
            )
            checks["llm_server_up"] = r.status_code == 200
        except Exception:
            checks["llm_server_up"] = False

        return checks

    @staticmethod
    def _check_tool(tool: str) -> bool:
        for flag in ("--version", "--help", "-h"):
            try:
                r = subprocess.run([tool, flag], capture_output=True, timeout=5)
                if r.returncode in (0, 1):
                    return True
            except FileNotFoundError:
                return False
            except Exception:
                continue
        return False
