# aegis-scanner/intelligence/adaptive_engine.py
"""
Adaptive Intelligence Engine — Aegis-Scanner v4
================================================
قلب v4: از هر اسکن یاد می‌گیرد و دفعه بعد هوشمندتر عمل می‌کند.

قابلیت‌ها:
  ① Subnet fingerprinting  — هر /24 یا /16 یک profile داره
  ② Port prediction         — پیش‌بینی پورت‌های باز قبل از اسکن
  ③ CVE correlation         — CVE‌های احتمالی بر اساس target profile
  ④ Evasion memory          — کدام technique برای این target کار کرد
  ⑤ Change detection        — target تغییر کرده؟
  ⑥ Confidence scoring      — هر پیش‌بینی یک confidence score داره
  ⑦ Trend analysis          — روند تغییرات در طول زمان
"""

import json
import math
import hashlib
import logging
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass, field, asdict
from collections import Counter, defaultdict

logger = logging.getLogger(__name__)

# ─── Data structures ──────────────────────────────────────────────────────────

@dataclass
class PortPrediction:
    port:        int
    service:     str
    confidence:  float       # 0.0 – 1.0
    seen_count:  int
    last_seen:   str
    basis:       str         # "subnet_history" | "service_pattern" | "ip_class"


@dataclass
class CVEPrediction:
    cve_id:     str
    service:    str
    cvss_score: float
    confidence: float
    basis:      str


@dataclass
class EvasionRecommendation:
    nmap_args:        str
    timing:           str
    mtu:              int
    use_decoys:       bool
    use_fragmentation: bool
    confidence:       float
    basis:            str


@dataclass
class ChangeAlert:
    port:        int
    change_type: str          # "new_port" | "closed_port" | "version_change" | "new_cve"
    old_value:   str
    new_value:   str
    severity:    str          # "HIGH" | "MEDIUM" | "LOW"


@dataclass
class IntelligenceReport:
    target:                str
    subnet:                str
    prior_scans:           int
    last_scanned:          Optional[str]
    port_predictions:      list = field(default_factory=list)
    cve_predictions:       list = field(default_factory=list)
    evasion_recommendation: Optional[dict]                  = None
    change_alerts:         list = field(default_factory=list)
    trend_summary:         str  = ""
    confidence_overall:    float = 0.0
    target_fingerprint:    str  = ""


# ─── Main Engine ──────────────────────────────────────────────────────────────

class AdaptiveIntelligenceEngine:
    """
    موتور یادگیری تطبیقی — هر اسکن داده‌ای به حافظه اضافه می‌کند
    و پیش‌بینی‌های دقیق‌تری برای اسکن بعدی می‌سازد.
    """

    VERSION = "4.0"
    DATA_FILE = "data/adaptive_intelligence.json"

    # حداقل اسکن برای پیش‌بینی قابل اعتماد
    MIN_SCANS_FOR_PREDICTION = 2
    # TTL: داده‌های قدیمی‌تر از این کم‌اهمیت‌تر می‌شوند
    DATA_DECAY_DAYS = 90

    def __init__(self, data_file: str = DATA_FILE):
        self.path = Path(data_file)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = self._load()
        logger.info(
            f"[AIE] Adaptive Intelligence Engine v{self.VERSION} loaded | "
            f"subnets={len(self._db.get('subnets', {}))} | "
            f"targets={len(self._db.get('targets', {}))}"
        )

    # ─── Persistence ──────────────────────────────────────────────────────
    def _load(self) -> dict:
        if self.path.exists():
            try:
                with open(self.path) as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"[AIE] Load error: {e} — starting fresh")
        return {
            "version":  self.VERSION,
            "subnets":  {},     # /24 → subnet profile
            "targets":  {},     # ip/host → target history
            "services": {},     # service_name → service intelligence
            "evasion":  {},     # target_hash → evasion profile
            "meta":     {"created": datetime.now().isoformat(), "total_scans": 0}
        }

    def _save(self) -> None:
        try:
            with open(self.path, "w") as f:
                json.dump(self._db, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"[AIE] Save error: {e}")

    # ─── Learning ─────────────────────────────────────────────────────────
    def learn_from_session(self, session) -> None:
        """
        یاد گرفتن از یک scan session کامل.
        این تابع بعد از هر اسکن موفق صدا زده می‌شود.
        """
        if not session.scan_result:
            return

        target     = session.target
        open_ports = session.scan_result.open_ports or []
        vulns      = session.vulnerabilities or []
        evasion    = session.evasion_profile or {}
        opsec      = session.opsec_report or {}
        rtt        = session.scan_result.rtt_ms or 0
        timestamp  = datetime.now().isoformat()

        # ① subnet learning
        subnet = self._get_subnet(target)
        self._learn_subnet(subnet, open_ports, rtt, timestamp)

        # ② target learning
        self._learn_target(
            target, open_ports, vulns, evasion,
            opsec, rtt, session.scan_result.scan_args, timestamp
        )

        # ③ service learning
        self._learn_services(open_ports, vulns, timestamp)

        # ④ evasion learning
        self._learn_evasion(target, evasion, opsec, timestamp)

        # meta
        self._db["meta"]["total_scans"] = self._db["meta"].get("total_scans", 0) + 1
        self._db["meta"]["last_scan"]   = timestamp

        self._save()
        logger.info(
            f"[AIE] Learned from session {session.session_id} | "
            f"target={target} | ports={len(open_ports)} | vulns={len(vulns)}"
        )

    def _learn_subnet(
        self, subnet: str, open_ports: list,
        rtt: float, timestamp: str
    ) -> None:
        """یادگیری الگوهای یک subnet /24"""
        sn = self._db["subnets"].setdefault(subnet, {
            "scan_count": 0,
            "port_frequency": {},    # port → count
            "service_frequency": {}, # service → count
            "avg_rtt": 0.0,
            "rtt_samples": [],
            "last_seen": timestamp,
            "first_seen": timestamp,
        })

        sn["scan_count"] = sn.get("scan_count", 0) + 1
        sn["last_seen"]  = timestamp

        # port frequency
        pf = sn.setdefault("port_frequency", {})
        for p in open_ports:
            key = str(p["port"])
            pf[key] = pf.get(key, 0) + 1

        # service frequency
        sf = sn.setdefault("service_frequency", {})
        for p in open_ports:
            svc = p.get("service", "unknown")
            sf[svc] = sf.get(svc, 0) + 1

        # RTT moving average (keep last 20 samples)
        samples = sn.setdefault("rtt_samples", [])
        if rtt > 0:
            samples.append(rtt)
            if len(samples) > 20:
                samples.pop(0)
            sn["avg_rtt"] = sum(samples) / len(samples)

    def _learn_target(
        self, target: str, open_ports: list, vulns: list,
        evasion: dict, opsec: dict, rtt: float,
        scan_args: str, timestamp: str
    ) -> None:
        """یادگیری تاریخچه یک target مشخص"""
        th = self._db["targets"].setdefault(target, {
            "scan_count":    0,
            "first_seen":    timestamp,
            "history":       [],     # آخرین 10 snapshot
            "fingerprint":   "",
        })

        th["scan_count"] = th.get("scan_count", 0) + 1
        th["last_seen"]  = timestamp

        # snapshot این اسکن
        snapshot = {
            "timestamp":  timestamp,
            "ports":      [{"port": p["port"], "service": p.get("service",""),
                           "version": f"{p.get('product','')} {p.get('version','')}".strip()}
                          for p in open_ports],
            "cves":       [v.get("cve_id","") for v in vulns if v.get("cve_id")],
            "rtt_ms":     round(rtt, 1),
            "scan_args":  scan_args,
            "opsec_score": opsec.get("opsec_score", 0),
            "firewall":   evasion.get("firewall_detected", False),
        }
        history = th.setdefault("history", [])
        history.insert(0, snapshot)
        if len(history) > 10:
            history.pop()

        # fingerprint: hash از پورت‌های باز (برای تشخیص تغییر)
        port_set = sorted(str(p["port"]) for p in open_ports)
        th["fingerprint"] = hashlib.md5(":".join(port_set).encode()).hexdigest()[:8]

    def _learn_services(self, open_ports: list, vulns: list, timestamp: str) -> None:
        """یادگیری الگوهای سرویس‌ها و CVE‌های مرتبط"""
        vuln_by_service = defaultdict(list)
        for v in vulns:
            svc = v.get("service", "")
            if svc:
                vuln_by_service[svc].append({
                    "cve_id":     v.get("cve_id", ""),
                    "cvss_score": v.get("cvss_score", 0),
                    "severity":   v.get("severity", ""),
                })

        for p in open_ports:
            svc   = p.get("service", "unknown")
            port  = p["port"]
            ver   = f"{p.get('product','')} {p.get('version','')}".strip()
            svc_db = self._db["services"].setdefault(svc, {
                "port_associations": {},
                "known_cves": {},
                "version_patterns": [],
                "occurrence_count": 0,
                "last_seen": timestamp,
            })

            svc_db["occurrence_count"] = svc_db.get("occurrence_count", 0) + 1
            svc_db["last_seen"]        = timestamp

            # port associations
            pa = svc_db.setdefault("port_associations", {})
            pa[str(port)] = pa.get(str(port), 0) + 1

            # version patterns
            if ver and ver not in svc_db.get("version_patterns", []):
                vp = svc_db.setdefault("version_patterns", [])
                vp.append(ver)
                if len(vp) > 20:
                    vp.pop(0)

            # CVE associations
            kc = svc_db.setdefault("known_cves", {})
            for vuln in vuln_by_service.get(svc, []):
                cve = vuln["cve_id"]
                if cve:
                    entry = kc.setdefault(cve, {"count": 0, "cvss": 0, "severity": ""})
                    entry["count"]    += 1
                    entry["cvss"]      = vuln["cvss_score"]
                    entry["severity"]  = vuln["severity"]

    def _learn_evasion(
        self, target: str, evasion: dict,
        opsec: dict, timestamp: str
    ) -> None:
        """یادگیری اینکه کدام evasion technique برای این target کار کرد"""
        if not evasion:
            return

        th = self._get_target_hash(target)
        ev = self._db["evasion"].setdefault(th, {
            "target":           target,
            "profiles":         [],
            "best_opsec_score": 0,
            "best_args":        "",
            "firewall_detected": False,
            "ids_detected":     False,
        })

        opsec_score  = opsec.get("opsec_score", 0)
        profile_entry = {
            "timestamp":    timestamp,
            "args":         evasion.get("final_nmap_args", ""),
            "techniques":   evasion.get("techniques_applied", []),
            "evasion_score": evasion.get("evasion_score", 0),
            "opsec_score":  opsec_score,
            "firewall":     evasion.get("firewall_detected", False),
            "ids":          evasion.get("ids_detected", False),
        }

        profiles = ev.setdefault("profiles", [])
        profiles.insert(0, profile_entry)
        if len(profiles) > 5:
            profiles.pop()

        # بهترین OPSEC score رو ذخیره کن
        if opsec_score > ev.get("best_opsec_score", 0):
            ev["best_opsec_score"] = opsec_score
            ev["best_args"]        = evasion.get("final_nmap_args", "")

        ev["firewall_detected"] = evasion.get("firewall_detected", False)
        ev["ids_detected"]      = evasion.get("ids_detected", False)

    # ─── Prediction ───────────────────────────────────────────────────────
    def get_intelligence(self, target: str) -> IntelligenceReport:
        """
        تولید گزارش هوشمند برای یک target قبل از شروع اسکن.
        این اطلاعات به engine اصلی کمک می‌کند تصمیم بهتری بگیرد.
        """
        subnet       = self._get_subnet(target)
        target_data  = self._db["targets"].get(target, {})
        subnet_data  = self._db["subnets"].get(subnet, {})
        prior_scans  = target_data.get("scan_count", 0)
        last_scanned = target_data.get("last_seen")
        fingerprint  = target_data.get("fingerprint", "")

        report = IntelligenceReport(
            target=target, subnet=subnet,
            prior_scans=prior_scans,
            last_scanned=last_scanned,
            target_fingerprint=fingerprint,
        )

        # پیش‌بینی پورت‌ها
        report.port_predictions = self._predict_ports(
            target, target_data, subnet_data
        )

        # پیش‌بینی CVE‌ها
        report.cve_predictions = self._predict_cves(target_data)

        # توصیه evasion
        ev_rec = self._recommend_evasion(target)
        report.evasion_recommendation = asdict(ev_rec) if ev_rec else None

        # تشخیص تغییر
        report.change_alerts = self._detect_changes(target_data)

        # خلاصه trend
        report.trend_summary = self._build_trend_summary(
            target_data, subnet_data, prior_scans
        )

        # امتیاز کلی اطمینان
        report.confidence_overall = self._overall_confidence(prior_scans)

        return report

    def _predict_ports(
        self, target: str,
        target_data: dict, subnet_data: dict
    ) -> list:
        """پیش‌بینی پورت‌های احتمالی باز"""
        predictions = []
        seen_ports   = set()
        total_subnet = max(subnet_data.get("scan_count", 0), 1)

        # ── از تاریخچه خود target ──────────────────────────────────────
        history = target_data.get("history", [])
        port_counter = Counter()
        port_service = {}
        for snap in history:
            for p in snap.get("ports", []):
                port_counter[p["port"]] += 1
                port_service[p["port"]] = p.get("service", "")

        for port, count in port_counter.most_common(15):
            conf  = min(count / max(len(history), 1), 1.0)
            decay = self._time_decay(history[0].get("timestamp") if history else None)
            predictions.append(PortPrediction(
                port=port, service=port_service.get(port, ""),
                confidence=round(conf * decay, 2),
                seen_count=count, last_seen=history[0]["timestamp"] if history else "",
                basis="target_history",
            ))
            seen_ports.add(port)

        # ── از الگوی subnet ────────────────────────────────────────────
        pf = subnet_data.get("port_frequency", {})
        for port_str, count in sorted(pf.items(), key=lambda x: -x[1])[:10]:
            port = int(port_str)
            if port in seen_ports:
                continue
            conf  = min(count / total_subnet, 0.85)
            sf    = subnet_data.get("service_frequency", {})
            svc   = max(sf, key=sf.get) if sf else ""
            if conf > 0.15:
                predictions.append(PortPrediction(
                    port=port, service=svc,
                    confidence=round(conf, 2),
                    seen_count=count, last_seen=subnet_data.get("last_seen", ""),
                    basis="subnet_pattern",
                ))
                seen_ports.add(port)

        # مرتب‌سازی بر اساس confidence
        predictions.sort(key=lambda x: -x.confidence)
        return [asdict(p) for p in predictions[:12]]

    def _predict_cves(self, target_data: dict) -> list:
        """پیش‌بینی CVE‌های احتمالی بر اساس سرویس‌های شناخته‌شده"""
        predictions = []
        history     = target_data.get("history", [])
        if not history:
            return []

        # سرویس‌هایی که قبلاً دیده‌ایم
        known_services = set()
        for snap in history[:3]:
            for p in snap.get("ports", []):
                svc = p.get("service", "")
                if svc:
                    known_services.add(svc)

        seen_cves = set()
        # CVE‌هایی که قبلاً روی این target دیده‌ایم
        for snap in history:
            for cve in snap.get("cves", []):
                if cve and cve not in seen_cves:
                    seen_cves.add(cve)
                    predictions.append(CVEPrediction(
                        cve_id=cve, service="",
                        cvss_score=0, confidence=0.9,
                        basis="target_history",
                    ))

        # CVE‌های مرتبط با سرویس‌های شناخته‌شده
        for svc in known_services:
            svc_data = self._db["services"].get(svc, {})
            for cve_id, cve_info in svc_data.get("known_cves", {}).items():
                if cve_id in seen_cves:
                    continue
                count = cve_info.get("count", 0)
                occ   = svc_data.get("occurrence_count", 1)
                conf  = min(count / max(occ, 1), 0.80)
                if conf > 0.1:
                    predictions.append(CVEPrediction(
                        cve_id=cve_id, service=svc,
                        cvss_score=cve_info.get("cvss", 0),
                        confidence=round(conf, 2),
                        basis="service_pattern",
                    ))
                    seen_cves.add(cve_id)

        predictions.sort(key=lambda x: -(x.cvss_score * x.confidence))
        return [asdict(p) for p in predictions[:10]]

    def _recommend_evasion(self, target: str) -> Optional[EvasionRecommendation]:
        """توصیه بهترین evasion profile بر اساس تاریخچه"""
        th      = self._get_target_hash(target)
        ev_data = self._db["evasion"].get(th)
        if not ev_data:
            return None

        profiles = ev_data.get("profiles", [])
        if not profiles:
            return None

        # بهترین profile بر اساس opsec_score
        best = max(profiles, key=lambda p: p.get("opsec_score", 0))
        has_fw  = ev_data.get("firewall_detected", False)
        has_ids = ev_data.get("ids_detected", False)

        techs = best.get("techniques", [])
        conf  = min(len(profiles) / 5.0, 0.9)

        return EvasionRecommendation(
            nmap_args=best.get("args", ""),
            timing="-T1" if has_ids else ("-T2" if has_fw else "-T3"),
            mtu=1280 if has_fw else 1500,
            use_decoys=has_fw or has_ids,
            use_fragmentation=has_fw,
            confidence=round(conf, 2),
            basis=f"best of {len(profiles)} previous profiles (opsec={best.get('opsec_score',0)}/10)",
        )

    def _detect_changes(self, target_data: dict) -> list:
        """تشخیص تغییرات نسبت به اسکن قبلی"""
        alerts  = []
        history = target_data.get("history", [])
        if len(history) < 2:
            return []

        curr  = history[0]
        prev  = history[1]

        curr_ports = {p["port"]: p for p in curr.get("ports", [])}
        prev_ports = {p["port"]: p for p in prev.get("ports", [])}

        # پورت‌های جدید
        for port, p in curr_ports.items():
            if port not in prev_ports:
                alerts.append(ChangeAlert(
                    port=port, change_type="new_port",
                    old_value="closed",
                    new_value=p.get("service", "unknown"),
                    severity="HIGH",
                ))

        # پورت‌های بسته‌شده
        for port, p in prev_ports.items():
            if port not in curr_ports:
                alerts.append(ChangeAlert(
                    port=port, change_type="closed_port",
                    old_value=p.get("service", "unknown"),
                    new_value="closed",
                    severity="MEDIUM",
                ))

        # تغییر version
        for port in set(curr_ports) & set(prev_ports):
            cv = curr_ports[port].get("version", "")
            pv = prev_ports[port].get("version", "")
            if cv and pv and cv != pv:
                alerts.append(ChangeAlert(
                    port=port, change_type="version_change",
                    old_value=pv, new_value=cv,
                    severity="MEDIUM",
                ))

        # CVE‌های جدید
        curr_cves = set(curr.get("cves", []))
        prev_cves = set(prev.get("cves", []))
        for cve in curr_cves - prev_cves:
            alerts.append(ChangeAlert(
                port=0, change_type="new_cve",
                old_value="not found", new_value=cve,
                severity="HIGH",
            ))

        return [asdict(a) for a in alerts]

    def _build_trend_summary(
        self, target_data: dict,
        subnet_data: dict, prior_scans: int
    ) -> str:
        """ساخت خلاصه روند تغییرات"""
        if prior_scans == 0:
            return "اولین اسکن این target — هیچ داده‌ای از گذشته وجود ندارد."

        history = target_data.get("history", [])
        parts   = [f"{prior_scans} اسکن قبلی ثبت‌شده."]

        if len(history) >= 2:
            prev_ports = len(history[1].get("ports", []))
            curr_ports = len(history[0].get("ports", []))
            if curr_ports > prev_ports:
                parts.append(f"سطح حمله گسترش یافته (+{curr_ports - prev_ports} پورت).")
            elif curr_ports < prev_ports:
                parts.append(f"سطح حمله کاهش یافته ({prev_ports - curr_ports} پورت بسته شد).")
            else:
                parts.append("سطح حمله تغییری نکرده.")

        avg_rtt = subnet_data.get("avg_rtt", 0)
        if avg_rtt:
            parts.append(f"میانگین RTT این subnet: {avg_rtt:.0f}ms.")

        sc = subnet_data.get("scan_count", 0)
        if sc > 1:
            top_ports = sorted(
                subnet_data.get("port_frequency", {}).items(),
                key=lambda x: -x[1]
            )[:3]
            if top_ports:
                port_str = ", ".join(p[0] for p in top_ports)
                parts.append(f"رایج‌ترین پورت‌های subnet: {port_str}.")

        return " ".join(parts)

    # ─── Helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _get_subnet(target: str) -> str:
        """استخراج /24 subnet از IP یا hostname"""
        try:
            ip   = ipaddress.ip_address(target)
            net  = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(net)
        except ValueError:
            # hostname — از دامنه اصلی استفاده می‌کنیم
            parts = target.rsplit(".", 2)
            return ".".join(parts[-2:]) if len(parts) >= 2 else target

    @staticmethod
    def _get_target_hash(target: str) -> str:
        return hashlib.md5(target.encode()).hexdigest()[:12]

    @staticmethod
    def _time_decay(timestamp_str: Optional[str]) -> float:
        """ضریب کاهش اهمیت داده با گذشت زمان (0.3 – 1.0)"""
        if not timestamp_str:
            return 0.5
        try:
            ts   = datetime.fromisoformat(timestamp_str)
            days = (datetime.now() - ts).days
            # exponential decay: نصف می‌شه هر 30 روز، کف 0.3
            return max(0.3, math.exp(-days * math.log(2) / 30))
        except Exception:
            return 0.5

    @staticmethod
    def _overall_confidence(prior_scans: int) -> float:
        """اطمینان کلی بر اساس تعداد اسکن‌های قبلی"""
        if prior_scans == 0:  return 0.0
        if prior_scans == 1:  return 0.3
        if prior_scans == 2:  return 0.5
        if prior_scans < 5:   return 0.7
        if prior_scans < 10:  return 0.85
        return 0.95

    # ─── Reporting ────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        return {
            "version":        self.VERSION,
            "total_scans":    self._db["meta"].get("total_scans", 0),
            "subnets_known":  len(self._db["subnets"]),
            "targets_known":  len(self._db["targets"]),
            "services_known": len(self._db["services"]),
            "evasion_profiles": len(self._db["evasion"]),
            "last_scan":      self._db["meta"].get("last_scan", "never"),
        }

    def to_dict(self, report: IntelligenceReport) -> dict:
        return asdict(report)
