# aegis-scanner/modules/campaign.py
"""
Multi-Target Campaign Mode — Aegis-Scanner v4
==============================================
اسکن همزمان چند target با اولویت‌بندی هوشمند و گزارش کمپین.

استفاده:
  python main.py --campaign targets.txt --level 2 --workers 3
"""

import json
import time
import logging
import threading
import ipaddress
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


@dataclass
class CampaignTarget:
    target:    str
    priority:  int = 5       # 1=highest, 10=lowest
    ports:     str = "1-1024"
    scan_level: int = 2
    notes:     str = ""


@dataclass
class CampaignResult:
    campaign_id: str
    start_time:  str
    end_time:    str
    total_targets: int
    completed:   int
    failed:      int
    duration_s:  float
    sessions:    list = field(default_factory=list)
    summary:     dict = field(default_factory=dict)
    report_path: str = ""


class CampaignEngine:
    """
    موتور کمپین — چند target را موازی اسکن می‌کند.
    """

    def __init__(self, max_workers: int = 3):
        self.max_workers = max_workers
        self._lock       = threading.Lock()
        self._results    = []

    @staticmethod
    def load_targets(file_path: str) -> list[CampaignTarget]:
        """
        بارگذاری لیست target‌ها از فایل.

        فرمت‌های پشتیبانی‌شده:
          192.168.1.1
          192.168.1.1:80,443
          192.168.1.0/24
          target.com priority=2 level=3
          # comment line
        """
        targets = []
        path    = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Target file not found: {file_path}")

        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split()
                host  = parts[0]

                # IP range → expand
                if "/" in host:
                    try:
                        network = ipaddress.ip_network(host, strict=False)
                        # فقط host‌ها نه network/broadcast
                        for ip in list(network.hosts())[:256]:
                            targets.append(CampaignTarget(target=str(ip)))
                        continue
                    except ValueError:
                        pass

                ct = CampaignTarget(target=host)
                for part in parts[1:]:
                    if "=" in part:
                        k, v = part.split("=", 1)
                        if k == "priority":
                            ct.priority = int(v)
                        elif k == "level":
                            ct.scan_level = int(v)
                        elif k == "ports":
                            ct.ports = v
                        elif k == "notes":
                            ct.notes = v

                targets.append(ct)

        # مرتب‌سازی بر اساس priority
        targets.sort(key=lambda t: t.priority)
        logger.info(f"[Campaign] Loaded {len(targets)} targets from {file_path}")
        return targets

    def run(
        self,
        targets: list[CampaignTarget],
        engine_factory: Callable,
        campaign_id: str,
        progress_cb: Optional[Callable] = None,
    ) -> CampaignResult:
        """
        اجرای کمپین با ThreadPoolExecutor.
        engine_factory: تابعی که یک AegisEngine جدید برمی‌گرداند
        """
        start_time = time.time()
        completed  = 0
        failed     = 0
        total      = len(targets)

        if progress_cb:
            progress_cb(f"Campaign {campaign_id} — {total} targets, {self.max_workers} workers")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self._scan_one,
                    target, engine_factory(), progress_cb
                ): target
                for target in targets
            }

            for future in as_completed(futures):
                tgt = futures[future]
                try:
                    session = future.result()
                    with self._lock:
                        self._results.append(session)
                        completed += 1
                    if progress_cb:
                        progress_cb(
                            f"[{completed}/{total}] Done: {tgt.target} — "
                            f"{len(session.scan_result.open_ports) if session.scan_result else 0} ports"
                        )
                except Exception as e:
                    failed += 1
                    logger.error(f"[Campaign] {tgt.target} failed: {e}")

        end_time = time.time()
        result   = CampaignResult(
            campaign_id=campaign_id,
            start_time=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(start_time)),
            end_time=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(end_time)),
            total_targets=total,
            completed=completed,
            failed=failed,
            duration_s=round(end_time - start_time, 1),
        )

        result.summary = self._build_summary()
        result.sessions = [s.session_id for s in self._results]
        return result

    def _scan_one(self, target: CampaignTarget, engine, progress_cb):
        """اسکن یک target با engine جداگانه"""
        return engine.run_full_scan(
            target=target.target,
            ports=target.ports,
            scan_level=target.scan_level,
            skip_honeypot_check=False,
            skip_osint=True,
            skip_realtime=False,
        )

    def _build_summary(self) -> dict:
        """خلاصه نتایج کمپین"""
        all_ports, all_vulns, all_criticals = [], [], []
        hosts_up = 0

        for session in self._results:
            if session.scan_result and session.scan_result.hosts_up > 0:
                hosts_up += 1
                all_ports.extend(session.scan_result.open_ports or [])
            all_vulns.extend(session.vulnerabilities or [])

        all_criticals = [v for v in all_vulns if v.get("severity") == "CRITICAL"]

        # رایج‌ترین پورت‌ها
        from collections import Counter
        port_counter = Counter(p["port"] for p in all_ports)
        top_ports    = port_counter.most_common(10)

        # رایج‌ترین CVE‌ها
        cve_counter  = Counter(v.get("cve_id", "") for v in all_vulns if v.get("cve_id"))
        top_cves     = cve_counter.most_common(5)

        return {
            "hosts_up":        hosts_up,
            "total_open_ports": len(all_ports),
            "total_cves":      len(all_vulns),
            "critical_cves":   len(all_criticals),
            "top_ports":       [{"port": p, "count": c} for p, c in top_ports],
            "top_cves":        [{"cve": c, "count": n} for c, n in top_cves],
            "attack_surface":  "HIGH" if len(all_criticals) > 0 else
                               "MEDIUM" if len(all_vulns) > 0 else "LOW",
        }

    def save_campaign_report(self, result: CampaignResult, output_dir: str = "reports") -> str:
        """ذخیره گزارش JSON کمپین"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        ts   = time.strftime("%Y%m%d_%H%M%S")
        path = f"{output_dir}/campaign_{result.campaign_id}_{ts}.json"
        with open(path, "w") as f:
            json.dump(asdict(result), f, indent=2, ensure_ascii=False)
        logger.info(f"[Campaign] Report saved: {path}")
        return path
