# aegis-scanner/modules/packet_optimizer.py
"""
ماژول بهینه‌سازی پکت.
تنظیم خودکار MTU، Timing، و پارامترهای اسکن بر اساس شرایط شبکه.
"""

import logging
from config.constants import (
    NMAP_SCAN_LEVELS, NMAP_TIMING_PROFILES,
    MTU_ETHERNET, MTU_VPN, MTU_TUNNEL, RTT_THRESHOLDS
)

logger = logging.getLogger(__name__)


class PacketOptimizer:
    """
    بهینه‌سازی پارامترهای Nmap بر اساس:
    - RTT (Round Trip Time)
    - Packet Loss
    - Scan Level (از کاربر)
    
    هدف: تعادل بین سرعت، دقت، و قابلیت دور زدن IDS/Firewall
    """

    def optimize(
        self,
        rtt_ms: float,
        packet_loss_pct: float,
        scan_level: int,
    ) -> dict:
        """
        محاسبه بهترین پارامترهای Nmap.
        
        Returns:
            dict با کلیدهای:
            - timing: T0-T5
            - mtu: optimal MTU
            - min_rate: حداقل rate packet
            - max_retries: تعداد retry
            - nmap_args_override: args کامل جایگزین (یا None)
            - reasoning: توضیح تصمیمات
        """
        timing    = self._select_timing(rtt_ms, packet_loss_pct, scan_level)
        mtu       = self._select_mtu(rtt_ms, packet_loss_pct)
        min_rate  = self._calc_min_rate(rtt_ms, packet_loss_pct)
        max_rtr   = self._calc_max_retries(packet_loss_pct)
        reasoning = self._build_reasoning(rtt_ms, packet_loss_pct, timing, mtu)

        # بازسازی args با بهینه‌سازی‌ها
        base_args = NMAP_SCAN_LEVELS.get(scan_level, NMAP_SCAN_LEVELS[2])["args"]
        override  = self._build_optimized_args(
            base_args, timing, mtu, min_rate, max_rtr, packet_loss_pct
        )

        result = {
            "timing":              timing,
            "mtu":                 mtu,
            "min_rate":            min_rate,
            "max_retries":         max_rtr,
            "nmap_args_override":  override,
            "reasoning":           reasoning,
            "rtt_ms":              round(rtt_ms, 1),
            "packet_loss_pct":     round(packet_loss_pct, 1),
        }

        logger.info(
            f"[PacketOptimizer] RTT={rtt_ms:.0f}ms | Loss={packet_loss_pct:.0f}% "
            f"→ Timing={timing} | MTU={mtu}"
        )
        return result

    # ─── Timing selection ─────────────────────────────────────────────────
    @staticmethod
    def _select_timing(rtt_ms: float, loss_pct: float, scan_level: int) -> str:
        """
        انتخاب Timing Template بر اساس RTT و scan level.
        
        منطق:
        - scan_level 5 (stealth) → همیشه T1 یا T2
        - شبکه کند (RTT > 500ms) → T2
        - شبکه متوسط → T3
        - شبکه سریع و scan level بالا → T4
        """
        # Stealth mode اولویت دارد
        if scan_level == 5:
            return "T1" if rtt_ms > 200 else "T2"

        # بر اساس RTT
        if loss_pct > 20:
            return "T2"    # شبکه unstable
        if rtt_ms > RTT_THRESHOLDS["medium"]:   # >200ms
            return "T2"

        # RTT خوب است (≤200ms)
        if scan_level >= 3:
            return "T4"
        return "T3"

    # ─── MTU selection ─────────────────────────────────────────────────────
    @staticmethod
    def _select_mtu(rtt_ms: float, loss_pct: float) -> int:
        """
        انتخاب MTU بهینه.
        MTU پایین‌تر → fragmentation بیشتر → دور زدن برخی IDS‌ها.
        اما خیلی پایین → کندی شدید.
        """
        if loss_pct > 15:
            return MTU_TUNNEL     # 1280 برای شبکه‌های ضعیف
        if rtt_ms > 300:
            return MTU_VPN        # 1400
        return MTU_ETHERNET       # 1500 استاندارد

    # ─── Rate and retry ────────────────────────────────────────────────────
    @staticmethod
    def _calc_min_rate(rtt_ms: float, loss_pct: float) -> int:
        """محاسبه حداقل packet rate (packets/sec)"""
        if loss_pct > 20:   return 10
        if rtt_ms > 500:    return 50
        if rtt_ms > 100:    return 100
        return 300

    @staticmethod
    def _calc_max_retries(loss_pct: float) -> int:
        """تعداد retry بر اساس packet loss"""
        if loss_pct > 30:   return 5
        if loss_pct > 15:   return 3
        if loss_pct > 5:    return 2
        return 1

    # ─── Args builder ──────────────────────────────────────────────────────
    @staticmethod
    def _build_optimized_args(
        base_args: str, timing: str, mtu: int,
        min_rate: int, max_retries: int, loss_pct: float
    ) -> str:
        """ساختن args بهینه‌شده Nmap"""
        # حذف timing موجود از base_args
        import re
        args = re.sub(r"-T\d", "", base_args).strip()

        # اضافه کردن timing بهینه
        args += f" -{timing}"

        # MTU fragmentation (فقط اگر از 1500 کمتر باشد)
        if mtu < MTU_ETHERNET:
            args += f" --mtu {mtu}"

        # Min rate (فقط اگر packet loss پایین باشد)
        if loss_pct < 10:
            args += f" --min-rate {min_rate}"

        # Max retries
        if max_retries > 1:
            args += f" --max-retries {max_retries}"

        return args.strip()

    @staticmethod
    def _build_reasoning(
        rtt_ms: float, loss_pct: float, timing: str, mtu: int
    ) -> str:
        parts = []
        parts.append(f"RTT={rtt_ms:.0f}ms → timing {timing}")
        if mtu < MTU_ETHERNET:
            parts.append(f"MTU reduced to {mtu} for fragmentation-based IDS evasion")
        if loss_pct > 10:
            parts.append(f"High packet loss ({loss_pct:.0f}%) — conservative timing applied")
        return " | ".join(parts)
