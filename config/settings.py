# aegis-scanner/config/settings.py
"""
تنظیمات قابل پیکربندی Aegis-Scanner
مقادیر از متغیرهای محیطی یا فایل config خوانده می‌شوند
"""

import os
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class LLMSettings:
    base_url: str     = os.getenv("OLLAMA_URL", "http://localhost:11434")
    model: str        = os.getenv("OLLAMA_MODEL", "llama3")
    timeout: int      = int(os.getenv("OLLAMA_TIMEOUT", "120"))
    max_tokens: int   = 2048
    temperature: float = 0.1       # پایین نگه‌داشتن برای کاهش hallucination
    enabled: bool     = True


@dataclass
class NmapSettings:
    binary_path: str      = os.getenv("NMAP_PATH", "nmap")
    default_timeout: int  = 300
    max_retries: int       = 2
    privileged: bool       = False   # اگر True: با sudo اجرا می‌شود


@dataclass
class NetworkSettings:
    ping_timeout: float   = 5.0
    port_timeout: float   = 10.0
    max_concurrent: int   = 50
    default_mtu: int      = 1500


@dataclass
class ReportSettings:
    output_dir: str        = "reports"
    include_raw_nmap: bool = True
    include_ai_analysis: bool = True
    max_cves_per_service: int = 5


@dataclass
class AegisSettings:
    llm: LLMSettings         = field(default_factory=LLMSettings)
    nmap: NmapSettings        = field(default_factory=NmapSettings)
    network: NetworkSettings  = field(default_factory=NetworkSettings)
    report: ReportSettings    = field(default_factory=ReportSettings)
    debug: bool               = os.getenv("AEGIS_DEBUG", "false").lower() == "true"
    log_level: str            = os.getenv("AEGIS_LOG_LEVEL", "INFO")

    @classmethod
    def from_file(cls, config_path: str = "aegis_config.json") -> "AegisSettings":
        """بارگذاری تنظیمات از فایل JSON با اعتبارسنجی نوع داده"""
        path = Path(config_path)
        if not path.exists():
            return cls()
        try:
            with open(path) as f:
                data = json.load(f)
            settings = cls()

            # نگاشت نوع داده برای جلوگیری از تزریق مقادیر ناخواسته
            _type_map: dict = {
                "llm": {
                    "base_url": str, "model": str, "timeout": int,
                    "max_tokens": int, "temperature": float, "enabled": bool,
                },
                "nmap": {
                    "binary_path": str, "default_timeout": int,
                    "max_retries": int, "privileged": bool,
                },
                "network": {
                    "ping_timeout": float, "port_timeout": float,
                    "max_concurrent": int, "default_mtu": int,
                },
                "report": {
                    "output_dir": str, "include_raw_nmap": bool,
                    "include_ai_analysis": bool, "max_cves_per_service": int,
                },
            }

            for section, field_types in _type_map.items():
                if section not in data:
                    continue
                target_obj = getattr(settings, section)
                for k, expected_type in field_types.items():
                    if k not in data[section]:
                        continue
                    val = data[section][k]
                    try:
                        # تبدیل نوع با بررسی ایمن
                        typed_val = expected_type(val)
                        setattr(target_obj, k, typed_val)
                    except (ValueError, TypeError):
                        logging.warning(
                            f"[Settings] Invalid type for {section}.{k}: "
                            f"expected {expected_type.__name__}, got {type(val).__name__}"
                        )
            # ── api_keys: مستقیم از config فایل به env variables ──────────
            api_key_map = {
                "nvd_api_key":    "NVD_API_KEY",
                "shodan_api_key": "SHODAN_API_KEY",
                "virustotal_api_key": "VIRUSTOTAL_API_KEY",
                "abuseipdb_api_key":  "ABUSEIPDB_API_KEY",
                "ipinfo_token":   "IPINFO_TOKEN",
            }
            api_section = data.get("api_keys", {})
            for json_key, env_key in api_key_map.items():
                val = api_section.get(json_key, "")
                if val and isinstance(val, str) and not val.startswith("_"):
                    os.environ.setdefault(env_key, val)
                    logging.info(f"[Settings] Loaded API key: {env_key}")

            return settings
        except Exception as e:
            logging.warning(f"[Settings] Could not load config file: {e}. Using defaults.")
            return cls()

    def to_file(self, config_path: str = "aegis_config.json") -> None:
        """ذخیره تنظیمات جاری"""
        with open(config_path, "w") as f:
            json.dump(asdict(self), f, indent=2)

    def configure_logging(self) -> None:
        level = getattr(logging, self.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S",
        )
