# aegis-scanner/core/llm_connector.py
"""
اتصال به LLM محلی (Ollama/Llama 3) برای تحلیل هوشمند نتایج اسکن.
تمامی prompt‌ها ساختارمند هستند و hallucination را به حداقل می‌رسانند.

معماری: BaseLLMProvider → OllamaProvider (پیش‌فرض)
امکان گسترش به OpenAI/Anthropic بدون تغییر کد اصلی.
"""

import json
import logging
import requests
from typing import Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod

from config.settings import LLMSettings

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """پاسخ ساختارمند از LLM"""
    raw_text: str
    parsed: Optional[dict]
    model: str
    tokens_used: int
    success: bool
    error: Optional[str] = None


# ─── Abstract provider interface ─────────────────────────────────────────────
class BaseLLMProvider(ABC):
    """رابط پایه برای هر LLM provider"""

    @abstractmethod
    def call(self, system: str, user_prompt: str) -> LLMResponse:
        ...

    @abstractmethod
    def check_availability(self) -> bool:
        ...


# ─── Ollama provider ──────────────────────────────────────────────────────────
class OllamaProvider(BaseLLMProvider):
    """
    ارتباط با Ollama local server.
    بهترین گزینه برای red team محلی — بدون هزینه، بدون ارسال داده به cloud.
    """

    def __init__(self, settings: LLMSettings):
        self.settings  = settings
        self.base_url  = settings.base_url.rstrip("/")
        self.model     = settings.model
        self._available: Optional[bool] = None

    def check_availability(self) -> bool:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                # match: "llama3" matches "llama3", "llama3:latest", "llama3:8b", etc.
                base_name = self.model.split(":")[0]
                exact     = self.model in models
                prefix    = any(m == self.model or m.startswith(base_name + ":") or m == base_name
                                for m in models)
                self._available = exact or prefix
                if self._available:
                    # اگر match دقیق نبود، model name رو آپدیت کن
                    if not exact:
                        matched = next(
                            (m for m in models
                             if m == self.model or m.startswith(base_name + ":")),
                            None
                        )
                        if matched:
                            self.model = matched
                            logger.info(f"[LLM/Ollama] Using model: {matched}")
                else:
                    logger.warning(
                        f"[LLM/Ollama] Model '{self.model}' not found. "
                        f"Available: {models}. "
                        f"Run: ollama pull {self.model}"
                    )
                return self._available
        except requests.ConnectionError:
            logger.warning(
                "[LLM/Ollama] Server not reachable at %s\n"
                "  Fix: Run  →  ollama serve\n"
                "  If not installed: https://ollama.com/install.sh",
                self.base_url
            )
        except Exception as e:
            logger.error(f"[LLM/Ollama] Availability check failed: {e}")
        self._available = False
        return False

    @property
    def is_available(self) -> bool:
        if self._available is None:
            return self.check_availability()
        return self._available

    def call(self, system: str, user_prompt: str) -> LLMResponse:
        if not self.is_available:
            return LLMResponse(
                raw_text="", parsed=None, model=self.model,
                tokens_used=0, success=False,
                error="Ollama not available"
            )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user_prompt},
            ],
            "stream": False,
            "options": {
                "temperature":    self.settings.temperature,
                "num_predict":    self.settings.max_tokens,
                "num_ctx":        8192,
                "repeat_penalty": 1.1,
            },
        }

        # retry تا ۲ بار برای خطاهای شبکه‌ای
        last_error = ""
        for attempt in range(1, 3):
            try:
                resp = requests.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                    timeout=self.settings.timeout,
                )
                resp.raise_for_status()
                data     = resp.json()
                raw_text = data.get("message", {}).get("content", "")
                tokens   = data.get("eval_count", 0)
                parsed   = LLMConnector._safe_parse_json(raw_text)
                return LLMResponse(
                    raw_text=raw_text, parsed=parsed,
                    model=self.model, tokens_used=tokens,
                    success=True
                )
            except requests.Timeout:
                last_error = f"Timeout after {self.settings.timeout}s (attempt {attempt})"
                logger.warning(f"[LLM/Ollama] {last_error}")
            except requests.ConnectionError:
                last_error = "Connection refused — is ollama serve running?"
                logger.warning(f"[LLM/Ollama] {last_error}")
                break   # retry نمی‌کنیم — سرور اصلاً بالا نیست
            except requests.HTTPError as e:
                last_error = f"HTTP {e.response.status_code}: {e}"
                logger.error(f"[LLM/Ollama] {last_error}")
                break
            except Exception as e:
                last_error = str(e)
                logger.error(f"[LLM/Ollama] Unexpected error: {e}")
                break

        return LLMResponse(
            raw_text="", parsed=None, model=self.model,
            tokens_used=0, success=False, error=last_error
        )


# ─── Main connector (facade) ──────────────────────────────────────────────────
class LLMConnector:
    """
    رابط اصلی LLM — از OllamaProvider استفاده می‌کند.
    اصل طراحی: هیچ‌گاه خروجی LLM را بدون اعتبارسنجی به pipeline اصلی
    تزریق نمی‌کنیم. هر پاسخ باید با داده‌های واقعی Nmap تطابق داشته باشد.
    """

    # ─── System prompts ────────────────────────────────────────────────────
    SYSTEM_PROMPT_ANALYST = """You are an expert cybersecurity analyst embedded in an automated penetration testing tool called Aegis-Scanner.

STRICT RULES:
1. Only analyze data provided to you. NEVER fabricate CVEs, exploits, or vulnerabilities.
2. All recommendations must be based on actual service/version data from Nmap output.
3. Return ONLY valid JSON. No markdown, no explanation outside the JSON structure.
4. If you are uncertain, set confidence to "low" and explain in the notes field.
5. CVE IDs must follow exact format: CVE-YYYY-NNNNN. Do not invent CVE IDs.
6. Think like a red teamer: identify highest-impact attack paths first.

Your role: Analyze real Nmap scan output and provide structured security insights for authorized penetration testing."""

    SYSTEM_PROMPT_OPTIMIZER = """You are a network reconnaissance expert optimizing Nmap scan parameters for authorized red team operations.

STRICT RULES:
1. Only suggest parameters that exist in Nmap's actual documentation.
2. Base timing recommendations on the RTT data provided.
3. Return ONLY valid JSON with the exact schema requested.
4. Do not suggest illegal or unauthorized actions."""

    SYSTEM_PROMPT_TRIAGE = """You are a security triage specialist. Given a list of open ports and services, you identify the most critical attack vectors for authorized penetration testing.

Return ONLY valid JSON. Prioritize findings by exploitability and impact. Focus on actionable intelligence."""

    def __init__(self, settings: LLMSettings):
        self.settings = settings
        self._provider: BaseLLMProvider = OllamaProvider(settings)

    def check_availability(self) -> bool:
        return self._provider.check_availability()

    @property
    def is_available(self) -> bool:
        return self._provider.is_available

    def _call(self, system: str, user_prompt: str) -> LLMResponse:
        """لایه پایه ارتباط — از provider فعال استفاده می‌کند"""
        return self._provider.call(system, user_prompt)

    # ─── JSON parser ──────────────────────────────────────────────────────
    @staticmethod
    def _safe_parse_json(text: str) -> Optional[dict]:
        """استخراج JSON از پاسخ LLM با مقاومت در برابر خطا"""
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end   = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
        return None

    # ─── Public analysis methods ──────────────────────────────────────────
    def analyze_scan_results(self, nmap_data: dict, target: str) -> LLMResponse:
        """تحلیل خروجی خام Nmap و تولید بینش امنیتی ساختارمند"""
        summary = self._summarize_nmap(nmap_data, target)

        prompt = f"""Analyze this Nmap scan result for target: {target}

SCAN DATA (verified, from Nmap):
{json.dumps(summary, indent=2)}

Return ONLY this JSON structure:
{{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "attack_surface_summary": "brief text",
  "findings": [
    {{
      "port": 80,
      "service": "http",
      "version": "Apache 2.4.49",
      "risk": "HIGH",
      "reasoning": "Known RCE vulnerability in this version",
      "confidence": "high|medium|low",
      "mitre_technique": "T1190"
    }}
  ],
  "kill_chain_stage": "Reconnaissance|Weaponization|Delivery|Exploitation|Installation|C2|Actions",
  "next_best_action": {{
    "command": "nmap -p 80 --script http-shellshock {target}",
    "reasoning": "Test for specific vulnerability",
    "priority": 1
  }},
  "additional_scans": [
    {{
      "command": "nmap --script=...",
      "purpose": "..."
    }}
  ],
  "pivot_potential": "HIGH|MEDIUM|LOW",
  "notes": "any caveats or uncertainty"
}}"""

        return self._call(self.SYSTEM_PROMPT_ANALYST, prompt)

    def suggest_next_action(
        self, open_ports: list, services: list,
        target: str, rtt_ms: float
    ) -> LLMResponse:
        """پیشنهاد بهترین دستور Nmap بعدی بر اساس نتایج فعلی"""
        prompt = f"""Target: {target}
RTT: {rtt_ms:.1f}ms
Open ports: {open_ports}
Detected services: {services}

Based on ONLY this verified data, suggest the optimal next Nmap scan.
Return ONLY this JSON:
{{
  "recommended_command": "nmap [args] {target}",
  "timing_template": "T0-T5",
  "rationale": "...",
  "evasion_techniques": ["decoy", "fragmentation"],
  "estimated_duration_seconds": 60,
  "expected_findings": "what this scan might reveal"
}}"""
        return self._call(self.SYSTEM_PROMPT_OPTIMIZER, prompt)

    def optimize_scan_parameters(
        self, rtt_ms: float, packet_loss_pct: float,
        target: str, previous_scan_args: str
    ) -> LLMResponse:
        """بهینه‌سازی پارامترهای اسکن برای دور زدن IDS/Firewall"""
        prompt = f"""Network conditions:
- RTT: {rtt_ms:.1f}ms
- Packet loss: {packet_loss_pct:.1f}%
- Previous args used: {previous_scan_args}
- Target: {target}

Recommend optimized Nmap parameters for stealth and accuracy.
Return ONLY this JSON:
{{
  "args": "-sS -T2 --mtu 24 ...",
  "timing_template": "T1",
  "mtu": 1400,
  "decoys": "RND:5",
  "source_port": 443,
  "reasoning": "...",
  "ids_evasion_score": 7
}}"""
        return self._call(self.SYSTEM_PROMPT_OPTIMIZER, prompt)

    def triage_attack_paths(
        self, open_ports: list, vulnerabilities: list, target: str
    ) -> LLMResponse:
        """
        جدید: triage مسیرهای حمله برای اولویت‌بندی red team.
        کمک می‌کند تیم قرمز بهترین نقطه شروع را پیدا کند.
        """
        vuln_summary = [
            {"cve": v.get("cve_id"), "score": v.get("cvss_score"), "service": v.get("service")}
            for v in vulnerabilities[:10]
        ]
        port_summary = [
            {"port": p.get("port"), "service": p.get("service"), "version": p.get("version")}
            for p in open_ports[:15]
        ]

        prompt = f"""Target: {target}
Open ports: {json.dumps(port_summary)}
Top vulnerabilities: {json.dumps(vuln_summary)}

Prioritize attack paths for authorized red team operation.
Return ONLY this JSON:
{{
  "priority_targets": [
    {{
      "port": 445,
      "service": "smb",
      "attack_vector": "MS17-010 EternalBlue",
      "difficulty": "LOW|MEDIUM|HIGH",
      "impact": "CRITICAL|HIGH|MEDIUM|LOW",
      "first_step": "use exploit/windows/smb/ms17_010_eternalblue"
    }}
  ],
  "recommended_order": [445, 22, 80],
  "pivot_opportunities": ["service that enables lateral movement"],
  "quick_wins": ["easiest targets to compromise first"],
  "overall_assessment": "brief summary"
}}"""
        return self._call(self.SYSTEM_PROMPT_TRIAGE, prompt)

    # ─── Helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _summarize_nmap(nmap_data: dict, target: str) -> dict:
        """تبدیل خروجی کامل nmap به خلاصه compact برای LLM"""
        summary: dict = {"target": target, "hosts": []}

        for host, host_data in nmap_data.get("scan", {}).items():
            host_entry: dict = {
                "ip": host,
                "status": host_data.get("status", {}).get("state", "unknown"),
                "os_guess": "",
                "ports": [],
            }
            osmatch = host_data.get("osmatch", [])
            if osmatch:
                host_entry["os_guess"] = osmatch[0].get("name", "")

            for proto in ("tcp", "udp"):
                for port, pdata in host_data.get(proto, {}).items():
                    if pdata.get("state") == "open":
                        host_entry["ports"].append({
                            "port":    int(port),
                            "proto":   proto,
                            "service": pdata.get("name", ""),
                            "version": f"{pdata.get('product','')} {pdata.get('version','')}".strip(),
                            "cpe":     pdata.get("cpe", ""),
                            "scripts": list(pdata.get("script", {}).keys()),
                        })

            summary["hosts"].append(host_entry)

        return summary

