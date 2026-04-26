#!/usr/bin/env python3
# aegis-scanner/tests/test_integration.py
"""
تست‌های یکپارچگی و واحد Aegis-Scanner v3.
بدون نیاز به Nmap، Ollama، یا اتصال اینترنت — تمام وابستگی‌ها mock شده‌اند.

اجرا:
    python tests/test_integration.py
    python -m pytest tests/test_integration.py -v
"""

import sys
import os
import json
import time
import unittest
import tempfile
from unittest.mock import patch, MagicMock, PropertyMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Mock data ───────────────────────────────────────────────────────────────

MOCK_OPEN_PORTS = [
    {
        "host": "192.168.1.100", "port": 22,   "proto": "tcp",
        "service": "ssh",    "product": "OpenSSH",    "version": "7.4",
        "cpe": "cpe:/a:openbsd:openssh:7.4", "scripts": {},
    },
    {
        "host": "192.168.1.100", "port": 80,   "proto": "tcp",
        "service": "http",   "product": "Apache httpd", "version": "2.4.49",
        "cpe": "cpe:/a:apache:http_server:2.4.49", "scripts": {},
    },
    {
        "host": "192.168.1.100", "port": 443,  "proto": "tcp",
        "service": "https",  "product": "Apache httpd", "version": "2.4.49",
        "cpe": "", "scripts": {},
    },
    {
        "host": "192.168.1.100", "port": 3306, "proto": "tcp",
        "service": "mysql",  "product": "MySQL",       "version": "5.7.32",
        "cpe": "", "scripts": {},
    },
    {
        "host": "192.168.1.100", "port": 6379, "proto": "tcp",
        "service": "redis",  "product": "Redis",       "version": "3.2.12",
        "cpe": "", "scripts": {},
    },
    {
        "host": "192.168.1.100", "port": 23,   "proto": "tcp",
        "service": "telnet", "product": "",            "version": "",
        "cpe": "", "scripts": {},
    },
    {
        "host": "192.168.1.100", "port": 4444, "proto": "tcp",
        "service": "unknown", "product": "",           "version": "",
        "cpe": "", "scripts": {},
    },
]

MOCK_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "published": "2021-10-05",
                "descriptions": [
                    {"lang": "en", "value": "Path traversal and RCE in Apache 2.4.49"}
                ],
                "references": [
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"}
                ],
                "weaknesses": [{"description": [{"value": "CWE-22"}]}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": 9.8,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    }]
                },
            }
        }
    ]
}

MOCK_NMAP_OUTPUT = {
    "scan": {
        "192.168.1.100": {
            "status": {"state": "up"},
            "osmatch": [{"name": "Linux 5.4", "accuracy": "95"}],
            "tcp": {
                "22":   {"state": "open", "name": "ssh",   "product": "OpenSSH",
                         "version": "7.4",   "cpe": "cpe:/a:openbsd:openssh:7.4", "script": {}},
                "80":   {"state": "open", "name": "http",  "product": "Apache httpd",
                         "version": "2.4.49","cpe": "cpe:/a:apache:http_server:2.4.49", "script": {}},
                "3306": {"state": "open", "name": "mysql", "product": "MySQL",
                         "version": "5.7.32","cpe": "", "script": {}},
            },
        }
    },
    "nmap": {"scanstats": {"uphosts": "1", "downhosts": "0"}},
}


# ─── Unit Tests ───────────────────────────────────────────────────────────────

class TestNmapController(unittest.TestCase):

    def setUp(self):
        from config.settings import NmapSettings
        self.settings = NmapSettings()

    def test_validate_target_valid_ip(self):
        from core.nmap_controller import NmapController
        with patch("nmap.PortScanner"):
            ctrl = NmapController(self.settings)
        valid, result = ctrl.validate_target("192.168.1.1")
        self.assertTrue(valid)
        self.assertEqual(result, "192.168.1.1")

    def test_validate_target_cidr(self):
        from core.nmap_controller import NmapController
        with patch("nmap.PortScanner"):
            ctrl = NmapController(self.settings)
        valid, result = ctrl.validate_target("10.0.0.0/24")
        self.assertTrue(valid)

    def test_validate_target_hostname(self):
        from core.nmap_controller import NmapController
        with patch("nmap.PortScanner"):
            ctrl = NmapController(self.settings)
        valid, result = ctrl.validate_target("example.com")
        self.assertTrue(valid)

    def test_validate_target_injection(self):
        from core.nmap_controller import NmapController
        with patch("nmap.PortScanner"):
            ctrl = NmapController(self.settings)
        for payload in ["192.168.1.1; rm -rf /", "target & id", "host|cat /etc/passwd"]:
            valid, _ = ctrl.validate_target(payload)
            self.assertFalse(valid, f"Should reject injection: {payload}")

    def test_validate_target_empty(self):
        from core.nmap_controller import NmapController
        with patch("nmap.PortScanner"):
            ctrl = NmapController(self.settings)
        valid, msg = ctrl.validate_target("")
        self.assertFalse(valid)
        self.assertIn("empty", msg.lower())

    def test_validate_target_invalid_ip(self):
        from core.nmap_controller import NmapController
        with patch("nmap.PortScanner"):
            ctrl = NmapController(self.settings)
        valid, _ = ctrl.validate_target("999.999.999.999")
        self.assertFalse(valid)

    def test_validate_target_ipv6_notation(self):
        from core.nmap_controller import NmapController
        with patch("nmap.PortScanner"):
            ctrl = NmapController(self.settings)
        # dash notation
        valid, _ = ctrl.validate_target("192.168.1.1-50")
        self.assertTrue(valid)


class TestPortAnalyzer(unittest.TestCase):

    def setUp(self):
        from modules.port_analyzer import PortAnalyzer
        self.analyzer = PortAnalyzer()

    def test_empty_ports(self):
        result = self.analyzer.analyze([])
        self.assertEqual(result["total_open"], 0)

    def test_telnet_is_critical(self):
        ports = [{"host": "1.2.3.4", "port": 23, "proto": "tcp",
                  "service": "telnet", "product": "", "version": "", "cpe": "", "scripts": {}}]
        result = self.analyzer.analyze(ports)
        findings = result["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["risk_level"], "CRITICAL")

    def test_suspicious_port_4444(self):
        ports = [{"host": "1.2.3.4", "port": 4444, "proto": "tcp",
                  "service": "unknown", "product": "", "version": "", "cpe": "", "scripts": {}}]
        result = self.analyzer.analyze(ports)
        findings = result["findings"]
        self.assertEqual(findings[0]["risk_level"], "CRITICAL")
        reasons = " ".join(findings[0]["risk_reasons"])
        self.assertIn("backdoor", reasons.lower())

    def test_https_is_low_risk(self):
        ports = [{"host": "1.2.3.4", "port": 443, "proto": "tcp",
                  "service": "https", "product": "nginx", "version": "1.20",
                  "cpe": "", "scripts": {}}]
        result = self.analyzer.analyze(ports)
        self.assertEqual(result["findings"][0]["risk_level"], "LOW")

    def test_redis_is_high_risk(self):
        ports = [{"host": "1.2.3.4", "port": 6379, "proto": "tcp",
                  "service": "redis", "product": "Redis", "version": "3.2",
                  "cpe": "", "scripts": {}}]
        result = self.analyzer.analyze(ports)
        self.assertEqual(result["findings"][0]["risk_level"], "HIGH")

    def test_script_vuln_escalates_risk(self):
        ports = [{"host": "1.2.3.4", "port": 80, "proto": "tcp",
                  "service": "http", "product": "Apache", "version": "2.4",
                  "cpe": "", "scripts": {"http-shellshock": "VULNERABLE: CVE-2014-6271"}}]
        result = self.analyzer.analyze(ports)
        self.assertEqual(result["findings"][0]["risk_level"], "CRITICAL")

    def test_attack_surface_score_calculation(self):
        result = self.analyzer.analyze(MOCK_OPEN_PORTS)
        score = result["attack_surface_score"]
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 10)

    def test_exposed_databases_detected(self):
        result = self.analyzer.analyze(MOCK_OPEN_PORTS)
        dbs = result["exposed_databases"]
        services = [d["service"] for d in dbs]
        self.assertIn("mysql", services)
        self.assertIn("redis", services)

    def test_remote_access_detected(self):
        result = self.analyzer.analyze(MOCK_OPEN_PORTS)
        ra = result["exposed_remote_access"]
        services = [r["service"] for r in ra]
        self.assertIn("ssh", services)
        self.assertIn("telnet", services)

    def test_full_mock_analysis(self):
        result = self.analyzer.analyze(MOCK_OPEN_PORTS)
        self.assertEqual(result["total_open"], len(MOCK_OPEN_PORTS))
        self.assertGreater(result["critical_count"], 0)
        self.assertIsInstance(result["summary"], str)


class TestVulnEngine(unittest.TestCase):

    def setUp(self):
        from modules.vuln_engine import VulnEngine
        self.engine = VulnEngine()

    def test_score_to_severity_critical(self):
        from modules.vuln_engine import VulnEngine
        self.assertEqual(VulnEngine._score_to_severity(9.8), "CRITICAL")
        self.assertEqual(VulnEngine._score_to_severity(9.0), "CRITICAL")

    def test_score_to_severity_high(self):
        from modules.vuln_engine import VulnEngine
        self.assertEqual(VulnEngine._score_to_severity(7.5), "HIGH")
        self.assertEqual(VulnEngine._score_to_severity(7.0), "HIGH")

    def test_score_to_severity_medium(self):
        from modules.vuln_engine import VulnEngine
        self.assertEqual(VulnEngine._score_to_severity(5.0), "MEDIUM")

    def test_score_to_severity_low(self):
        from modules.vuln_engine import VulnEngine
        self.assertEqual(VulnEngine._score_to_severity(2.0), "LOW")

    def test_score_to_severity_info(self):
        from modules.vuln_engine import VulnEngine
        self.assertEqual(VulnEngine._score_to_severity(0.0), "INFO")

    def test_parse_nvd_response(self):
        from modules.vuln_engine import VulnEngine
        results = VulnEngine._parse_nvd_response(MOCK_NVD_RESPONSE)
        self.assertEqual(len(results), 1)
        cve = results[0]
        self.assertEqual(cve["cve_id"], "CVE-2021-41773")
        self.assertAlmostEqual(cve["cvss_score"], 9.8)
        self.assertEqual(cve["severity"], "CRITICAL")
        self.assertEqual(cve["cvss_version"], "3.1")

    def test_parse_nvd_empty_response(self):
        from modules.vuln_engine import VulnEngine
        results = VulnEngine._parse_nvd_response({"vulnerabilities": []})
        self.assertEqual(results, [])

    def test_map_vulnerabilities_with_mock_api(self):
        with patch("requests.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = MOCK_NVD_RESPONSE
            mock_get.return_value.raise_for_status = MagicMock()

            from modules.vuln_engine import VulnEngine
            engine = VulnEngine()
            engine.cache._data = {}  # empty cache
            engine._last_req = 0

            ports = [{"host": "1.2.3.4", "port": 80, "service": "http",
                      "product": "Apache httpd", "version": "2.4.49",
                      "cpe": "cpe:/a:apache:http_server:2.4.49"}]
            vulns = engine.map_vulnerabilities(ports)
            self.assertIsInstance(vulns, list)

    def test_map_vulnerabilities_sorted_by_cvss(self):
        with patch.object(self.engine, "_query_by_cpe", return_value=[
            {"cve_id": "CVE-2021-0001", "cvss_score": 7.5, "severity": "HIGH",
             "description": "test", "cvss_vector": "", "cvss_version": "3.1",
             "published": "2021-01-01", "weaknesses": [], "references": []},
            {"cve_id": "CVE-2021-0002", "cvss_score": 9.8, "severity": "CRITICAL",
             "description": "test", "cvss_vector": "", "cvss_version": "3.1",
             "published": "2021-01-01", "weaknesses": [], "references": []},
        ]):
            ports = [{"host": "1.2.3.4", "port": 80, "service": "http",
                      "product": "Apache", "version": "2.4.49",
                      "cpe": "cpe:/a:apache:http_server:2.4.49"}]
            vulns = self.engine.map_vulnerabilities(ports)
            if len(vulns) >= 2:
                self.assertGreaterEqual(vulns[0]["cvss_score"], vulns[1]["cvss_score"])

    def test_cve_cache_set_and_get(self):
        from modules.vuln_engine import CVECache
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            cache = CVECache(f.name)
        cache.set("test_key", [{"cve_id": "CVE-2021-12345"}])
        result = cache.get("test_key")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["cve_id"], "CVE-2021-12345")

    def test_cve_cache_miss(self):
        from modules.vuln_engine import CVECache
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            cache = CVECache(f.name)
        result = cache.get("nonexistent_key_xyz")
        self.assertIsNone(result)


class TestExploitSuggestor(unittest.TestCase):

    def setUp(self):
        from modules.exploit_suggestor import ExploitSuggestor
        self.suggestor = ExploitSuggestor()

    def test_known_cve_eternalblue(self):
        vulns = [{"cve_id": "CVE-2017-0144", "cvss_score": 9.3,
                  "severity": "CRITICAL", "host": "1.2.3.4",
                  "port": 445, "service": "smb"}]
        suggestions = self.suggestor.suggest(vulns)
        self.assertEqual(len(suggestions), 1)
        s = suggestions[0]
        self.assertEqual(s["cve_id"], "CVE-2017-0144")
        self.assertIn("ms17_010", s["metasploit_module"])
        self.assertTrue(s["verified"])

    def test_known_cve_log4shell(self):
        vulns = [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0,
                  "severity": "CRITICAL", "host": "1.2.3.4",
                  "port": 8080, "service": "http"}]
        suggestions = self.suggestor.suggest(vulns)
        self.assertEqual(len(suggestions), 1)
        self.assertIn("log4shell", suggestions[0]["metasploit_module"])

    def test_low_cvss_skipped(self):
        vulns = [{"cve_id": "CVE-2021-99999", "cvss_score": 3.5,
                  "severity": "LOW", "host": "1.2.3.4",
                  "port": 80, "service": "http"}]
        suggestions = self.suggestor.suggest(vulns)
        self.assertEqual(len(suggestions), 0)

    def test_no_duplicate_cves(self):
        vulns = [
            {"cve_id": "CVE-2017-0144", "cvss_score": 9.3,
             "severity": "CRITICAL", "host": "1.2.3.4", "port": 445, "service": "smb"},
            {"cve_id": "CVE-2017-0144", "cvss_score": 9.3,
             "severity": "CRITICAL", "host": "1.2.3.4", "port": 445, "service": "smb"},
        ]
        suggestions = self.suggestor.suggest(vulns)
        cve_ids = [s["cve_id"] for s in suggestions]
        self.assertEqual(len(cve_ids), len(set(cve_ids)))

    def test_verified_sorted_first(self):
        from modules.exploit_suggestor import ExploitSuggestor
        vulns = [
            {"cve_id": "CVE-2017-0144", "cvss_score": 9.3, "severity": "CRITICAL",
             "host": "h", "port": 445, "service": "smb"},
            {"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "severity": "CRITICAL",
             "host": "h", "port": 8080, "service": "http"},
        ]
        suggestor = ExploitSuggestor()
        suggestor._searchsploit_available = False
        suggestions = suggestor.suggest(vulns)
        for s in suggestions:
            self.assertTrue(s.get("verified"))


class TestSettingsValidation(unittest.TestCase):

    def test_from_file_valid_json(self):
        from config.settings import AegisSettings
        data = {
            "llm": {"model": "llama3", "timeout": 60, "enabled": True},
            "nmap": {"privileged": False, "max_retries": 3},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            fname = f.name
        settings = AegisSettings.from_file(fname)
        self.assertEqual(settings.llm.model, "llama3")
        self.assertEqual(settings.llm.timeout, 60)
        self.assertEqual(settings.nmap.max_retries, 3)

    def test_from_file_type_coercion(self):
        from config.settings import AegisSettings
        data = {"llm": {"timeout": "90", "temperature": "0.2"}}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            fname = f.name
        settings = AegisSettings.from_file(fname)
        self.assertIsInstance(settings.llm.timeout, int)
        self.assertIsInstance(settings.llm.temperature, float)

    def test_from_file_invalid_type_ignored(self):
        from config.settings import AegisSettings
        data = {"llm": {"timeout": "NOT_A_NUMBER"}}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            fname = f.name
        # نباید crash کند — مقدار پیش‌فرض حفظ می‌شود
        settings = AegisSettings.from_file(fname)
        self.assertEqual(settings.llm.timeout, 120)  # default

    def test_from_file_nonexistent(self):
        from config.settings import AegisSettings
        settings = AegisSettings.from_file("/nonexistent/path/config.json")
        self.assertIsNotNone(settings)


class TestLLMConnector(unittest.TestCase):

    def setUp(self):
        from config.settings import LLMSettings
        from core.llm_connector import LLMConnector
        settings = LLMSettings()
        settings.enabled = True
        self.connector = LLMConnector(settings)

    def test_safe_parse_json_valid(self):
        from core.llm_connector import LLMConnector
        result = LLMConnector._safe_parse_json('{"key": "value"}')
        self.assertEqual(result, {"key": "value"})

    def test_safe_parse_json_with_markdown_fence(self):
        from core.llm_connector import LLMConnector
        text = '```json\n{"key": "value"}\n```'
        result = LLMConnector._safe_parse_json(text)
        self.assertEqual(result, {"key": "value"})

    def test_safe_parse_json_embedded(self):
        from core.llm_connector import LLMConnector
        text = 'Here is the result: {"key": "value"} end'
        result = LLMConnector._safe_parse_json(text)
        self.assertEqual(result, {"key": "value"})

    def test_safe_parse_json_invalid(self):
        from core.llm_connector import LLMConnector
        result = LLMConnector._safe_parse_json("not valid json at all")
        self.assertIsNone(result)

    def test_check_availability_no_server(self):
        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("Connection refused")
            result = self.connector.check_availability()
            self.assertFalse(result)

    def test_check_availability_model_missing(self):
        with patch("requests.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = {
                "models": [{"name": "mistral"}, {"name": "phi3"}]
            }
            result = self.connector.check_availability()
            self.assertFalse(result)

    def test_summarize_nmap(self):
        from core.llm_connector import LLMConnector
        summary = LLMConnector._summarize_nmap(MOCK_NMAP_OUTPUT, "192.168.1.100")
        self.assertEqual(summary["target"], "192.168.1.100")
        self.assertEqual(len(summary["hosts"]), 1)
        host = summary["hosts"][0]
        self.assertEqual(host["ip"], "192.168.1.100")
        self.assertGreater(len(host["ports"]), 0)


class TestRealtimeAnalyzer(unittest.TestCase):

    def setUp(self):
        from modules.realtime_analyzer import RealtimeAnalyzer
        self.rta = RealtimeAnalyzer()

    def test_guess_os_linux(self):
        os_name = self.rta._guess_os(ttl=64, window=29200, mss=1460)
        self.assertIn("Linux", os_name)

    def test_guess_os_windows(self):
        os_name = self.rta._guess_os(ttl=128, window=65535, mss=1460)
        self.assertIn("Windows", os_name)

    def test_guess_os_unknown(self):
        os_name = self.rta._guess_os(ttl=0, window=0, mss=0)
        self.assertEqual(os_name, "Unknown")

    def test_analyze_samples_throttling_detection(self):
        # RTT رفته‌رفته افزایش می‌یابد → throttling
        samples = [10, 10, 11, 30, 50, 80, 120, 200]
        behavior = self.rta._analyze_samples("1.2.3.4", samples, 0, [], None)
        self.assertTrue(behavior.throttling_detected)

    def test_analyze_samples_rst_injection(self):
        samples = [20, 22, 21]
        behavior = self.rta._analyze_samples("1.2.3.4", samples, 3, [], None)
        self.assertEqual(behavior.rst_injections, 3)
        self.assertTrue(behavior.middlebox_detected)

    def test_adapt_scan_args_timing(self):
        from modules.realtime_analyzer import NetworkBehavior
        behavior = NetworkBehavior(
            target="1.2.3.4", samples=10,
            avg_rtt_ms=300.0, min_rtt_ms=280.0, max_rtt_ms=320.0,
            std_rtt_ms=10.0, packet_loss_pct=0.0,
            rst_injections=0, throttling_detected=False,
            mtu_issues=False, ttl_variance=0,
            recommended_timing="T2", recommended_mtu=1400,
            middlebox_detected=False,
        )
        adaptation = self.rta.adapt_scan_args("-sV -T3 -sC", behavior)
        self.assertIn("T2", adaptation.adapted_args)
        self.assertNotIn("T3", adaptation.adapted_args)

    def test_adapt_scan_args_mtu(self):
        from modules.realtime_analyzer import NetworkBehavior
        behavior = NetworkBehavior(
            target="1.2.3.4", samples=10,
            avg_rtt_ms=50.0, min_rtt_ms=40.0, max_rtt_ms=60.0,
            std_rtt_ms=5.0, packet_loss_pct=0.0,
            rst_injections=0, throttling_detected=False,
            mtu_issues=True, ttl_variance=0,
            recommended_timing="T3", recommended_mtu=1280,
            middlebox_detected=False,
        )
        adaptation = self.rta.adapt_scan_args("-sV -T3", behavior)
        self.assertIn("--mtu 1280", adaptation.adapted_args)

    def test_adapt_scan_throttling_rate_limit(self):
        from modules.realtime_analyzer import NetworkBehavior
        behavior = NetworkBehavior(
            target="1.2.3.4", samples=10,
            avg_rtt_ms=50.0, min_rtt_ms=40.0, max_rtt_ms=200.0,
            std_rtt_ms=20.0, packet_loss_pct=0.0,
            rst_injections=0, throttling_detected=True,
            mtu_issues=False, ttl_variance=0,
            recommended_timing="T1", recommended_mtu=1500,
            middlebox_detected=False,
        )
        adaptation = self.rta.adapt_scan_args("-sV -T3", behavior)
        self.assertIn("--max-rate", adaptation.adapted_args)


class TestConstants(unittest.TestCase):

    def test_nse_scripts_non_empty(self):
        from config.constants import (
            NSE_SCRIPTS_AUTH, NSE_SCRIPTS_DISCOVERY, NSE_SCRIPTS_VULN
        )
        self.assertGreater(len(NSE_SCRIPTS_AUTH), 5)
        self.assertGreater(len(NSE_SCRIPTS_DISCOVERY), 5)
        self.assertGreater(len(NSE_SCRIPTS_VULN), 5)

    def test_scan_levels_exist(self):
        from config.constants import NMAP_SCAN_LEVELS
        for level in range(1, 6):
            self.assertIn(level, NMAP_SCAN_LEVELS)
            self.assertIn("args", NMAP_SCAN_LEVELS[level])
            self.assertIn("label", NMAP_SCAN_LEVELS[level])

    def test_level_5_has_full_ports(self):
        from config.constants import NMAP_SCAN_LEVELS
        args = NMAP_SCAN_LEVELS[5]["args"]
        self.assertIn("-p-", args)

    def test_vuln_scripts_in_level_4(self):
        from config.constants import NMAP_SCAN_LEVELS, NSE_SCRIPTS_VULN
        args = NMAP_SCAN_LEVELS[4]["args"]
        # حداقل یکی از اسکریپت‌های vuln باید در args باشه
        self.assertIn("--script=", args)
        self.assertTrue(any(s in args for s in NSE_SCRIPTS_VULN[:3]))

    def test_suspicious_ports_contains_common_backdoors(self):
        from modules.port_analyzer import SUSPICIOUS_PORTS
        for port in [4444, 1337, 31337]:
            self.assertIn(port, SUSPICIOUS_PORTS)

    def test_standard_ports_comprehensive(self):
        from modules.port_analyzer import STANDARD_PORTS
        critical_ports = [22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 6379]
        for port in critical_ports:
            self.assertIn(port, STANDARD_PORTS, f"Port {port} missing from STANDARD_PORTS")

    def test_cvss_thresholds_ordered(self):
        from config.constants import CVSS_CRITICAL, CVSS_HIGH, CVSS_MEDIUM, CVSS_LOW
        self.assertGreater(CVSS_CRITICAL, CVSS_HIGH)
        self.assertGreater(CVSS_HIGH, CVSS_MEDIUM)
        self.assertGreater(CVSS_MEDIUM, CVSS_LOW)


class TestIntegrationEngine(unittest.TestCase):
    """تست‌های یکپارچگی engine — تمام I/O به mock تبدیل شده"""

    def _build_mock_scan_result(self):
        from core.nmap_controller import ScanResult
        return ScanResult(
            target="192.168.1.100",
            scan_args="-sV -sC",
            raw_data=MOCK_NMAP_OUTPUT,
            hosts_up=1,
            hosts_down=0,
            open_ports=MOCK_OPEN_PORTS,
            scan_start=time.time() - 10,
            scan_end=time.time(),
            rtt_ms=15.0,
            packet_loss_pct=0.0,
        )

    @patch("nmap.PortScanner")
    def test_full_scan_completes(self, mock_nmap):
        from config.settings import AegisSettings
        from core.aegis_engine import AegisEngine

        settings = AegisSettings()
        settings.llm.enabled = False

        engine = AegisEngine(settings)
        mock_scan = self._build_mock_scan_result()

        with patch.object(engine.nmap, "measure_rtt", return_value=(15.0, 0.0)), \
             patch.object(engine.nmap, "run_scan",    return_value=mock_scan), \
             patch.object(engine.knowledge_base, "save_session"), \
             patch.object(engine.json_reporter,  "generate",  return_value="/tmp/test.json"), \
             patch.object(engine.md_reporter,    "generate",  return_value="/tmp/test.md"):

            session = engine.run_full_scan(
                target="192.168.1.100",
                ports="1-1024",
                scan_level=2,
                skip_honeypot_check=True,
                skip_osint=True,
                skip_realtime=True,
            )

        self.assertIsNotNone(session)
        self.assertEqual(session.target, "192.168.1.100")
        self.assertIn("nmap_scan", session.phases_completed)
        self.assertIn("port_analysis", session.phases_completed)
        self.assertEqual(len(session.errors), 0)

    @patch("nmap.PortScanner")
    def test_scan_handles_nmap_failure(self, mock_nmap):
        from config.settings import AegisSettings
        from core.aegis_engine import AegisEngine
        from core.nmap_controller import ScanResult

        settings = AegisSettings()
        settings.llm.enabled = False
        engine = AegisEngine(settings)

        failed_scan = ScanResult(
            target="192.168.1.100", scan_args="-sV",
            raw_data={}, hosts_up=0, hosts_down=1,
            open_ports=[], scan_start=time.time(), scan_end=time.time(),
            rtt_ms=0, packet_loss_pct=100.0, error="Connection timeout",
        )

        with patch.object(engine.nmap, "measure_rtt", return_value=(999.0, 100.0)), \
             patch.object(engine.nmap, "run_scan",    return_value=failed_scan), \
             patch.object(engine.knowledge_base, "save_session"), \
             patch.object(engine.json_reporter,  "generate", return_value=""), \
             patch.object(engine.md_reporter,    "generate", return_value=""):

            session = engine.run_full_scan(
                "192.168.1.100",
                skip_honeypot_check=True,
                skip_osint=True,
                skip_realtime=True,
            )

        self.assertGreater(len(session.errors), 0)
        self.assertIn("Scan failed", session.errors[0])

    @patch("nmap.PortScanner")
    def test_honeypot_detection_aborts_scan(self, mock_nmap):
        from config.settings import AegisSettings
        from core.aegis_engine import AegisEngine
        from modules.honeypot_detector import HoneypotResult

        settings = AegisSettings()
        settings.llm.enabled = False
        engine = AegisEngine(settings)
        mock_scan = self._build_mock_scan_result()

        fake_hp = HoneypotResult(
            target="192.168.1.100",
            is_honeypot=True,
            confidence=0.92,
            verdict="HIGH_CONFIDENCE_HONEYPOT",
            indicators=[],
            score=9,
        )

        with patch.object(engine.nmap, "measure_rtt", return_value=(15.0, 0.0)), \
             patch.object(engine.nmap, "run_scan",    return_value=mock_scan), \
             patch.object(engine.honeypot_det, "analyze", return_value=fake_hp), \
             patch.object(engine.knowledge_base, "save_session"), \
             patch.object(engine.json_reporter,  "generate", return_value=""), \
             patch.object(engine.md_reporter,    "generate", return_value=""):

            session = engine.run_full_scan(
                "192.168.1.100",
                skip_osint=True,
                skip_realtime=True,
            )

        self.assertTrue(any("HONEYPOT" in e for e in session.errors))
        self.assertNotIn("nmap_scan", session.phases_completed)

    @patch("nmap.PortScanner")
    def test_health_check_returns_dict(self, mock_nmap):
        from config.settings import AegisSettings
        from core.aegis_engine import AegisEngine

        settings = AegisSettings()
        engine = AegisEngine(settings)

        with patch.object(engine.llm, "check_availability", return_value=False), \
             patch.object(engine.knowledge_base, "is_healthy", return_value=True):
            health = engine.health_check()

        self.assertIn("nmap", health)
        self.assertIn("llm", health)
        self.assertIn("knowledge_base", health)
        self.assertIsInstance(health, dict)


class TestReporting(unittest.TestCase):
    """تست تولید گزارش"""

    def _make_mock_session(self):
        """یک session ساده برای تست گزارش"""
        from core.nmap_controller import ScanResult

        class MockSession:
            session_id = "test001"
            target = "192.168.1.100"
            ports = "1-1024"
            scan_level = 2
            duration = 30.0
            errors = []
            phases_completed = ["nmap_scan", "port_analysis"]
            report_paths = {}
            scan_result = ScanResult(
                target="192.168.1.100", scan_args="-sV",
                raw_data=MOCK_NMAP_OUTPUT, hosts_up=1, hosts_down=0,
                open_ports=MOCK_OPEN_PORTS,
                scan_start=time.time() - 30, scan_end=time.time(),
                rtt_ms=15.0, packet_loss_pct=0.0,
            )
            port_analysis = None
            vulnerabilities = []
            exploit_suggestions = []
            ai_analysis = {}
            ai_triage = {}
            optimized_params = {}
            next_best_action = {}
            honeypot_analysis = {}
            evasion_profile = {}
            protocol_inspection = {}
            attack_chain = {}
            opsec_report = {}
            lateral_movement = {}
            realtime_analysis = {}
            osint_data = {}

            @property
            def settings(self):
                from config.settings import AegisSettings
                return AegisSettings()

        return MockSession()

    def test_json_reporter_generates_valid_json(self):
        from reporting.json_reporter import JSONReporter
        from config.settings import ReportSettings

        with tempfile.TemporaryDirectory() as tmpdir:
            settings = ReportSettings(output_dir=tmpdir)
            reporter = JSONReporter(settings)
            session = self._make_mock_session()
            path = reporter.generate(session)

            self.assertTrue(os.path.exists(path))
            with open(path) as f:
                data = json.load(f)

            self.assertIn("meta", data)
            self.assertIn("scan", data)
            self.assertIn("realtime_analysis", data)
            self.assertIn("osint_data", data)
            self.assertIn("ai_triage", data)
            self.assertEqual(data["meta"]["session_id"], "test001")

    def test_markdown_reporter_generates_file(self):
        from reporting.markdown_reporter import MarkdownReporter
        from config.settings import ReportSettings

        with tempfile.TemporaryDirectory() as tmpdir:
            settings = ReportSettings(output_dir=tmpdir)
            reporter = MarkdownReporter(settings)
            session = self._make_mock_session()
            path = reporter.generate(session)

            self.assertTrue(os.path.exists(path))
            with open(path) as f:
                content = f.read()

            self.assertIn("Aegis-Scanner", content)
            self.assertIn("test001", content)
            self.assertIn("192.168.1.100", content)


# ─── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    loader  = unittest.TestLoader()
    suite   = unittest.TestSuite()

    test_classes = [
        TestNmapController,
        TestPortAnalyzer,
        TestVulnEngine,
        TestExploitSuggestor,
        TestSettingsValidation,
        TestLLMConnector,
        TestRealtimeAnalyzer,
        TestConstants,
        TestIntegrationEngine,
        TestReporting,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
