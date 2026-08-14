import os
import unittest
from unittest.mock import patch

import requests

from agents import AGENT_ORDER, OPTIONAL_AGENT_ORDER, available_agent_names
from agents.machine_discovery_agent import DiscoveryBudget, MachineDiscoveryAgent, is_public_ip
import main


class MachineDiscoveryAgentTests(unittest.TestCase):
    def test_experimental_agent_is_explicit_only(self) -> None:
        self.assertNotIn("MachineDiscoveryAgent", AGENT_ORDER)
        self.assertIn("MachineDiscoveryAgent", OPTIONAL_AGENT_ORDER)
        self.assertIn("MachineDiscoveryAgent", available_agent_names())
        self.assertNotIn("MachineDiscoveryAgent", main._select_agent_names(set(), set()))
        self.assertEqual(
            list(main._select_agent_names({"MachineDiscoveryAgent"}, set())),
            ["MachineDiscoveryAgent"],
        )

    def test_missing_api_key_degrades_gracefully(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            result = MachineDiscoveryAgent().run("example.com")
        self.assertEqual(result["status"], "skipped")
        self.assertIn("SHODAN_API_KEY", result["reason"])

    def test_private_and_metadata_service_addresses_are_blocked(self) -> None:
        for value in (
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "::1",
            "fc00::1",
        ):
            self.assertFalse(is_public_ip(value), value)
            self.assertIsNone(MachineDiscoveryAgent._scope_for_target(value))
        self.assertTrue(is_public_ip("8.8.8.8"))

    def test_budget_is_hard_capped(self) -> None:
        env = {
            "SYNINT_MACHINE_MAX_REQUESTS": "999",
            "SYNINT_MACHINE_MAX_PAGES": "999",
            "SYNINT_MACHINE_MAX_RECORDS": "999",
            "SYNINT_MACHINE_MAX_RUNTIME": "999",
        }
        with patch.dict(os.environ, env, clear=True):
            budget = DiscoveryBudget.from_environment()
        self.assertEqual(budget.max_requests, 10)
        self.assertEqual(budget.max_pages, 5)
        self.assertEqual(budget.max_records, 100)
        self.assertEqual(budget.max_runtime_seconds, 120)

    def test_camera_alpr_flir_results_are_read_only_and_redacted(self) -> None:
        plate = "ABC1234"
        responses = {
            "camera": {
                "total": 1,
                "matches": [
                    {
                        "ip_str": "8.8.8.8",
                        "port": 443,
                        "product": "Public Camera",
                        "http": {"title": "Camera"},
                        "location": {"country_name": "US", "city": "Chicago"},
                    }
                ],
            },
            "alpr": {
                "total": 2,
                "matches": [
                    {
                        "ip_str": "1.1.1.1",
                        "port": 443,
                        "product": "OpenALPR",
                        "http": {"title": "ALPR"},
                        "data": {'license_plate': plate, "cameraId": 3},
                    },
                    {"ip_str": "10.0.0.5", "port": 80, "product": "blocked"},
                ],
            },
            "flir": {
                "total": 1,
                "matches": [
                    {
                        "ip_str": "9.9.9.9",
                        "port": 80,
                        "product": "Teledyne FLIR",
                        "http": {"title": "FLIR thermal camera"},
                    }
                ],
            },
        }

        def fake_search(_self, *, api_key, query, page, timeout):
            del api_key, page, timeout
            if "ALPR" in query:
                return responses["alpr"]
            if "FLIR" in query:
                return responses["flir"]
            return responses["camera"]

        env = {
            "SHODAN_API_KEY": "test-secret",
            "SYNINT_MACHINE_MAX_REQUESTS": "3",
            "SYNINT_MACHINE_MAX_PAGES": "3",
            "SYNINT_MACHINE_MAX_RECORDS": "10",
        }
        with patch.dict(os.environ, env, clear=True), patch.object(
            MachineDiscoveryAgent, "_search_page", fake_search
        ):
            result = MachineDiscoveryAgent().run("example.com")

        self.assertEqual(result["status"], "ok")
        findings = result["findings"]
        self.assertEqual(findings["classification"], "EXPERIMENTAL")
        self.assertEqual(findings["counts"]["camera"], 1)
        self.assertEqual(findings["counts"]["alpr"], 1)
        self.assertEqual(findings["counts"]["flir"], 1)
        self.assertNotIn(plate, repr(result))
        alpr = next(item for item in findings["sources"] if "alpr" in item["service_types"])
        self.assertTrue(alpr["plate_data_indicator"])
        self.assertTrue(alpr["plate_values_redacted"])
        self.assertTrue(findings["safety"]["plate_redaction_before_persistence"])
        self.assertEqual(findings["safety"]["direct_device_requests"], 0)
        self.assertEqual(findings["safety"]["device_control_operations"], [])
        self.assertLessEqual(findings["budget"]["requests"]["spent"], 3)
        self.assertFalse(any(item["ip"].startswith("10.") for item in findings["sources"]))
        self.assertNotIn("test-secret", repr(result))

    def test_private_target_is_rejected_before_search(self) -> None:
        with patch.dict(os.environ, {"SHODAN_API_KEY": "test"}, clear=True), patch.object(
            MachineDiscoveryAgent, "_search_page"
        ) as search:
            result = MachineDiscoveryAgent().run("http://169.254.169.254/latest/meta-data")
        self.assertEqual(result["status"], "skipped")
        search.assert_not_called()

    def test_service_unavailable_fails_gracefully(self) -> None:
        with patch.dict(os.environ, {"SHODAN_API_KEY": "test"}, clear=True), patch.object(
            MachineDiscoveryAgent,
            "_search_page",
            side_effect=ValueError("offline"),
        ):
            result = MachineDiscoveryAgent().run("example.com")
        self.assertEqual(result["status"], "error")
        self.assertIn("unavailable", result["error"])

    def test_api_key_is_redacted_from_request_errors(self) -> None:
        secret = "audit-key-with-reserved/value"
        error = requests.HTTPError(
            f"401 Client Error for url: https://api.shodan.io/search?key={secret}"
        )
        with patch.dict(os.environ, {"SHODAN_API_KEY": secret}, clear=True), patch.object(
            MachineDiscoveryAgent,
            "_search_page",
            side_effect=error,
        ):
            result = MachineDiscoveryAgent().run("example.com")

        self.assertEqual(result["status"], "error")
        self.assertNotIn(secret, repr(result))
        self.assertIn("[REDACTED]", result["error"])


if __name__ == "__main__":
    unittest.main()
