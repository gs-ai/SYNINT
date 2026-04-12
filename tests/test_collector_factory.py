import unittest
from unittest.mock import patch

from collectors.factory import collector_capability_matrix, select_collector


class CollectorFactoryTests(unittest.TestCase):
    def test_capability_matrix_shape(self) -> None:
        matrix = collector_capability_matrix()
        self.assertIn("static_http", matrix)
        self.assertIn("camoufox", matrix)
        self.assertIn("capabilities", matrix["static_http"])
        self.assertIn("available", matrix["static_http"])

    def test_fallback_chain_prefers_static_when_optional_unavailable(self) -> None:
        with (
            patch("collectors.camoufox_collector.CamoufoxCollector.is_available", return_value=False),
            patch("collectors.scrapling_collector.ScraplingCollector.is_available", return_value=False),
            patch("collectors.scrapy_collector.ScrapyCollector.is_available", return_value=False),
        ):
            collector, attempts = select_collector(mode="stealth", need_render=True)
            self.assertEqual(collector.engine_name, "static_http")
            self.assertGreaterEqual(len(attempts), 2)
            self.assertEqual(attempts[0]["collector_engine"], "camoufox")
            self.assertEqual(attempts[1]["collector_engine"], "static_http")

    def test_env_preference_can_force_scrapling_first(self) -> None:
        with (
            patch.dict("os.environ", {"SYNINT_PREFER_COLLECTOR": "scrapling"}, clear=False),
            patch("collectors.static_http.StaticHttpCollector.is_available", return_value=True),
            patch("collectors.scrapling_collector.ScraplingCollector.is_available", return_value=True),
        ):
            collector, attempts = select_collector(mode="balanced")
            self.assertEqual(collector.engine_name, "scrapling")
            self.assertEqual(attempts[0]["collector_engine"], "scrapling")


if __name__ == "__main__":
    unittest.main()
