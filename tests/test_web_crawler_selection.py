import unittest
from unittest.mock import patch

from agents.web_crawler_agent import WebCrawlerAgent


class _FakeCrawlerCollector:
    engine_name = "fake"

    def crawl(self, target):
        return {"status": "skipped", "reason": "fake skip"}


class WebCrawlerSelectionTests(unittest.TestCase):
    def test_stealth_mode_requests_crawl_capability_without_forcing_render(self) -> None:
        payload = {
            "target": "https://example.com",
            "investigation_context": {"collection_mode": "stealth"},
        }

        with patch(
            "agents.web_crawler_agent.select_collector",
            return_value=(_FakeCrawlerCollector(), [{"collector_engine": "fake", "available": True, "reason": None}]),
        ) as mocked:
            result = WebCrawlerAgent().run(payload)

        self.assertEqual(result.get("status"), "skipped")
        kwargs = mocked.call_args.kwargs
        self.assertTrue(kwargs.get("need_crawl"))
        self.assertFalse(kwargs.get("need_render"))


if __name__ == "__main__":
    unittest.main()
