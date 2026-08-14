import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agents import AGENT_ORDER, OPTIONAL_AGENT_ORDER, available_agent_names
from agents.commoncrawl_ingest_agent import CommonCrawlIngestAgent, html_to_text


class FakeWarcRecord:
    def __init__(self, rec_type: str, payload: bytes) -> None:
        self.rec_type = rec_type
        self._payload = payload

    def content_stream(self) -> io.BytesIO:
        return io.BytesIO(self._payload)


def fake_archive_iterator(_stream):
    return iter(
        [
            FakeWarcRecord("warcinfo", b""),
            FakeWarcRecord(
                "response",
                b"<html><body>Contact jane@example.com or visit https://example.com/page</body></html>",
            ),
        ]
    )


class CommonCrawlAgentAvailabilityTests(unittest.TestCase):
    def test_not_in_default_agent_order_but_is_discoverable(self) -> None:
        self.assertNotIn("CommonCrawlIngestAgent", AGENT_ORDER)
        self.assertIn("CommonCrawlIngestAgent", OPTIONAL_AGENT_ORDER)
        self.assertIn("CommonCrawlIngestAgent", available_agent_names())

    def test_skips_gracefully_when_warcio_missing(self) -> None:
        agent = CommonCrawlIngestAgent()
        if agent.dependency_available():
            self.skipTest("warcio is installed in this environment")
        result = agent.run({"target": "example.com", "investigation_context": {}})
        self.assertEqual(result.get("status"), "skipped")
        self.assertIn("warcio", result.get("reason", ""))


class DefaultAgentSelectionTests(unittest.TestCase):
    def test_default_run_excludes_optional_agents(self) -> None:
        import main

        selected = main._select_agent_names(set(), set())
        self.assertNotIn("CommonCrawlIngestAgent", selected)
        self.assertEqual(list(selected), [n for n in AGENT_ORDER])

    def test_explicit_include_selects_optional_agent(self) -> None:
        import main

        selected = main._select_agent_names({"CommonCrawlIngestAgent"}, set())
        self.assertEqual(list(selected), ["CommonCrawlIngestAgent"])


class CommonCrawlPatternTests(unittest.TestCase):
    def test_build_cdx_pattern_domain(self) -> None:
        self.assertEqual(CommonCrawlIngestAgent.build_cdx_pattern("example.com"), "example.com/*")

    def test_build_cdx_pattern_url_with_path(self) -> None:
        self.assertEqual(
            CommonCrawlIngestAgent.build_cdx_pattern("https://example.com/page"),
            "example.com/page",
        )

    def test_build_cdx_pattern_url_root(self) -> None:
        self.assertEqual(CommonCrawlIngestAgent.build_cdx_pattern("https://example.com/"), "example.com/*")

    def test_build_cdx_pattern_empty(self) -> None:
        self.assertEqual(CommonCrawlIngestAgent.build_cdx_pattern(""), "")


class HtmlToTextTests(unittest.TestCase):
    def test_strips_script_and_style(self) -> None:
        html = "<html><head><style>.a{}</style></head><body><script>x=1</script><p>Hello world</p></body></html>"
        text = html_to_text(html)
        self.assertIn("Hello world", text)
        self.assertNotIn("x=1", text)


class CommonCrawlFullFlowTests(unittest.TestCase):
    def _responses(self):
        collinfo_response = SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: [{"id": "CC-MAIN-2026-21", "name": "Aug 2026"}],
        )
        cdx_line = json.dumps(
            {
                "url": "https://example.com/page",
                "timestamp": "20260601000000",
                "mime": "text/html",
                "status": "200",
                "digest": "ABC123",
                "filename": "crawl-data/CC-MAIN-2026-21/segments/x/warc/file.warc.gz",
                "offset": "1000",
                "length": "500",
            }
        )
        cdx_response = SimpleNamespace(
            status_code=200,
            raise_for_status=lambda: None,
            iter_lines=lambda decode_unicode=True: iter([cdx_line]),
        )
        data_response = SimpleNamespace(
            raise_for_status=lambda: None,
            content=b"fake-warc-gzip-bytes",
        )
        return collinfo_response, cdx_response, data_response

    def test_full_flow_extracts_entities(self) -> None:
        collinfo_response, cdx_response, data_response = self._responses()

        def fake_get(url, *args, **kwargs):
            if "collinfo.json" in url:
                return collinfo_response
            if "index.commoncrawl.org" in url:
                return cdx_response
            if "data.commoncrawl.org" in url:
                return data_response
            raise AssertionError(f"unexpected URL requested: {url}")

        with (
            patch("agents.commoncrawl_ingest_agent._WARCIO_AVAILABLE", True),
            patch("agents.commoncrawl_ingest_agent.ArchiveIterator", fake_archive_iterator),
            patch("agents.commoncrawl_ingest_agent.requests.get", side_effect=fake_get),
        ):
            result = CommonCrawlIngestAgent().run({"target": "example.com", "investigation_context": {}})

        self.assertEqual(result.get("status"), "ok")
        findings = result.get("findings", {})
        self.assertEqual(findings.get("records_found"), 1)
        self.assertEqual(findings.get("records_fetched"), 1)
        self.assertIn("jane@example.com", findings.get("emails", []))
        self.assertIn("https://example.com/page", findings.get("urls", []))
        self.assertEqual(findings.get("index_id"), "CC-MAIN-2026-21")

    def test_env_override_skips_collinfo_lookup(self) -> None:
        _, cdx_response, data_response = self._responses()

        def fake_get(url, *args, **kwargs):
            if "collinfo.json" in url:
                raise AssertionError("collinfo.json should not be queried when index override is set")
            if "index.commoncrawl.org" in url:
                return cdx_response
            if "data.commoncrawl.org" in url:
                return data_response
            raise AssertionError(f"unexpected URL requested: {url}")

        with (
            patch("agents.commoncrawl_ingest_agent._WARCIO_AVAILABLE", True),
            patch("agents.commoncrawl_ingest_agent.ArchiveIterator", fake_archive_iterator),
            patch("agents.commoncrawl_ingest_agent.requests.get", side_effect=fake_get),
            patch.dict("os.environ", {"SYNINT_COMMONCRAWL_INDEX": "CC-MAIN-2026-99"}),
        ):
            result = CommonCrawlIngestAgent().run({"target": "example.com", "investigation_context": {}})

        self.assertEqual(result.get("status"), "ok")
        self.assertEqual(result.get("findings", {}).get("index_id"), "CC-MAIN-2026-99")

    def test_no_captures_found_returns_skipped(self) -> None:
        collinfo_response, _, _ = self._responses()
        empty_cdx_response = SimpleNamespace(
            status_code=200,
            raise_for_status=lambda: None,
            iter_lines=lambda decode_unicode=True: iter([]),
        )

        def fake_get(url, *args, **kwargs):
            if "collinfo.json" in url:
                return collinfo_response
            if "index.commoncrawl.org" in url:
                return empty_cdx_response
            raise AssertionError(f"unexpected URL requested: {url}")

        with (
            patch("agents.commoncrawl_ingest_agent._WARCIO_AVAILABLE", True),
            patch("agents.commoncrawl_ingest_agent.requests.get", side_effect=fake_get),
        ):
            result = CommonCrawlIngestAgent().run({"target": "example.com", "investigation_context": {}})

        self.assertEqual(result.get("status"), "skipped")
        self.assertEqual(result.get("findings", {}).get("cdx_meta", {}).get("status_code"), 200)

    def test_record_length_over_bound_is_rejected(self) -> None:
        agent = CommonCrawlIngestAgent()
        oversized_record = {
            "filename": "crawl-data/CC-MAIN-2026-21/x.warc.gz",
            "offset": "0",
            "length": str(agent.MAX_RANGE_BYTES + 1),
        }
        with patch("agents.commoncrawl_ingest_agent._WARCIO_AVAILABLE", True):
            text, meta = agent._fetch_record_payload(oversized_record)
        self.assertEqual(text, "")
        self.assertIn("exceeds bound", meta.get("error", ""))


if __name__ == "__main__":
    unittest.main()
