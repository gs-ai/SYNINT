import os
import unittest
from unittest.mock import patch

from agents.social_media_agent import SocialMediaAgent
from collectors.base import CollectionConfig
from collectors.static_http import StaticHttpCollector
from collectors.utils import create_safe_session, normalize_url
from core.redaction import redact_url_credentials, redact_values


class PrivacyGuardTests(unittest.TestCase):
    def test_create_safe_session_ignores_env_network_config_by_default(self) -> None:
        session = create_safe_session()
        self.assertFalse(session.trust_env)

    def test_create_safe_session_can_opt_in_env_network_config(self) -> None:
        session = create_safe_session(allow_env_network_config=True)
        self.assertTrue(session.trust_env)

    def test_normalize_url_strips_embedded_credentials(self) -> None:
        normalized = normalize_url("https://alice:secret@example.com:8443/private")
        self.assertEqual(normalized, "https://example.com:8443/private")

    def test_static_collector_does_not_send_env_cookie_without_opt_in(self) -> None:
        with patch.dict(os.environ, {"SYNINT_CF_CLEARANCE": "sensitive-token"}, clear=False):
            collector = StaticHttpCollector(config=CollectionConfig())
        self.assertNotIn("Cookie", collector._session.headers)

    def test_static_collector_only_sends_env_cookie_on_explicit_opt_in(self) -> None:
        with patch.dict(os.environ, {"SYNINT_CF_CLEARANCE": "sensitive-token"}, clear=False):
            collector = StaticHttpCollector(config=CollectionConfig(allow_env_cookies=True))
        cookie_header = str(collector._session.headers.get("Cookie", ""))
        self.assertIn("cf_clearance=sensitive-token", cookie_header)

    def test_social_media_user_agent_is_not_tool_identifying(self) -> None:
        agent = SocialMediaAgent()
        ua = str(agent._get_session().headers.get("User-Agent", ""))
        self.assertNotIn("SYNINT", ua.upper())

    def test_url_credentials_are_redacted_from_diagnostics(self) -> None:
        message = "proxy failed: https://alice:secret@example.com:8443"
        redacted = redact_url_credentials(message)
        self.assertNotIn("alice:secret", redacted)
        self.assertIn("https://[REDACTED]@example.com:8443", redacted)

    def test_raw_and_encoded_secret_values_are_redacted(self) -> None:
        secret = "token/with reserved"
        message = "raw=token/with reserved encoded=token%2Fwith%20reserved"
        redacted = redact_values(message, [secret])
        self.assertNotIn(secret, redacted)
        self.assertNotIn("token%2Fwith%20reserved", redacted)


if __name__ == "__main__":
    unittest.main()
