import unittest

from core.entity_utils import (
    extract_entities_enhanced,
    extract_entities_from_text,
    normalize_date_to_iso,
    normalize_phone,
)


class EntityUtilsTests(unittest.TestCase):
    def test_extract_entities_unobfuscates_and_cleans_tokens(self) -> None:
        text = """
        Contact jane [at] example [dot] com, visit hxxps://portal.example.com/login),
        mirror www.example.net, host 8.8.8.8, handle @synint_ops.
        """
        entities = extract_entities_from_text(text)
        self.assertIn("jane@example.com", entities["emails"])
        self.assertIn("https://portal.example.com/login", entities["urls"])
        self.assertIn("portal.example.com", entities["domains"])
        self.assertIn("www.example.net", [url.replace("https://", "") for url in entities["urls"]])
        self.assertIn("example.net", entities["domains"])
        self.assertIn("8.8.8.8", entities["ips"])
        self.assertIn("@synint_ops", entities["handles"])

    def test_phone_normalization_validates_lengths(self) -> None:
        self.assertEqual(normalize_phone("(312) 555-1212"), "+13125551212")
        self.assertEqual(normalize_phone("+44 20 7946 0958"), "+442079460958")
        self.assertEqual(normalize_phone("1234"), "1234")

    def test_date_normalization_accepts_broader_formats(self) -> None:
        self.assertEqual(normalize_date_to_iso("2026/06/13"), "2026-06-13T00:00:00")
        self.assertEqual(normalize_date_to_iso("13 Jun 2026"), "2026-06-13T00:00:00")
        self.assertEqual(normalize_date_to_iso("2026-06-13T14:30:00Z"), "2026-06-13T14:30:00+00:00")

    def test_enhanced_extraction_is_separate_and_redacts_ssn_like_values(self) -> None:
        text = (
            "BTC 1BoatSLRHtKNngkdXEeobR76b53LETtpyT "
            "ETH 0x52908400098527886E0F7030069857D2E4169EE7 "
            "UUID 550e8400-e29b-41d4-a716-446655440000 SSN 123-45-6789"
        )
        legacy = extract_entities_from_text(text)
        enhanced = extract_entities_enhanced(text)
        self.assertNotIn("bitcoin_wallets", legacy)
        self.assertEqual(enhanced["bitcoin_wallets"], ["1BoatSLRHtKNngkdXEeobR76b53LETtpyT"])
        self.assertEqual(
            enhanced["ethereum_wallets"],
            ["0x52908400098527886e0f7030069857d2e4169ee7"],
        )
        self.assertEqual(enhanced["uuids"], ["550e8400-e29b-41d4-a716-446655440000"])
        self.assertEqual(enhanced["ssn_like_redacted"], ["***-**-6789"])
        self.assertNotIn("123-45-6789", repr(enhanced))


if __name__ == "__main__":
    unittest.main()
