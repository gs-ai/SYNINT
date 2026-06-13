import unittest

from core.entity_utils import extract_entities_from_text, normalize_date_to_iso, normalize_phone


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


if __name__ == "__main__":
    unittest.main()
