import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from converter.model import Behavior, BuildContext
from converter.providers import process_provider


class ProvidersTest(unittest.TestCase):
    def test_normalization_contains_payload_but_no_url_or_path(self):
        context = BuildContext({}, {"A"})
        with patch("converter.net.fetch_text", return_value="payload:\n- example.com\n"):
            result = process_provider("A", {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/a"}, context)
        provider = result.providers[0]
        self.assertEqual(provider.behavior, Behavior.DOMAIN)
        self.assertEqual(provider.payload, ("example.com",))
        self.assertNotIn("url", provider.as_config())
        self.assertNotIn("path", provider.as_config())

    def test_external_mrs_is_fail_closed_before_fetch(self):
        with self.assertRaisesRegex(SystemExit, "external MRS input is unsupported"):
            process_provider("A", {"type": "http", "behavior": "domain", "format": "mrs", "url": "https://example.invalid/a"}, BuildContext({}, {"A"}))

    def test_mixed_provider_splits_in_memory(self):
        context = BuildContext({}, {"A"})
        with patch("converter.net.fetch_text", return_value="payload:\n- DOMAIN,example.com\n- IP-CIDR,192.0.2.0/24\n"):
            result = process_provider("A", {"type": "http", "behavior": "classical", "format": "yaml", "url": "https://example.invalid/a"}, context)
        self.assertEqual({provider.behavior for provider in result.providers}, {Behavior.DOMAIN, Behavior.IPCIDR})


if __name__ == "__main__":
    unittest.main()
