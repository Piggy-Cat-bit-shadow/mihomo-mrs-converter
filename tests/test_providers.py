import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from converter.model import Behavior, BuildContext
from converter.providers import process_provider
from converter import net


class Response:
    def __init__(self, body: bytes):
        self.body = body
        self.headers = Message()
    def read(self, size=-1):
        if size < 0:
            body, self.body = self.body, b""
            return body
        body, self.body = self.body[:size], self.body[size:]
        return body
    def __enter__(self): return self
    def __exit__(self, *_): return False


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

    def test_fetch_text_streams_and_caches_normal_response(self):
        with patch("converter.net.urllib.request.urlopen", return_value=Response(b"payload")):
            self.assertEqual(net.fetch_text("https://example.invalid/rules", None, {}), "payload")

    def test_fetch_text_rejects_oversized_response(self):
        with patch.object(net, "MAX_PROVIDER_BYTES", 3), patch("converter.net.urllib.request.urlopen", return_value=Response(b"four")):
            with self.assertRaisesRegex(RuntimeError, "exceeds 3 bytes.*example.invalid"):
                net.fetch_text("https://example.invalid/rules", None, {})

    def test_provider_url_basics_reject_userinfo_and_private_literals(self):
        for url in ("https://user:pass@example.invalid/rules", "http://127.0.0.1/rules", "http://localhost/rules"):
            with self.assertRaisesRegex(SystemExit, "URL"):
                process_provider("A", {"type": "http", "behavior": "domain", "format": "text", "url": url}, BuildContext({}, {"A"}))


if __name__ == "__main__":
    unittest.main()
