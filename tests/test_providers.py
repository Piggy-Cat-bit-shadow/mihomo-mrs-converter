import tempfile
import unittest
import threading
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from converter.model import Behavior, BuildContext
from converter.providers import prefetch_provider_texts, process_provider
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
    def test_prefetch_downloads_referenced_requests_concurrently(self):
        providers = {
            f"P{index}": {"type": "http", "behavior": "domain", "format": "yaml", "url": f"https://example.invalid/{index}"}
            for index in range(4)
        }
        active = 0
        maximum = 0
        lock = threading.Lock()
        barrier = threading.Barrier(4)
        def fetch(url, headers, cache):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            barrier.wait(timeout=2)
            with lock:
                active -= 1
            return f"payload:\n- {url.rsplit('/', 1)[-1]}.example\n"
        with patch.dict("os.environ", {"PROVIDER_PREFETCH_WORKERS": "4"}), patch("converter.providers.net.fetch_text", side_effect=fetch):
            result = prefetch_provider_texts(providers, set(providers), {})
        self.assertGreaterEqual(maximum, 2)
        self.assertEqual(result.unique_requests, 4)
        self.assertEqual(result.downloads, 4)

    def test_prefetch_cache_identity_includes_headers_and_reuses_exact_request(self):
        providers = {
            "A": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/rules", "header": {"X-Key": "one"}},
            "B": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/rules", "header": {"X-Key": "one"}},
            "C": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/rules", "header": {"X-Key": "two"}},
        }
        calls = []
        def fetch(url, headers, cache):
            calls.append(headers)
            return headers["X-Key"]
        with patch("converter.providers.net.fetch_text", side_effect=fetch):
            result = prefetch_provider_texts(providers, set(providers), {})
        self.assertEqual(len(calls), 2)
        self.assertEqual(result.texts, {"A": "one", "B": "one", "C": "two"})

    def test_prefetch_failure_is_propagated(self):
        providers = {"A": {"type": "http", "behavior": "domain", "format": "yaml", "url": "https://example.invalid/rules"}}
        with patch("converter.providers.net.fetch_text", side_effect=RuntimeError("upstream down")):
            with self.assertRaisesRegex(RuntimeError, "upstream down"):
                prefetch_provider_texts(providers, {"A"}, {})

    def test_prefetch_worker_count_does_not_change_result_order_or_content(self):
        providers = {
            f"P{index}": {"type": "http", "behavior": "domain", "format": "yaml", "url": f"https://example.invalid/{index}"}
            for index in range(6)
        }
        def fetch(url, headers, cache):
            return url.rsplit("/", 1)[-1]
        results = []
        for workers in ("1", "8"):
            with patch.dict("os.environ", {"PROVIDER_PREFETCH_WORKERS": workers}), patch("converter.providers.net.fetch_text", side_effect=fetch):
                results.append(prefetch_provider_texts(providers, set(providers), {}).texts)
        self.assertEqual(results[0], results[1])

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
