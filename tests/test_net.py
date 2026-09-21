import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

from converter.net import retry_after_seconds


class RetryAfterTest(unittest.TestCase):
    def test_seconds_and_http_date(self) -> None:
        self.assertEqual(retry_after_seconds("120"), 120.0)
        value = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=2), usegmt=True)
        self.assertGreaterEqual(retry_after_seconds(value), 0.0)
        self.assertEqual(retry_after_seconds("not-a-date"), 0.0)

    def test_past_http_date_is_zero(self) -> None:
        value = format_datetime(datetime(2015, 10, 21, tzinfo=timezone.utc), usegmt=True)
        self.assertEqual(retry_after_seconds(value), 0.0)

    def test_conditional_request_304_reuses_cache(self) -> None:
        import tempfile
        import os
        from pathlib import Path
        from unittest.mock import patch
        import urllib.error
        from email.message import Message
        from converter import net

        class MockResponse:
            def __init__(self, body: bytes, headers: dict[str, str] | None = None):
                self.body = body
                self.headers = Message()
                if headers:
                    for k, v in headers.items():
                        self.headers[k] = v
            def read(self, size=-1):
                body, self.body = self.body, b""
                return body
            def __enter__(self): return self
            def __exit__(self, *_): return False

        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            url = "https://example.invalid/rules.yaml"

            # Initial 200 response with ETag and Last-Modified
            resp1 = MockResponse(b"initial payload", {"ETag": '"abc-123"', "Last-Modified": "Wed, 21 Oct 2025 07:28:00 GMT"})
            with patch("urllib.request.urlopen", return_value=resp1):
                body = net.fetch_text(url, None, {}, disk_cache_dir=cache_dir)
                self.assertEqual(body, "initial payload")

            cache_path = net.provider_cache_path(cache_dir, url, None)
            self.assertTrue(cache_path.exists())
            self.assertEqual(cache_path.read_text(encoding="utf-8"), "initial payload")
            meta = net._read_cache_meta(cache_path)
            self.assertEqual(meta.get("etag"), '"abc-123"')
            self.assertEqual(meta.get("last_modified"), "Wed, 21 Oct 2025 07:28:00 GMT")

            # Expire disk cache
            os.utime(cache_path, (net.time.time() - 90000, net.time.time() - 90000))

            # Second request: server returns 304 Not Modified
            req_headers = {}
            def mock_urlopen(req, timeout, context):
                nonlocal req_headers
                req_headers = dict(req.headers)
                exc = urllib.error.HTTPError(req.full_url, 304, "Not Modified", Message(), None)
                raise exc

            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                body2 = net.fetch_text(url, None, {}, disk_cache_dir=cache_dir)
                self.assertEqual(body2, "initial payload")
                self.assertEqual(req_headers.get("If-none-match"), '"abc-123"')
                self.assertEqual(req_headers.get("If-modified-since"), "Wed, 21 Oct 2025 07:28:00 GMT")
                # Ensure cache is now considered fresh (mtime refreshed)
                self.assertTrue(net.fresh_provider_cache(cache_path))

