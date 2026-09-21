import os
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

    def test_cache_case1_200_without_validators_deletes_stale_meta(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
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

            # 1. First fetch with ETag creates .meta
            resp1 = MockResponse(b"initial", {"ETag": '"v1"'})
            with patch("urllib.request.urlopen", return_value=resp1):
                net.fetch_text(url, None, {}, disk_cache_dir=cache_dir)
            cache_path = net.provider_cache_path(cache_dir, url, None)
            meta_path = net._cache_meta_path(cache_path)
            self.assertTrue(meta_path.exists())

            # 2. Second fetch returns 200 WITHOUT ETag/Last-Modified: stale .meta must be unlinked
            os.utime(cache_path, (net.time.time() - 90000, net.time.time() - 90000))
            resp2 = MockResponse(b"updated without etag")
            with patch("urllib.request.urlopen", return_value=resp2):
                body = net.fetch_text(url, None, {}, disk_cache_dir=cache_dir)
            self.assertEqual(body, "updated without etag")
            self.assertFalse(meta_path.exists())

    def test_cache_case3_304_without_cached_body_fails_closed(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        import urllib.error
        from email.message import Message
        from converter import net

        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            url = "https://example.invalid/rules.yaml"
            def mock_urlopen(req, timeout, context):
                raise urllib.error.HTTPError(req.full_url, 304, "Not Modified", Message(), None)

            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                with self.assertRaisesRegex(RuntimeError, "cache body missing"):
                    net.fetch_text(url, None, {}, disk_cache_dir=cache_dir)

    def test_cache_case4_corrupt_meta_json_recovers_cleanly(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from email.message import Message
        from converter import net

        class MockResponse:
            def __init__(self, body: bytes):
                self.body = body
                self.headers = Message()
            def read(self, size=-1):
                body, self.body = self.body, b""
                return body
            def __enter__(self): return self
            def __exit__(self, *_): return False

        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            url = "https://example.invalid/rules.yaml"
            cache_path = net.provider_cache_path(cache_dir, url, None)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text("old body", encoding="utf-8")
            os.utime(cache_path, (net.time.time() - 90000, net.time.time() - 90000))
            meta_path = net._cache_meta_path(cache_path)
            meta_path.write_text("NOT_JSON_CORRUPT{[[[", encoding="utf-8")

            # Corrupt meta should be ignored and fetch should succeed cleanly
            resp = MockResponse(b"new clean body")
            with patch("urllib.request.urlopen", return_value=resp):
                body = net.fetch_text(url, None, {}, disk_cache_dir=cache_dir)
            self.assertEqual(body, "new clean body")

    def test_cache_case5_sha256_mismatch_invalidates_conditional_request_and_304(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        import urllib.error
        from email.message import Message
        from converter import net

        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            url = "https://example.invalid/rules.yaml"
            cache_path = net.provider_cache_path(cache_dir, url, None)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text("tampered body", encoding="utf-8")
            os.utime(cache_path, (net.time.time() - 90000, net.time.time() - 90000))
            meta_path = net._cache_meta_path(cache_path)
            net._write_cache_meta(cache_path, {
                "etag": '"etag-abc"',
                "body_sha256": "expected_different_sha256_hash",
            })

            # Since body_sha256 doesn't match actual body, conditional headers should NOT be sent
            req_headers = {}
            def mock_urlopen(req, timeout, context):
                nonlocal req_headers
                req_headers = dict(req.headers)
                # If server responds 304 to corrupt cache, it must fail-closed
                raise urllib.error.HTTPError(req.full_url, 304, "Not Modified", Message(), None)

            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                    net.fetch_text(url, None, {}, disk_cache_dir=cache_dir)
                self.assertNotIn("If-none-match", req_headers)

    def test_fetch_text_enforces_size_limit(self) -> None:
        from unittest.mock import patch
        from email.message import Message
        from converter import net

        class MockResponse:
            def __init__(self, body: bytes, length: int | None = None):
                self.body = body
                self.headers = Message()
                if length is not None:
                    self.headers["Content-Length"] = str(length)
            def read(self, size=-1):
                body, self.body = self.body, b""
                return body
            def __enter__(self): return self
            def __exit__(self, *_): return False

        url = "https://example.invalid/rules.yaml"

        # Content-Length header exceeding size_limit
        resp1 = MockResponse(b"small body", length=500)
        with patch("urllib.request.urlopen", return_value=resp1):
            with self.assertRaisesRegex(RuntimeError, "exceeds 100 bytes"):
                net.fetch_text(url, None, {}, size_limit=100)

        # Streamed body exceeding size_limit
        resp2 = MockResponse(b"x" * 200)
        with patch("urllib.request.urlopen", return_value=resp2):
            with self.assertRaisesRegex(RuntimeError, "exceeds 100 bytes"):
                net.fetch_text(url, None, {}, size_limit=100)

    def test_validating_redirect_handler(self) -> None:
        import urllib.request
        from converter.net import ValidatingRedirectHandler

        handler = ValidatingRedirectHandler()
        req = urllib.request.Request("https://example.com/start")

        # Disallowed redirect to loopback IP
        with self.assertRaisesRegex(ValueError, "IP literal is not allowed"):
            handler.redirect_request(req, None, 302, "Found", {}, "http://127.0.0.1/evil")

        # Disallowed redirect to private IP
        with self.assertRaisesRegex(ValueError, "IP literal is not allowed"):
            handler.redirect_request(req, None, 302, "Found", {}, "http://192.168.1.1/evil")

        # Disallowed redirect to userinfo
        with self.assertRaisesRegex(ValueError, "userinfo is not allowed"):
            handler.redirect_request(req, None, 302, "Found", {}, "http://user:pass@example.com/evil")

        # Disallowed redirect to file scheme
        with self.assertRaisesRegex(ValueError, "unsupported provider URL scheme"):
            handler.redirect_request(req, None, 302, "Found", {}, "file:///etc/passwd")

        # Valid redirect to public https
        redirected_req = handler.redirect_request(req, None, 302, "Found", {}, "https://safe.example.com/target")
        self.assertIsNotNone(redirected_req)
        self.assertEqual(redirected_req.full_url, "https://safe.example.com/target")

    def test_origin_helper(self) -> None:
        from converter.net import _origin
        self.assertEqual(_origin("https://example.com/a"), ("https", "example.com", 443))
        self.assertEqual(_origin("https://example.com:443/b"), ("https", "example.com", 443))
        self.assertEqual(_origin("http://example.com/a"), ("http", "example.com", 80))
        self.assertEqual(_origin("http://example.com:80/b"), ("http", "example.com", 80))
        self.assertEqual(_origin("https://example.com:8443/a"), ("https", "example.com", 8443))
        self.assertEqual(_origin("https://EXAMPLE.COM./a"), ("https", "example.com", 443))
        self.assertEqual(_origin("https://other.example.com/a"), ("https", "other.example.com", 443))

    def test_1_user_agent_secret_does_not_cross_origin(self) -> None:
        import urllib.request
        from converter.net import ValidatingRedirectHandler, DEFAULT_USER_AGENT

        handler = ValidatingRedirectHandler()
        req = urllib.request.Request("https://a.example/start", headers={"User-Agent": "SECRET-UA"})
        redirected = handler.redirect_request(req, None, 302, "Found", {}, "https://b.example/dest")
        self.assertIsNotNone(redirected)
        self.assertEqual(redirected.headers.get("User-agent"), DEFAULT_USER_AGENT)
        self.assertNotIn("SECRET-UA", str(redirected.headers))
        self.assertNotIn("SECRET-UA", str(redirected.unredirected_hdrs))

    def test_2_accept_value_does_not_cross_origin(self) -> None:
        import urllib.request
        from converter.net import ValidatingRedirectHandler

        handler = ValidatingRedirectHandler()
        req = urllib.request.Request("https://a.example/start", headers={"Accept": "SECRET-IN-ACCEPT"})
        redirected = handler.redirect_request(req, None, 302, "Found", {}, "https://b.example/dest")
        self.assertIsNotNone(redirected)
        self.assertNotIn("Accept", redirected.headers)
        self.assertNotIn("accept", redirected.headers)
        self.assertNotIn("SECRET-IN-ACCEPT", str(redirected.headers))

    def test_3_all_user_headers_cleared_on_cross_origin(self) -> None:
        import urllib.request
        from converter.net import ValidatingRedirectHandler, DEFAULT_USER_AGENT

        handler = ValidatingRedirectHandler()
        req = urllib.request.Request(
            "https://a.example/start",
            headers={
                "Authorization": "Bearer secret-tok",
                "Cookie": "session=abc",
                "Proxy-Authorization": "Basic creds",
                "X-API-Key": "key-secret",
                "X-Custom": "val",
                "Accept": "text/yaml",
                "Accept-Encoding": "gzip",
                "Accept-Language": "zh-CN",
                "Referer": "https://a.example/private",
                "Origin": "https://a.example",
                "If-None-Match": '"etag-abc"',
                "If-Modified-Since": "Wed, 21 Oct 2025 07:28:00 GMT",
                "User-Agent": "SECRET-UA-OVERRIDE",
            },
        )
        redirected = handler.redirect_request(req, None, 302, "Found", {}, "https://b.example/dest")
        self.assertIsNotNone(redirected)
        # Directly assert that only the framework-owned User-Agent remains
        self.assertEqual(dict(redirected.headers), {"User-agent": DEFAULT_USER_AGENT})
        self.assertEqual(dict(redirected.unredirected_hdrs), {})

    def test_4_same_origin_preserves_all_headers(self) -> None:
        import urllib.request
        from converter.net import ValidatingRedirectHandler

        handler = ValidatingRedirectHandler()
        req = urllib.request.Request(
            "https://a.example/path1",
            headers={
                "Authorization": "Bearer my-secret-token",
                "X-API-Key": "api-key-123",
                "User-Agent": "CUSTOM-UA",
                "Accept": "application/json",
                "If-None-Match": '"etag-123"',
                "If-Modified-Since": "Wed, 21 Oct 2025 07:28:00 GMT",
            },
        )
        redirected = handler.redirect_request(req, None, 302, "Found", {}, "https://a.example/path2")
        self.assertIsNotNone(redirected)
        self.assertEqual(redirected.headers["Authorization"], "Bearer my-secret-token")
        self.assertEqual(redirected.headers["X-api-key"], "api-key-123")
        self.assertEqual(redirected.headers["User-agent"], "CUSTOM-UA")
        self.assertEqual(redirected.headers["Accept"], "application/json")
        self.assertEqual(redirected.headers["If-none-match"], '"etag-123"')
        self.assertEqual(redirected.headers["If-modified-since"], "Wed, 21 Oct 2025 07:28:00 GMT")

    def test_5_unredirected_hdrs_completely_cleared_on_cross_origin(self) -> None:
        import urllib.request
        from converter.net import _sanitize_cross_origin_headers, DEFAULT_USER_AGENT

        req = urllib.request.Request("https://a.example/start")
        req.add_header("X-Secret-Regular", "val1")
        req.add_unredirected_header("Authorization", "Bearer tok")
        req.add_unredirected_header("X-Secret", "my-secret")
        req.add_unredirected_header("Accept", "text/plain")
        req.add_unredirected_header("User-Agent", "SECRET-UNREDIR-UA")

        _sanitize_cross_origin_headers(req)

        self.assertEqual(dict(req.headers), {"User-agent": DEFAULT_USER_AGENT})
        self.assertEqual(dict(req.unredirected_hdrs), {})
        self.assertNotIn("SECRET-UNREDIR-UA", str(req.headers))
        self.assertNotIn("SECRET-UNREDIR-UA", str(req.unredirected_hdrs))

    def test_6_cross_port_clears_all_user_headers(self) -> None:
        import urllib.request
        from converter.net import ValidatingRedirectHandler, DEFAULT_USER_AGENT

        handler = ValidatingRedirectHandler()
        req = urllib.request.Request(
            "https://a.example/start",
            headers={"X-API-Key": "secret", "Authorization": "Bearer tok", "User-Agent": "CUSTOM-UA"},
        )
        redirected = handler.redirect_request(req, None, 302, "Found", {}, "https://a.example:8443/dest")
        self.assertIsNotNone(redirected)
        self.assertEqual(dict(redirected.headers), {"User-agent": DEFAULT_USER_AGENT})
        self.assertEqual(dict(redirected.unredirected_hdrs), {})

    def test_7_scheme_change_clears_all_user_headers(self) -> None:
        import urllib.request
        from converter.net import ValidatingRedirectHandler, DEFAULT_USER_AGENT

        handler = ValidatingRedirectHandler()
        req = urllib.request.Request(
            "https://a.example/start",
            headers={"X-Custom-Secret": "secret", "Authorization": "Bearer tok", "User-Agent": "CUSTOM-UA"},
        )
        redirected = handler.redirect_request(req, None, 302, "Found", {}, "http://a.example/dest")
        self.assertIsNotNone(redirected)
        self.assertEqual(dict(redirected.headers), {"User-agent": DEFAULT_USER_AGENT})
        self.assertEqual(dict(redirected.unredirected_hdrs), {})

    def test_8_default_port_equivalence_is_same_origin(self) -> None:
        import urllib.request
        from converter.net import ValidatingRedirectHandler

        handler = ValidatingRedirectHandler()
        # https default port 443
        req_https = urllib.request.Request(
            "https://a.example/start",
            headers={"Authorization": "Bearer tok", "X-Key": "123", "User-Agent": "CUSTOM-UA"},
        )
        redirected_https = handler.redirect_request(req_https, None, 302, "Found", {}, "https://a.example:443/dest")
        self.assertIsNotNone(redirected_https)
        self.assertEqual(redirected_https.headers["Authorization"], "Bearer tok")
        self.assertEqual(redirected_https.headers["X-key"], "123")
        self.assertEqual(redirected_https.headers["User-agent"], "CUSTOM-UA")

        # http default port 80
        req_http = urllib.request.Request(
            "http://a.example/start",
            headers={"Authorization": "Bearer tok-http", "X-Key": "456", "User-Agent": "CUSTOM-UA-HTTP"},
        )
        redirected_http = handler.redirect_request(req_http, None, 302, "Found", {}, "http://a.example:80/dest")
        self.assertIsNotNone(redirected_http)
        self.assertEqual(redirected_http.headers["Authorization"], "Bearer tok-http")
        self.assertEqual(redirected_http.headers["X-key"], "456")
        self.assertEqual(redirected_http.headers["User-agent"], "CUSTOM-UA-HTTP")

    def test_fetch_text_bom_hash_consistency_and_304(self) -> None:
        import tempfile
        import hashlib
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
            url = "https://example.invalid/bom-rules.yaml"

            # Server returns UTF-8 BOM + content
            raw_body = b"\xef\xbb\xbfpayload:\n- bom.example.com\n"
            resp = MockResponse(raw_body, {"ETag": '"bom-etag"'})
            with patch("urllib.request.urlopen", return_value=resp):
                body = net.fetch_text(url, None, {}, disk_cache_dir=cache_dir)
                self.assertEqual(body, "payload:\n- bom.example.com\n")

            cache_path = net.provider_cache_path(cache_dir, url, None)
            self.assertTrue(cache_path.exists())
            # Cached file must be normalized UTF-8 without BOM
            self.assertEqual(cache_path.read_bytes(), b"payload:\n- bom.example.com\n")
            meta = net._read_cache_meta(cache_path)
            # body_sha256 must match normalized cached file, not raw BOM bytes
            expected_hash = hashlib.sha256(b"payload:\n- bom.example.com\n").hexdigest()
            self.assertEqual(meta.get("body_sha256"), expected_hash)

            # Expire cache to force conditional request
            net.os.utime(cache_path, (net.time.time() - 90000, net.time.time() - 90000))

            # 304 Not Modified must succeed because checksums match
            def mock_304(req, timeout, context):
                raise urllib.error.HTTPError(req.full_url, 304, "Not Modified", Message(), None)

            with patch("urllib.request.urlopen", side_effect=mock_304):
                body304 = net.fetch_text(url, None, {}, disk_cache_dir=cache_dir)
                self.assertEqual(body304, "payload:\n- bom.example.com\n")

    def test_cached_disk_hit_enforces_size_limit(self) -> None:
        import tempfile
        from pathlib import Path
        from converter import net

        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            url = "https://example.invalid/large.yaml"
            cache_path = net.provider_cache_path(cache_dir, url, None)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            # Write 500 bytes to cache
            cache_path.write_bytes(b"x" * 500)

            # Fresh cache hit must raise if size_limit is 100
            with self.assertRaisesRegex(RuntimeError, "exceeds 100 bytes"):
                net.fetch_text(url, None, {}, disk_cache_dir=cache_dir, size_limit=100)


