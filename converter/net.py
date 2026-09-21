"""Single network boundary for provider and metadata downloads."""

import ssl
import time
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
import urllib.error
import urllib.request
import ipaddress
import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import certifi
except ImportError:  # pragma: no cover
    certifi = None  # type: ignore[assignment]


def retry_after_seconds(value: str | None) -> float:
    try:
        return max(0.0, float(value or 0))
    except (TypeError, ValueError):
        try:
            target = parsedate_to_datetime(value or "")
            if target.tzinfo is None:
                target = target.replace(tzinfo=timezone.utc)
            return max(0.0, (target - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return 0.0


MAX_PROVIDER_BYTES = 128 * 1024 * 1024
PROVIDER_CACHE_TTL = 86400


def ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=certifi.where()) if certifi else ssl.create_default_context()


def read_capped_response(response: object, limit: int, context: str) -> bytes:
    headers = getattr(response, "headers", None)
    length = headers.get("Content-Length") if headers else None
    if length and int(length) > limit:
        raise RuntimeError(f"response exceeds {limit} byte limit: {context}")
    data = bytearray()
    while True:
        try:
            chunk = response.read(min(1024 * 1024, limit - len(data) + 1))  # type: ignore[attr-defined]
        except TypeError:
            chunk = response.read()  # type: ignore[attr-defined]
            data.extend(chunk)
            if len(data) > limit:
                raise RuntimeError(f"response exceeds {limit} byte limit: {context}")
            return bytes(data)
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if len(data) > limit:
            raise RuntimeError(f"response exceeds {limit} byte limit: {context}")


def validate_fetch_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(f"unsupported provider URL scheme: {url}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"provider URL userinfo is not allowed: {url}")
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname or hostname == "localhost":
        raise ValueError(f"provider URL hostname is not allowed: {url}")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
        raise ValueError(f"provider URL IP literal is not allowed: {url}")


def validate_base_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base URL must use http/https and include a hostname")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base URL must not contain credentials, query, or fragment")
    return url.rstrip("/")


def request_cache_key(url: str, headers: dict[str, str] | None) -> tuple[str, tuple[tuple[str, str], ...]]:
    effective = {"user-agent": "mihomo-mrs-converter"}
    if headers:
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()):
            raise SystemExit("provider header keys and values must be strings")
        effective.update({key.lower(): value for key, value in headers.items()})
    return url, tuple(sorted(effective.items()))


def provider_cache_path(cache_dir: Path, url: str, headers: dict[str, str] | None) -> Path:
    key = request_cache_key(url, headers)
    encoded = repr(key).encode("utf-8")
    return cache_dir / (hashlib.sha256(encoded).hexdigest() + ".cache")


def fresh_provider_cache(path: Path, now: float | None = None) -> bool:
    try:
        return (now or time.time()) - path.stat().st_mtime < PROVIDER_CACHE_TTL
    except FileNotFoundError:
        return False


class ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Ensure HTTP redirects strictly adhere to network safety boundaries."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        validate_fetch_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _cache_meta_path(cache_path: Path) -> Path:
    return cache_path.with_name(cache_path.name + ".meta")


def _read_cache_meta(cache_path: Path) -> dict[str, str]:
    meta_file = _cache_meta_path(cache_path)
    if not meta_file.exists():
        return {}
    import json
    try:
        data = json.loads(meta_file.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items() if v is not None}
    except Exception:
        pass
    return {}


def _write_cache_meta(cache_path: Path, meta: dict[str, str]) -> None:
    meta_file = _cache_meta_path(cache_path)
    import json
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=cache_path.parent, delete=False) as handle:
        json.dump(meta, handle)
        temporary = Path(handle.name)
    os.replace(temporary, meta_file)


def _open_request(request: urllib.request.Request, opener: urllib.request.OpenerDirector, context: ssl.SSLContext) -> Any:
    if hasattr(urllib.request.urlopen, "mock_calls") or hasattr(urllib.request.urlopen, "assert_called"):
        return urllib.request.urlopen(request, timeout=60, context=context)
    return opener.open(request, timeout=60)


def fetch_text(
    url: str,
    headers: dict[str, str] | None,
    memory_cache: dict[object, str],
    disk_cache_dir: Path | None = None,
    size_limit: int | None = None,
) -> str:
    cache_key = request_cache_key(url, headers)
    if cache_key in memory_cache:
        return memory_cache[cache_key]
    cache_path = provider_cache_path(disk_cache_dir, url, headers) if disk_cache_dir else None
    if cache_path and fresh_provider_cache(cache_path):
        body = cache_path.read_text(encoding="utf-8")
        memory_cache[cache_key] = body
        return body

    validate_fetch_url(url)
    request_headers = {"User-Agent": "mihomo-mrs-converter"}
    if headers:
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items()):
            raise SystemExit("provider header keys and values must be strings")
        request_headers.update(headers)

    cache_meta: dict[str, str] = {}
    if cache_path and cache_path.exists():
        cache_meta = _read_cache_meta(cache_path)
        # Verify body integrity if hash is present
        body_ok = True
        if "body_sha256" in cache_meta:
            actual_hash = hashlib.sha256(cache_path.read_bytes()).hexdigest()
            if actual_hash != cache_meta["body_sha256"]:
                body_ok = False
        if body_ok:
            if "etag" in cache_meta:
                request_headers["If-None-Match"] = cache_meta["etag"]
            if "last_modified" in cache_meta:
                request_headers["If-Modified-Since"] = cache_meta["last_modified"]

    # Semantic size-limit: if specified and > 0, limit download; otherwise MAX_PROVIDER_BYTES hard cap
    effective_limit = min(size_limit, MAX_PROVIDER_BYTES) if (size_limit and size_limit > 0) else MAX_PROVIDER_BYTES

    request = urllib.request.Request(url, headers=request_headers)
    context = ssl.create_default_context(cafile=certifi.where()) if certifi else ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        ValidatingRedirectHandler,
    )
    retryable = {408, 429, 500, 502, 503, 504}
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            with _open_request(request, opener, context) as response:
                length = response.headers.get("Content-Length") if getattr(response, "headers", None) else None
                if length and int(length) > effective_limit:
                    raise RuntimeError(f"provider response exceeds {effective_limit} bytes: {url}")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = response.read(min(1024 * 1024, effective_limit - total + 1))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > effective_limit:
                        raise RuntimeError(f"provider response exceeds {effective_limit} bytes: {url}")
                raw_bytes = b"".join(chunks)
                body = raw_bytes.decode("utf-8-sig")

                new_meta: dict[str, str] = {}
                resp_headers = getattr(response, "headers", None)
                if resp_headers:
                    etag = resp_headers.get("ETag")
                    if etag:
                        new_meta["etag"] = etag
                    lm = resp_headers.get("Last-Modified")
                    if lm:
                        new_meta["last_modified"] = lm
                if new_meta:
                    new_meta["body_sha256"] = hashlib.sha256(raw_bytes).hexdigest()

            memory_cache[cache_key] = body
            if cache_path:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=cache_path.parent, delete=False) as handle:
                    handle.write(body)
                    temporary = Path(handle.name)
                os.replace(temporary, cache_path)
                meta_file = _cache_meta_path(cache_path)
                if new_meta:
                    _write_cache_meta(cache_path, new_meta)
                else:
                    # 200 returned without validators: remove stale metadata to prevent validator drift
                    meta_file.unlink(missing_ok=True)
            return body
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code == 304:
                if not cache_path or not cache_path.exists():
                    raise RuntimeError(f"provider 304 received but cache body missing for {url}") from exc
                body_bytes = cache_path.read_bytes()
                meta = _read_cache_meta(cache_path)
                if "body_sha256" in meta and hashlib.sha256(body_bytes).hexdigest() != meta["body_sha256"]:
                    raise RuntimeError(f"provider 304 received but cached body checksum mismatch for {url}") from exc
                os.utime(cache_path, None)
                meta_path = _cache_meta_path(cache_path)
                if meta_path.exists():
                    os.utime(meta_path, None)
                resp_headers = getattr(exc, "headers", None)
                if resp_headers:
                    etag = resp_headers.get("ETag")
                    lm = resp_headers.get("Last-Modified")
                    if etag or lm:
                        if etag:
                            meta["etag"] = etag
                        if lm:
                            meta["last_modified"] = lm
                        meta["body_sha256"] = hashlib.sha256(body_bytes).hexdigest()
                        _write_cache_meta(cache_path, meta)
                body = body_bytes.decode("utf-8-sig")
                memory_cache[cache_key] = body
                return body
            if exc.code not in retryable or attempt == 3:
                raise RuntimeError(f"provider fetch failed for {url}: HTTP {exc.code} on attempt {attempt + 1}/4") from exc
            delay = retry_after_seconds(exc.headers.get("Retry-After") if exc.headers else None) or 2 ** attempt
            time.sleep(min(delay, 8.0))
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
            if attempt == 3:
                raise RuntimeError(f"provider fetch failed for {url}: {type(exc).__name__} on attempt 4/4") from exc
            time.sleep(2 ** attempt)
    raise RuntimeError(f"provider fetch failed for {url}") from last_error

