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
from urllib.parse import urlparse

try:
    import certifi
except ImportError:  # pragma: no cover
    certifi = None


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


def fetch_text(url: str, headers: dict[str, str] | None, memory_cache: dict[object, str], disk_cache_dir: Path | None = None) -> str:
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
    request = urllib.request.Request(url, headers=request_headers)
    context = ssl.create_default_context(cafile=certifi.where()) if certifi else ssl.create_default_context()
    retryable = {408, 429, 500, 502, 503, 504}
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=60, context=context) as response:
                length = response.headers.get("Content-Length") if getattr(response, "headers", None) else None
                if length and int(length) > MAX_PROVIDER_BYTES:
                    raise RuntimeError(f"provider response exceeds {MAX_PROVIDER_BYTES} bytes: {url}")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = response.read(min(1024 * 1024, MAX_PROVIDER_BYTES - total + 1))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > MAX_PROVIDER_BYTES:
                        raise RuntimeError(f"provider response exceeds {MAX_PROVIDER_BYTES} bytes: {url}")
                body = b"".join(chunks).decode("utf-8-sig")
            memory_cache[cache_key] = body
            if cache_path:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=cache_path.parent, delete=False) as handle:
                    handle.write(body)
                    temporary = Path(handle.name)
                os.replace(temporary, cache_path)
            return body
        except urllib.error.HTTPError as exc:
            last_error = exc
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
