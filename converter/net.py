"""Single network boundary for provider and metadata downloads."""

import ssl
import time
import urllib.error
import urllib.request
import ipaddress
from urllib.parse import urlparse

try:
    import certifi
except ImportError:  # pragma: no cover
    certifi = None


def retry_after_seconds(value: str | None) -> float:
    try:
        return max(0.0, float(value or 0))
    except ValueError:
        return 0.0


MAX_PROVIDER_BYTES = 128 * 1024 * 1024


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


def request_cache_key(url: str, headers: dict[str, str] | None) -> tuple[str, tuple[tuple[str, str], ...]]:
    effective = {"user-agent": "mihomo-mrs-converter"}
    if headers:
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()):
            raise SystemExit("provider header keys and values must be strings")
        effective.update({key.lower(): value for key, value in headers.items()})
    return url, tuple(sorted(effective.items()))


def fetch_text(url: str, headers: dict[str, str] | None, memory_cache: dict[object, str]) -> str:
    cache_key = request_cache_key(url, headers)
    if cache_key in memory_cache:
        return memory_cache[cache_key]
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
