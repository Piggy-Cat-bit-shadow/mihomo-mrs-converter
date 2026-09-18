"""Single network boundary for provider and metadata downloads."""

import ssl
import time
import urllib.error
import urllib.request

try:
    import certifi
except ImportError:  # pragma: no cover
    certifi = None


def retry_after_seconds(value: str | None) -> float:
    try:
        return max(0.0, float(value or 0))
    except ValueError:
        return 0.0


def fetch_text(url: str, headers: dict[str, str] | None, memory_cache: dict[str, str]) -> str:
    if url in memory_cache:
        return memory_cache[url]
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
                body = response.read().decode("utf-8-sig")
            memory_cache[url] = body
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
