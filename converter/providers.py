"""Fetch and normalize providers into in-memory semantic state."""

import hashlib
import os
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import net
from .identifiers import validate_artifact_id
from .model import Behavior, BuildContext, NormalizedProvider, ProviderMetadata
from .payload import IpEntry, parse_classical_payload, parse_domain_payload, parse_ip_network
from .rules import parse_rule, source_domain_value, source_ip_value, validate_source_domain_value
from .yamlio import load_yaml

ALLOWED_PROVIDER_FIELDS = {"type", "behavior", "format", "url", "path", "interval", "proxy", "size-limit", "header"}


def validate_provider_name(name: str) -> None:
    validate_artifact_id(name, "provider name")


def validate_http_url(name: str, url: str) -> None:
    try:
        net.validate_fetch_url(url)
    except ValueError as exc:
        raise SystemExit(f"{name}: {exc}") from exc


def strict_yaml_rule_list(name: str, value: Any, allow_integer_items: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise SystemExit(f"{name}: YAML provider payload must be a list")
    output: list[str] = []
    for item in value:
        if allow_integer_items and isinstance(item, int) and not isinstance(item, bool):
            item = str(item)
        if not isinstance(item, str):
            raise SystemExit(f"{name}: YAML provider payload items must be strings")
        item = item.strip()
        if item:
            output.append(item)
    return output


def payload_from_remote(name: str, text: str, fmt: str, allow_integer_items: bool = False) -> list[str]:
    if fmt == "text":
        return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    if fmt != "yaml":
        raise SystemExit(f"{name}: external MRS input is unsupported; use YAML/text source")
    value = load_yaml(text)
    if isinstance(value, dict):
        value = value.get("payload", value.get("rules"))
    return strict_yaml_rule_list(name, value, allow_integer_items)


def _reserve(base: str, suffix: str, context: BuildContext) -> str:
    candidate = f"{base}-{suffix}"
    if candidate not in context.used_names:
        context.used_names.add(candidate)
        return candidate
    index = 1
    while True:
        candidate = f"{base}-mrs{index if index > 1 else ''}-{suffix}"
        if candidate not in context.used_names:
            context.used_names.add(candidate)
            return candidate
        index += 1


@dataclass(frozen=True)
class ProviderPrefetch:
    texts: dict[str, str]
    unique_requests: int
    cache_hits: int
    downloads: int
    disk_hits: int


def _prefetch_workers(request_count: int) -> int:
    try:
        configured = int(os.environ.get("PROVIDER_PREFETCH_WORKERS", "8"))
    except ValueError:
        configured = 8
    return max(1, min(16, configured, request_count))


RequestKey = tuple[str, tuple[tuple[str, str], ...]]
RequestEntry = tuple[str, dict[str, str] | None, list[str], list[int]]


def prefetch_provider_texts(
    providers: dict[str, dict[str, Any]], referenced: set[str], memory_cache: dict[object, str], disk_cache_dir: Path | None = None
) -> ProviderPrefetch:
    requests: dict[RequestKey, RequestEntry] = {}
    for name, provider in providers.items():
        if name not in referenced:
            continue
        if set(provider) - ALLOWED_PROVIDER_FIELDS:
            continue
        if provider.get("type") != "http" or not isinstance(provider.get("url"), str):
            continue
        if provider.get("behavior") not in {"classical", "domain", "ipcidr"}:
            continue
        if provider.get("format", "yaml") == "mrs":
            # Preserve process_provider's fail-closed validation without
            # contacting an unsupported external MRS source first.
            continue
        if provider.get("format", "yaml") not in {"yaml", "text"} or (
            provider.get("header") is not None and not isinstance(provider.get("header"), dict)
        ):
            continue
        size_limit = provider.get("size-limit", 0)
        if isinstance(size_limit, bool) or not isinstance(size_limit, int) or size_limit < 0:
            continue
        url = provider.get("url")
        headers = provider.get("header")
        if not isinstance(url, str):
            continue
        key = net.request_cache_key(url, headers if isinstance(headers, dict) else None)
        if key not in requests:
            requests[key] = (url, headers if isinstance(headers, dict) else None, [], [])
        requests[key][2].append(name)
        requests[key][3].append(size_limit)

    cache_hits = sum(key in memory_cache for key in requests)
    disk_hits = 0
    if disk_cache_dir:
        for key, (url, headers, _names, limits) in requests.items():
            cache_path = net.provider_cache_path(disk_cache_dir, url, headers)
            if key not in memory_cache and net.fresh_provider_cache(cache_path):
                positive = [lim for lim in limits if lim > 0]
                effective_limit = min(positive) if positive else net.MAX_PROVIDER_BYTES
                if cache_path.stat().st_size > effective_limit:
                    continue
                meta = net._read_cache_meta(cache_path)
                if "body_sha256" in meta and hashlib.sha256(cache_path.read_bytes()).hexdigest() != meta["body_sha256"]:
                    continue
                memory_cache[key] = cache_path.read_text(encoding="utf-8")
                disk_hits += 1
    pending: list[tuple[RequestKey, RequestEntry]] = [(key, request) for key, request in requests.items() if key not in memory_cache]

    def download(item: tuple[RequestKey, RequestEntry]) -> tuple[RequestKey, str]:
        key, (url, headers, _names, limits) = item
        positive = [lim for lim in limits if lim > 0]
        effective_limit = min(positive) if positive else None
        if effective_limit is not None:
            if disk_cache_dir is not None:
                text = net.fetch_text(url, headers, {}, disk_cache_dir, size_limit=effective_limit)
            else:
                text = net.fetch_text(url, headers, {}, size_limit=effective_limit)
        else:
            if disk_cache_dir is not None:
                text = net.fetch_text(url, headers, {}, disk_cache_dir)
            else:
                text = net.fetch_text(url, headers, {})
        return key, text

    with ThreadPoolExecutor(max_workers=_prefetch_workers(len(pending))) if pending else _NullExecutor() as executor:
        for key, text in executor.map(download, pending):
            memory_cache[key] = text

    texts = {
        name: memory_cache[key]
        for key, (_url, _headers, names, _limits) in requests.items()
        for name in names
    }
    return ProviderPrefetch(texts, len(requests), cache_hits, len(pending), disk_hits)


class _NullExecutor:
    def __enter__(self) -> "_NullExecutor":
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def map(self, _function: Any, _items: list[Any]) -> list[Any]:
        return []


def _classical_payloads(
    name: str, parsed: list[Any], metadata: ProviderMetadata, context: BuildContext
) -> list[NormalizedProvider]:
    """Split a classical provider into the domain/ip/classical providers it implies."""
    domains: list[str] = []
    ips: list[IpEntry] = []
    classical: list[Any] = []
    for item in parsed:
        domain = source_domain_value(item)
        ip = source_ip_value(item)
        if domain is not None:
            validate_source_domain_value(item, domain)
            domains.append(domain)
        elif ip is not None:
            network = parse_ip_network(ip)
            if network is None:
                raise SystemExit(f"{name}: invalid IP-CIDR value in classical provider: {item.raw!r}")
            ips.append(IpEntry(ip, network))
        else:
            classical.append(item)
    generated: list[NormalizedProvider] = []
    if domains:
        generated.append(NormalizedProvider(_reserve(name, "domain", context), name, Behavior.DOMAIN, parse_domain_payload(domains), metadata))
    if ips:
        generated.append(NormalizedProvider(_reserve(name, "ip", context), name, Behavior.IPCIDR, tuple(ips), metadata))
    if classical:
        generated.append(NormalizedProvider(_reserve(name, "classical", context), name, Behavior.CLASSICAL, tuple(classical), metadata))
    return generated


def process_provider(
    name: str, provider: dict[str, Any], context: BuildContext, remote_text: str | None = None
) -> tuple[NormalizedProvider, ...]:
    validate_provider_name(name)
    unknown = sorted(set(provider) - ALLOWED_PROVIDER_FIELDS)
    if "path-in-bundle" in provider or unknown:
        detail = "path-in-bundle is unsupported" if "path-in-bundle" in provider else f"unsupported provider fields: {', '.join(unknown)}"
        raise SystemExit(f"{name}: {detail}")
    url = provider.get("url")
    behavior = provider.get("behavior")
    fmt = provider.get("format", "yaml")
    if provider.get("type") != "http" or not isinstance(url, str):
        raise SystemExit(f"{name}: only http providers with url are supported")
    validate_http_url(name, url)
    if behavior not in {"classical", "domain", "ipcidr"}:
        raise SystemExit(f"{name}: unsupported behavior {behavior!r}")
    if fmt == "mrs":
        raise SystemExit(f"{name}: external MRS input is unsupported; use YAML/text source")
    if fmt not in {"yaml", "text"}:
        raise SystemExit(f"{name}: unsupported format {fmt!r}")
    headers = provider.get("header")
    if headers is not None and not isinstance(headers, dict):
        raise SystemExit(f"{name}: provider header must be a mapping")
    size_limit = provider.get("size-limit", 0)
    if isinstance(size_limit, bool) or not isinstance(size_limit, int) or size_limit < 0:
        raise SystemExit(f"{name}: size-limit must be a non-negative byte count")

    if remote_text is not None:
        effective_limit = size_limit if size_limit > 0 else net.MAX_PROVIDER_BYTES
        if len(remote_text.encode("utf-8")) > effective_limit:
            raise SystemExit(f"{name}: provider response exceeds {effective_limit} bytes: {url}")
        remote = remote_text
    else:
        try:
            if size_limit > 0:
                remote = net.fetch_text(url, headers, context.memory_cache, size_limit=size_limit)
            else:
                remote = net.fetch_text(url, headers, context.memory_cache)
        except RuntimeError as exc:
            raise SystemExit(f"{name}: {exc}") from exc
    raw = payload_from_remote(name, remote, fmt, allow_integer_items=behavior == "ipcidr")
    if not raw:
        raise SystemExit(f"{name}: provider contains no rules")
    original = Counter(raw)
    rebuilt: Counter[str] = Counter()
    metadata = ProviderMetadata.from_mapping(provider)
    generated: list[NormalizedProvider] = []

    if behavior == "domain":
        generated.append(NormalizedProvider(name, name, Behavior.DOMAIN, parse_domain_payload(raw), metadata))
        rebuilt.update(raw)
    elif behavior == "ipcidr":
        valid: list[IpEntry] = []
        asns: list[str] = []
        for value in raw:
            network = parse_ip_network(value)
            if network is not None:
                valid.append(IpEntry(value, network))
            else:
                asns.append(value)
        if asns:
            counts = re.findall(r"(?im)^\s*#\s*IP-ASN\s*:\s*(\d+)\s*$", remote)
            if len(counts) != 1 or any(not item.isdigit() for item in asns) or len(asns) != int(counts[0]):
                raise SystemExit(f"{name}: invalid ipcidr payload entries cannot be safely classified: {asns}")
        if valid:
            generated.append(NormalizedProvider(name, name, Behavior.IPCIDR, tuple(valid), metadata))
            rebuilt.update(entry.raw for entry in valid)
        if asns:
            asn_payload = parse_classical_payload([f"IP-ASN,{asn}" for asn in asns])
            generated.append(
                NormalizedProvider(_reserve(name, "classical", context), name, Behavior.CLASSICAL, asn_payload, metadata)
            )
            rebuilt.update(asns)
    else:
        parsed = [parse_rule(rule) for rule in raw]
        generated = _classical_payloads(name, parsed, metadata, context)
        rebuilt.update(item.raw for item in parsed)

    if not generated:
        raise SystemExit(f"{name}: provider produced no generated providers")
    if original != rebuilt:
        raise SystemExit(f"{name}: rule-count conservation failed")
    return tuple(generated)
