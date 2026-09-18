"""Fetch and normalize providers into in-memory semantic state."""

import re
from collections import Counter
from typing import Any
from urllib.parse import urlparse

import yaml

from . import net
from .model import Behavior, BuildContext, NormalizedProvider, ProviderMetadata, ProviderResult
from .rules import parse_rule, source_domain_value, source_ip_value, validate_source_domain_value
from .semantics import parse_ip_network

ALLOWED_PROVIDER_FIELDS = {"type", "behavior", "format", "url", "path", "interval", "proxy", "size-limit", "header"}


def validate_provider_name(name: str) -> None:
    if not isinstance(name, str) or not name:
        raise SystemExit("provider name must be a non-empty string")
    if "\x00" in name or "/" in name or "\\" in name or ".." in name:
        raise SystemExit(f"{name}: provider name contains unsupported path content")


def validate_http_url(name: str, url: str) -> None:
    if urlparse(url).scheme.lower() not in {"http", "https"}:
        raise SystemExit(f"{name}: unsupported provider URL scheme")


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
    value = yaml.safe_load(text)
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


def process_provider(name: str, provider: dict[str, Any], context: BuildContext) -> ProviderResult:
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

    remote = net.fetch_text(url, headers, context.memory_cache)
    raw = payload_from_remote(name, remote, fmt, allow_integer_items=behavior == "ipcidr")
    if not raw:
        raise SystemExit(f"{name}: provider contains no rules")
    parsed = [parse_rule(rule) for rule in raw]
    original = Counter(raw)
    rebuilt: Counter[str] = Counter()
    metadata = ProviderMetadata.from_mapping(provider)
    providers: list[NormalizedProvider] = []

    if behavior == "domain":
        providers.append(NormalizedProvider(name, Behavior.DOMAIN, tuple(item.raw for item in parsed), metadata))
        rebuilt.update(item.raw for item in parsed)
    elif behavior == "ipcidr":
        valid = [item.raw for item in parsed if parse_ip_network(item.raw) is not None]
        invalid = [item.raw for item in parsed if parse_ip_network(item.raw) is None]
        asns: list[str] = []
        if invalid:
            counts = re.findall(r"(?im)^\s*#\s*IP-ASN\s*:\s*(\d+)\s*$", remote)
            if len(counts) != 1 or any(not item.isdigit() for item in invalid) or len(invalid) != int(counts[0]):
                raise SystemExit(f"{name}: invalid ipcidr payload entries cannot be safely classified: {invalid}")
            asns = invalid
        if valid:
            providers.append(NormalizedProvider(name, Behavior.IPCIDR, tuple(valid), metadata))
            rebuilt.update(valid)
        if asns:
            asn_name = _reserve(name, "classical", context)
            asn_payload = [f"IP-ASN,{asn}" for asn in asns]
            providers.append(NormalizedProvider(asn_name, Behavior.CLASSICAL, tuple(asn_payload), metadata))
            rebuilt.update(asns)
    else:
        domains: list[str] = []
        ips: list[str] = []
        classical: list[str] = []
        for item in parsed:
            domain = source_domain_value(item)
            ip = source_ip_value(item)
            if domain is not None:
                validate_source_domain_value(item, domain)
                domains.append(domain)
            elif ip is not None:
                ips.append(ip)
            else:
                classical.append(item.raw)
        if domains:
            generated = _reserve(name, "domain", context)
            providers.append(NormalizedProvider(generated, Behavior.DOMAIN, tuple(domains), metadata))
            rebuilt.update(item.raw for item in parsed if source_domain_value(item) is not None)
        if ips:
            generated = _reserve(name, "ip", context)
            providers.append(NormalizedProvider(generated, Behavior.IPCIDR, tuple(ips), metadata))
            rebuilt.update(item.raw for item in parsed if source_ip_value(item) is not None)
        if classical:
            generated = _reserve(name, "classical", context)
            providers.append(NormalizedProvider(generated, Behavior.CLASSICAL, tuple(classical), metadata))
            rebuilt.update(classical)

    if not providers:
        raise SystemExit(f"{name}: provider produced no generated providers")
    if original != rebuilt:
        raise SystemExit(f"{name}: rule-count conservation failed")
    return ProviderResult(name, providers, [item.name for item in providers], original, rebuilt)
