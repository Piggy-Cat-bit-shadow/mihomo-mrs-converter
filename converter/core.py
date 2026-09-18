#!/usr/bin/env python3
import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import tempfile
import re
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from .model import Behavior, ProviderIdentity, format_provider_name, parse_legacy_provider_name
from .rules import (
    RuleLine, RulesetReference, _rewrite_expression, _ruleset_parts_in_expression,
    find_ruleset_refs, normalize, parse_egern_network_rule, parse_egern_sub_rule_members,
    parse_rule, parse_ruleset_reference, provider_has_target_ip, simple_ruleset_wrapper,
    split_top_level_commas, strip_balanced_outer_parentheses, wrap_ruleset_rule,
    source_domain_value, validate_source_domain_value, source_ip_value,
    ruleset_routing_signature, egern_udp_and_ruleset,
)

try:
    import certifi
except ImportError:  # pragma: no cover - optional runtime fallback
    certifi = None


DOMAIN_RULES = {"DOMAIN", "DOMAIN-SUFFIX"}
IPCIDR_RULES = {"IP-CIDR", "IP-CIDR6"}
TARGET_IP_KINDS = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}
SUITES = {"unmerged", "merged", "merged-dedup"}
FINAL_SUITE = "final"
MANAGED_STATE_FILENAME = "managed-state.yaml"
BEHAVIOR_ORDER = {"domain": 0, "classical": 1, "ipcidr": 2}


def is_target_ip_kind(kind: str) -> bool:
    """Return whether a matcher targets the destination IP.

    Source-IP matchers intentionally remain outside this set: no-resolve is a
    destination-IP routing policy, not a generic modifier for every IP rule.
    """
    return kind.upper() in TARGET_IP_KINDS


@dataclass
class ProviderResult:
    original_name: str
    generated_names: list[str]
    providers: dict[str, dict[str, Any]]
    original_rules: Counter[str]
    rebuilt_rules: Counter[str]
    source_payloads: dict[str, list[str]]


@dataclass
class BuildOptions:
    dist: Path
    base_url: str
    mihomo: str | None
    used_names: set[str]
    used_paths: set[str]
    memory_cache: dict[str, str]
    final_payloads: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class DedupStats:
    input_count: int = 0
    exact_duplicates_removed: int = 0
    domain_covered_by_suffix: int = 0
    suffix_covered_by_parent_suffix: int = 0
    ipcidr_duplicates_removed: int = 0
    ipcidr_covered_by_parent: int = 0
    output_count: int = 0

    @property
    def removed(self) -> int:
        return self.input_count - self.output_count


ALLOWED_PROVIDER_FIELDS = {
    "type",
    "behavior",
    "format",
    "url",
    "path",
    "interval",
    "proxy",
    "size-limit",
    "header",
}
PASSTHROUGH_PROVIDER_FIELDS = {
    "type",
    "behavior",
    "format",
    "url",
    "path",
    "interval",
    "proxy",
    "size-limit",
}


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must be a YAML mapping")
    return data


def load_yaml(path: Path) -> dict[str, Any]:
    data = load_yaml_mapping(path)
    if "rule-providers" in data and not isinstance(data["rule-providers"], dict):
        raise SystemExit(f"{path}: rule-providers must be a YAML mapping")
    if "sub-rules" in data:
        if not isinstance(data["sub-rules"], dict):
            raise SystemExit(f"{path}: sub-rules must be a YAML mapping")
        for name, members in data["sub-rules"].items():
            if not isinstance(name, str) or not isinstance(members, list):
                raise SystemExit(f"{path}: sub-rules entries must map names to lists")
            if not all(isinstance(member, str) for member in members):
                raise SystemExit(f"{path}: sub-rules members must be strings")
    if "rules" in data and not isinstance(data["rules"], list):
        raise SystemExit(f"{path}: rules must be a YAML list")
    return data


def validate_provider_name(name: str) -> None:
    if not isinstance(name, str) or not name:
        raise SystemExit("provider name must be a non-empty string")
    if "\x00" in name or "/" in name or "\\" in name or ".." in name:
        raise SystemExit(f"{name}: provider name contains unsupported path content")


def load_segment_name_mapping(root: Path) -> dict[str, str]:
    path = root / "segment-names.yaml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SystemExit(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("segments", {}), dict):
        raise SystemExit(f"{path}: expected a segments mapping")
    mapping: dict[str, str] = {}
    for old, new in data.get("segments", {}).items():
        if not isinstance(old, str) or not re.fullmatch(r"merged-segment-\d+", old):
            raise SystemExit(f"{path}: invalid segment name {old!r}")
        if not isinstance(new, str):
            raise SystemExit(f"{path}: mapped name for {old} must be a string")
        validate_provider_name(new)
        if new in mapping.values():
            raise SystemExit(f"{path}: duplicate final segment name {new!r}")
        mapping[old] = new
    return mapping


def validate_http_url(name: str, url: str) -> None:
    scheme = urlparse(url).scheme.lower()
    if scheme not in {"http", "https"}:
        raise SystemExit(f"{name}: unsupported provider URL scheme {scheme!r}")


def fetch_text(url: str, headers: dict[str, Any] | None, memory_cache: dict[str, str]) -> str:
    if url in memory_cache:
        return memory_cache[url]
    request_headers = {"User-Agent": "mihomo-mrs-converter"}
    if headers:
        for key, value in headers.items():
            if isinstance(key, str) and isinstance(value, str):
                request_headers[key] = value
            else:
                raise SystemExit("provider header keys and values must be strings")
    request = urllib.request.Request(url, headers=request_headers)
    context = (
        ssl.create_default_context(cafile=certifi.where())
        if certifi is not None
        else ssl.create_default_context()
    )
    last_error: Exception | None = None
    max_attempts = 4
    retryable_statuses = {408, 429, 500, 502, 503, 504}
    for attempt in range(max_attempts):
        try:
            with urllib.request.urlopen(request, timeout=60, context=context) as response:
                body = response.read().decode("utf-8-sig")
            break
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in retryable_statuses or attempt == max_attempts - 1:
                raise RuntimeError(
                    f"provider fetch failed for {url}: HTTP {exc.code} "
                    f"on attempt {attempt + 1}/{max_attempts}"
                ) from exc
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            delay = min(_retry_after_seconds(retry_after), 8.0) if retry_after else 2 ** attempt
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:  # pragma: no cover - network timing dependent
            last_error = exc
            if attempt == max_attempts - 1:
                raise RuntimeError(
                    f"provider fetch failed for {url}: {type(exc).__name__} "
                    f"on attempt {attempt + 1}/{max_attempts}"
                ) from exc
            time.sleep(2 ** attempt)
    else:  # pragma: no cover
        raise last_error
    memory_cache[url] = body
    return body


def _retry_after_seconds(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return max(0.0, float(value))
    except ValueError:
        return 0.0


def strict_yaml_rule_list(name: str, value: Any, allow_integer_items: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise SystemExit(f"{name}: YAML provider payload must be a list")
    rules: list[str] = []
    for item in value:
        if allow_integer_items and isinstance(item, int) and not isinstance(item, bool):
            item = str(item)
        if not isinstance(item, str):
            raise SystemExit(f"{name}: YAML provider payload items must be strings")
        stripped = item.strip()
        if stripped:
            rules.append(stripped)
    return rules


def payload_from_yaml(name: str, text: str, allow_integer_items: bool = False) -> list[str]:
    parsed = yaml.safe_load(text)
    if isinstance(parsed, dict):
        for key in ("payload", "rules"):
            if key in parsed:
                return strict_yaml_rule_list(name, parsed[key], allow_integer_items)
        raise SystemExit(f"{name}: YAML provider must contain payload or rules")
    if isinstance(parsed, list):
        return strict_yaml_rule_list(name, parsed, allow_integer_items)
    raise SystemExit(f"{name}: YAML provider must be a mapping or list")


def payload_from_text(text: str) -> list[str]:
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def payload_from_remote(name: str, text: str, fmt: str, allow_integer_items: bool = False) -> list[str]:
    if fmt == "yaml":
        return payload_from_yaml(name, text, allow_integer_items)
    if fmt == "text":
        return payload_from_text(text)
    raise SystemExit(f"{name}: unsupported source format {fmt!r}")


def domain_suffix_value(rule: str) -> str | None:
    value = rule.strip().lower()
    if value.startswith("+.") and len(value) > 2:
        return value[2:].rstrip(".")
    return None


def domain_covered_by_suffix(domain: str, suffixes: set[str]) -> bool:
    value = domain.strip().lower().rstrip(".")
    if not value:
        return False
    labels = value.split(".")
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in suffixes:
            return True
    return False


def suffix_covered_by_parent_suffix(suffix: str, suffixes: set[str]) -> bool:
    labels = suffix.split(".")
    for index in range(1, len(labels)):
        parent = ".".join(labels[index:])
        if parent in suffixes:
            return True
    return False


def dedup_domain_payload(rules: list[str]) -> tuple[list[str], DedupStats]:
    stats = DedupStats(input_count=len(rules))
    unique_rules: list[str] = []
    seen: set[str] = set()
    for rule in rules:
        if rule in seen:
            stats.exact_duplicates_removed += 1
            continue
        seen.add(rule)
        unique_rules.append(rule)

    suffixes = {
        suffix
        for rule in unique_rules
        if (suffix := domain_suffix_value(rule)) is not None
    }
    output: list[str] = []
    for rule in unique_rules:
        suffix = domain_suffix_value(rule)
        if suffix is not None:
            if suffix_covered_by_parent_suffix(suffix, suffixes):
                stats.suffix_covered_by_parent_suffix += 1
                continue
        elif domain_covered_by_suffix(rule, suffixes):
            stats.domain_covered_by_suffix += 1
            continue
        output.append(rule)

    stats.output_count = len(output)
    return output, stats


def dedup_exact_rules(rules: list[str]) -> tuple[list[str], int]:
    """Stable exact-string deduplication for classical DNS-only rules."""
    seen: set[str] = set()
    output: list[str] = []
    for rule in rules:
        if rule in seen:
            continue
        seen.add(rule)
        output.append(rule)
    return output, len(rules) - len(output)


def parse_ip_network(rule: str) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(rule.strip(), strict=False)
    except ValueError:
        return None


def network_covered_by_parent(
    network: ipaddress._BaseNetwork,
    networks: set[ipaddress._BaseNetwork],
) -> bool:
    for prefix in range(network.prefixlen - 1, -1, -1):
        parent = network.supernet(new_prefix=prefix)
        if parent in networks:
            return True
    return False


def dedup_ipcidr_payload(rules: list[str]) -> tuple[list[str], DedupStats]:
    stats = DedupStats(input_count=len(rules))
    unique_rules: list[str] = []
    seen: set[str] = set()
    for rule in rules:
        if rule in seen:
            stats.ipcidr_duplicates_removed += 1
            continue
        seen.add(rule)
        unique_rules.append(rule)

    networks = {
        network
        for rule in unique_rules
        if (network := parse_ip_network(rule)) is not None
    }
    output: list[str] = []
    for rule in unique_rules:
        network = parse_ip_network(rule)
        if network is not None and network_covered_by_parent(network, networks):
            stats.ipcidr_covered_by_parent += 1
            continue
        output.append(rule)

    stats.output_count = len(output)
    return output, stats


def write_yaml_payload(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump({"payload": rules}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def read_yaml_payload(path: Path) -> list[str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("payload"), list):
        raise SystemExit(f"{path}: expected YAML payload list")
    payload: list[str] = []
    for item in data["payload"]:
        if not isinstance(item, str):
            raise SystemExit(f"{path}: payload items must be strings")
        payload.append(item)
    return payload


def write_text_payload(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rules) + "\n", encoding="utf-8")


def write_yaml_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
        prefix=f".{path.name}.",
        suffix=".tmp",
    ) as handle:
        handle.write(encoded)
        temporary = Path(handle.name)
    try:
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def write_text_atomic(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False,
        prefix=f".{path.name}.", suffix=".tmp",
    ) as handle:
        handle.write(data)
        temporary = Path(handle.name)
    try:
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def convert_source_to_mrs(mihomo: str, behavior: str, source: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            mihomo,
            "convert-ruleset",
            behavior,
            "yaml",
            str(source),
            str(output),
        ],
        check=True,
    )


def public_url(base_url: str, *parts: str) -> str:
    return "/".join([base_url.rstrip("/"), *[part.strip("/") for part in parts]])


def make_provider(
    behavior: str,
    fmt: str,
    url: str,
    path: str,
    source_provider: dict[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "http",
        "behavior": behavior,
        "format": fmt,
        "url": url,
        "path": path,
    }
    for key in ("interval", "proxy", "size-limit"):
        if key in source_provider:
            result[key] = source_provider[key]
    return result


def reserve_provider_name(name: str, suffix: str, used_names: set[str]) -> str:
    candidate = f"{name}-{suffix}"
    if candidate not in used_names:
        used_names.add(candidate)
        return candidate
    candidate = f"{name}-mrs-{suffix}"
    if candidate not in used_names:
        used_names.add(candidate)
        return candidate
    index = 2
    while True:
        candidate = f"{name}-mrs{index}-{suffix}"
        if candidate not in used_names:
            used_names.add(candidate)
            return candidate
        index += 1


def reserve_path(path: str, used_paths: set[str]) -> None:
    if path in used_paths:
        raise SystemExit(f"generated provider path collision: {path}")
    used_paths.add(path)


def generated_artifact_path(dist: Path, provider: dict[str, Any]) -> Path | None:
    url = provider.get("url")
    if not isinstance(url, str):
        return None
    marker = "/dist/"
    if marker not in url:
        return None
    relative = url.split(marker, 1)[1]
    return dist / relative


def dist_relative_from_url(url: str) -> Path | None:
    marker = "/dist/"
    if marker not in url:
        return None
    return Path(url.split(marker, 1)[1])


def suite_relative_path(relative: Path, suite: str) -> Path:
    parts = relative.parts
    if parts and parts[0] in SUITES:
        relative = Path(*parts[1:])
    return Path(suite) / relative


def provider_path_for_suite(provider_name: str, provider: dict[str, Any], suite: str) -> str:
    extension = ".mrs" if provider.get("format") == "mrs" else ".yaml"
    return f"./ruleset/{suite}/{provider_name}{extension}"


def copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def copy_tree_contents(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    for path in source.rglob("*"):
        if path.is_file():
            copy_file(path, destination / path.relative_to(source))


def source_path_for_provider(dist: Path, provider: dict[str, Any]) -> Path | None:
    behavior = provider.get("behavior")
    if behavior not in {"domain", "ipcidr"}:
        return None
    url = provider.get("url")
    if not isinstance(url, str):
        return None
    relative = dist_relative_from_url(url)
    if relative is None:
        return None
    parts = relative.parts
    source_dir = "ipcidr" if behavior == "ipcidr" else "domain"
    filename = Path(parts[-1]).with_suffix(".yaml")
    if len(parts) >= 4 and parts[0] in SUITES and parts[1] == "source":
        candidate = dist / relative
        if candidate.exists():
            return candidate
    if len(parts) >= 3 and parts[0] == "source":
        candidate = dist / relative
        if candidate.exists():
            return candidate
    if len(parts) >= 3 and parts[-3] in SUITES:
        candidate = dist / parts[-3] / "source" / source_dir / filename
        if candidate.exists():
            return candidate
    if len(parts) >= 2 and parts[0] in {"domain", "ipcidr"}:
        candidate = dist / "source" / source_dir / filename
        if candidate.exists():
            return candidate
    return None


def rewrite_provider_for_suite(
    name: str,
    provider: dict[str, Any],
    suite: str,
    base_url: str,
) -> dict[str, Any]:
    result = dict(provider)
    url = result.get("url")
    if isinstance(url, str):
        relative = dist_relative_from_url(url)
        if relative is not None:
            result["url"] = public_url(base_url, "dist", str(suite_relative_path(relative, suite)))
    result["path"] = provider_path_for_suite(name, result, suite)
    return result


def copy_provider_artifacts_to_suite(
    name: str,
    provider: dict[str, Any],
    suite: str,
    dist: Path,
) -> None:
    url = provider.get("url")
    if not isinstance(url, str):
        return
    relative = dist_relative_from_url(url)
    if relative is None:
        return
    destination_relative = suite_relative_path(relative, suite)
    source = dist / relative
    destination = dist / destination_relative
    if source.resolve() != destination.resolve() and source.exists():
        copy_file(source, destination)

    source_path = source_path_for_provider(dist, provider)
    if source_path is not None:
        source_dir = "ipcidr" if provider.get("behavior") == "ipcidr" else "domain"
        source_destination = dist / suite / "source" / source_dir / source_path.name
        if source_path.resolve() != source_destination.resolve():
            copy_file(source_path, source_destination)


def provider_source_dir(behavior: str) -> str:
    return "ipcidr" if behavior == "ipcidr" else "domain"


def publish_final_config(
    config: dict[str, Any], work_dist: Path, final_dist: Path, base_url: str
) -> dict[str, Any]:
    """Publish only artifacts referenced by the validated final config."""
    providers: dict[str, dict[str, Any]] = {}
    for name, provider in config["rule-providers"].items():
        updated = dict(provider)
        relative = dist_relative_from_url(str(provider.get("url", "")))
        if relative is not None:
            parts = relative.parts
            if parts and parts[0] == "merged-dedup":
                relative = Path(*parts[1:])
            source = work_dist / dist_relative_from_url(str(provider["url"]))
            destination = final_dist / relative
            if source.exists():
                copy_file(source, destination)
            updated["url"] = public_url(base_url, "dist", *relative.parts)
            updated["path"] = f"./ruleset/{'/'.join(relative.with_suffix('').parts)}{relative.suffix}"
        providers[name] = updated
    published = {**config, "rule-providers": providers}
    return published


def egern_segment_name(provider_name: str) -> str:
    identity = parse_legacy_provider_name(provider_name)
    return identity.segment if identity else provider_name


def loon_segment_name(provider_name: str) -> str:
    identity = parse_legacy_provider_name(provider_name)
    return identity.segment if identity else provider_name


def export_loon(*args: Any, **kwargs: Any) -> dict[str, int]:
    from .exporters.loon import export_loon as implementation
    return implementation(*args, **kwargs)


def export_egern(*args: Any, **kwargs: Any) -> dict[str, int]:
    from .exporters.egern import export_egern as implementation
    return implementation(*args, **kwargs)


def export_dns(*args: Any, **kwargs: Any) -> dict[str, int]:
    from .exporters.dns import export_dns as implementation
    return implementation(*args, **kwargs)


def collect_dns_domain_payloads(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .exporters.dns import collect_dns_domain_payloads as implementation
    return implementation(*args, **kwargs)


def classify_egern_classical(*args: Any, **kwargs: Any) -> Any:
    from .exporters.egern import classify_egern_classical as implementation
    return implementation(*args, **kwargs)


def optimize_egern_rule_set(*args: Any, **kwargs: Any) -> Any:
    from .exporters.egern import optimize_egern_rule_set as implementation
    return implementation(*args, **kwargs)


def process_provider(*args: Any, **kwargs: Any) -> ProviderResult:
    from .providers import process_provider as implementation
    return implementation(*args, **kwargs)


def _optimizer(name: str, *args: Any, **kwargs: Any) -> Any:
    from . import optimize
    return getattr(optimize, name)(*args, **kwargs)


def canonicalize_dedup_provider_names(*args: Any, **kwargs: Any) -> Any:
    return _optimizer("canonicalize_dedup_provider_names", *args, **kwargs)


def apply_segment_name_mapping(*args: Any, **kwargs: Any) -> Any:
    return _optimizer("apply_segment_name_mapping", *args, **kwargs)


def build_dedup_config(*args: Any, **kwargs: Any) -> Any:
    return _optimizer("build_dedup_config", *args, **kwargs)


def rewrite_rules(*args: Any, **kwargs: Any) -> Any:
    return _optimizer("rewrite_rules", *args, **kwargs)


def build_merged_config(*args: Any, **kwargs: Any) -> Any:
    return _optimizer("build_merged_config", *args, **kwargs)


def consolidate_segment_behavior_providers(*args: Any, **kwargs: Any) -> Any:
    return _optimizer("consolidate_segment_behavior_providers", *args, **kwargs)


def _state(name: str, *args: Any, **kwargs: Any) -> Any:
    from . import state
    return getattr(state, name)(*args, **kwargs)


def provider_fingerprint(*args: Any, **kwargs: Any) -> Any:
    return _state("provider_fingerprint", *args, **kwargs)


def build_managed_manifest(*args: Any, **kwargs: Any) -> Any:
    return _state("build_managed_manifest", *args, **kwargs)


def read_managed_manifest(*args: Any, **kwargs: Any) -> Any:
    return _state("read_managed_manifest", *args, **kwargs)


def write_managed_manifest(*args: Any, **kwargs: Any) -> Any:
    return _state("write_managed_manifest", *args, **kwargs)


def materialize_suite_config(*args: Any, **kwargs: Any) -> Any:
    return _state("materialize_suite_config", *args, **kwargs)


def main() -> None:
    from .cli import main as implementation
    implementation()


def format_percent(before: int, after: int) -> str:
    if before == 0:
        return "0.00%"
    return f"{(before - after) / before * 100:.2f}%"


def print_dedup_report(
    config: dict[str, Any],
    stats_by_provider: dict[str, DedupStats],
) -> None:
    totals = DedupStats()
    domain_before = 0
    domain_after = 0
    ip_before = 0
    ip_after = 0

    for name, stats in stats_by_provider.items():
        if name not in config["rule-providers"]:
            continue
        behavior = config["rule-providers"][name]["behavior"]
        if behavior == "ipcidr":
            ip_before += stats.input_count
            ip_after += stats.output_count
        else:
            domain_before += stats.input_count
            domain_after += stats.output_count

        totals.input_count += stats.input_count
        totals.exact_duplicates_removed += stats.exact_duplicates_removed
        totals.domain_covered_by_suffix += stats.domain_covered_by_suffix
        totals.suffix_covered_by_parent_suffix += stats.suffix_covered_by_parent_suffix
        totals.ipcidr_duplicates_removed += stats.ipcidr_duplicates_removed
        totals.ipcidr_covered_by_parent += stats.ipcidr_covered_by_parent
        totals.output_count += stats.output_count

        print(f"[{name}]")
        print(f"input: {stats.input_count}")
        if behavior == "ipcidr":
            print(f"exact duplicates removed: {stats.ipcidr_duplicates_removed}")
            print(f"subnets covered by parent: {stats.ipcidr_covered_by_parent}")
        else:
            print(f"exact duplicates removed: {stats.exact_duplicates_removed}")
            print(f"domain covered by suffix: {stats.domain_covered_by_suffix}")
            print(f"suffix covered by parent suffix: {stats.suffix_covered_by_parent_suffix}")
        print(f"output: {stats.output_count}")
        print(f"reduction: {format_percent(stats.input_count, stats.output_count)}")
        print()

    print("========== MRS Optimization Summary ==========")
    print("Before dedup:")
    print(f"Domain rules: {domain_before}")
    print(f"IPCIDR rules: {ip_before}")
    print(f"Total: {totals.input_count}")
    print()
    print("After dedup:")
    print(f"Domain rules: {domain_after}")
    print(f"IPCIDR rules: {ip_after}")
    print(f"Total: {totals.output_count}")
    print()
    print("Removed:")
    print(f"Exact duplicates: {totals.exact_duplicates_removed}")
    print(f"Domain covered by suffix: {totals.domain_covered_by_suffix}")
    print(f"Suffix covered by parent suffix: {totals.suffix_covered_by_parent_suffix}")
    print(f"IPCIDR duplicates: {totals.ipcidr_duplicates_removed}")
    print(f"IPCIDR covered by parent: {totals.ipcidr_covered_by_parent}")
    print()
    print(f"Total removed: {totals.removed}")
    print(f"Overall reduction: {format_percent(totals.input_count, totals.output_count)}")
    print("==============================================")


def referenced_rule_counts(config: dict[str, Any], dist: Path) -> Counter[str]:
    counts: Counter[str] = Counter()
    for provider in config["rule-providers"].values():
        behavior = provider.get("behavior")
        if behavior not in {"domain", "ipcidr", "classical"}:
            continue
        if behavior == "classical":
            artifact = generated_artifact_path(dist, provider)
            if artifact is not None and artifact.exists():
                counts[behavior] += len(read_yaml_payload(artifact))
            continue
        source = source_path_for_provider(dist, provider)
        if source is not None:
            counts[behavior] += len(read_yaml_payload(source))
    return counts


def suite_mrs_stats(dist: Path, suite: str) -> tuple[int, int]:
    root = dist if suite == FINAL_SUITE else dist / suite
    files = [
        path
        for folder in ("domain", "ipcidr")
        for path in (root / folder).glob("*.mrs")
    ]
    return len(files), sum(path.stat().st_size for path in files)


def print_suite_stats(
    label: str,
    suite: str,
    config: dict[str, Any],
    dist: Path,
    counts: Counter[str] | None = None,
) -> None:
    counts = counts or referenced_rule_counts(config, dist)
    mrs_count, mrs_size = suite_mrs_stats(dist, suite)
    total_rules = counts["domain"] + counts["ipcidr"] + counts["classical"]
    print(f"{label}:")
    print(f"  rules: {total_rules} (domain={counts['domain']}, ipcidr={counts['ipcidr']}, classical={counts['classical']})")
    print(f"  MRS files: {mrs_count}")
    print(f"  MRS size: {mrs_size} bytes")


def make_generated_provider(
    behavior: str,
    fmt: str,
    url: str,
    path: str,
    source_provider: dict[str, Any],
    used_paths: set[str],
) -> dict[str, Any]:
    reserve_path(path, used_paths)
    return make_provider(behavior, fmt, url, path, source_provider)


def make_merged_provider(
    behavior: str,
    fmt: str,
    url: str,
    path: str,
    source_providers: list[dict[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "http",
        "behavior": behavior,
        "format": fmt,
        "url": url,
        "path": path,
    }
    intervals = [
        provider["interval"]
        for provider in source_providers
        if isinstance(provider.get("interval"), int)
    ]
    if intervals:
        result["interval"] = min(intervals)
    for key in ("proxy", "size-limit"):
        values = [provider[key] for provider in source_providers if key in provider]
        if values and all(value == values[0] for value in values):
            result[key] = values[0]
    return result


def merge_metadata_compatible(providers: list[dict[str, Any]]) -> bool:
    for key in ("proxy", "size-limit"):
        present = [provider[key] for provider in providers if key in provider]
        if present and len(present) != len(providers):
            return False
        if len({repr(value) for value in present}) > 1:
            return False
    return True


def ruleset_parts(rule: Any) -> list[str] | None:
    if not isinstance(rule, str):
        return None
    return _ruleset_parts_in_expression(rule)


def ruleset_suffix_for_behavior(suffix: tuple[str, ...], behavior: str) -> list[str]:
    inherited = list(suffix)
    if behavior != "ipcidr":
        inherited = [part for part in inherited if part != "no-resolve"]
    return inherited


def _with_single_no_resolve(parts: list[str]) -> list[str]:
    """Add one no-resolve modifier to a RULE-SET reference."""
    head = parts[:2]
    modifiers = [item for item in parts[2:] if item.lower() != "no-resolve"]
    return [*head, *modifiers, "no-resolve"]


def normalize_no_active_resolve(
    config: dict[str, Any], payloads: dict[str, list[str]]
) -> dict[str, Any]:
    """Normalize the final Mihomo routing config to destination-IP no-resolve."""
    target_providers = {
        name
        for name, provider in config["rule-providers"].items()
        if provider_has_target_ip(provider.get("behavior", ""), payloads.get(name, []))
    }

    def rewrite_expression(expression: str) -> str:
        direct = _ruleset_parts_in_expression(expression)
        if direct is not None:
            parts = _with_single_no_resolve(direct) if direct[1] in target_providers else direct
            result = ",".join(parts)
            return f"({result})" if strip_balanced_outer_parentheses(expression)[1] else result
        inner, wrapped = strip_balanced_outer_parentheses(expression)
        parts = split_top_level_commas(inner if wrapped else expression)
        rewritten = [
            rewrite_expression(part) if strip_balanced_outer_parentheses(part)[1] else part
            for part in parts
        ]
        result = ",".join(rewritten)
        return f"({result})" if wrapped else result

    rewritten_rules: list[Any] = []
    for raw_rule in config.get("rules", []):
        if not isinstance(raw_rule, str):
            rewritten_rules.append(raw_rule)
            continue
        parsed = parse_rule(raw_rule)
        if is_target_ip_kind(parsed.kind):
            parts = split_top_level_commas(raw_rule)
            parts = [*parts[:2], *(item for item in parts[2:] if item.lower() != "no-resolve"), "no-resolve"]
            raw_rule = ",".join(parts)
        rewritten_rules.append(rewrite_expression(raw_rule))
    return {**config, "rules": rewritten_rules}


def contains_ruleset(value: Any) -> bool:
    if isinstance(value, str):
        return "RULE-SET" in value.upper()
    if isinstance(value, list):
        return any(contains_ruleset(item) for item in value)
    if isinstance(value, dict):
        return any(contains_ruleset(item) for item in value.values())
    return False


def validate_top_level_rulesets(rules: list[Any], provider_names: set[str]) -> None:
    for item in rules:
        if not isinstance(item, str):
            continue
        for name in find_ruleset_refs(item):
            if name not in provider_names:
                raise SystemExit(f"RULE-SET references missing provider {name!r} in rule: {item}")
        if find_ruleset_refs(item):
            parse_ruleset_reference(item)


def validate_generated_rulesets(rules: list[Any], provider_names: set[str]) -> None:
    validate_top_level_rulesets(rules, provider_names)


def validate_generated_artifacts(dist: Path, providers: dict[str, dict[str, Any]]) -> None:
    for name, provider in providers.items():
        artifact = generated_artifact_path(dist, provider)
        if artifact is not None and not artifact.exists():
            raise SystemExit(f"{name}: generated URL artifact does not exist: {artifact}")


def validate_unique_provider_paths(config: dict[str, Any]) -> None:
    paths: dict[str, str] = {}
    for name, provider in config["rule-providers"].items():
        path = provider.get("path")
        if not isinstance(path, str):
            continue
        if path in paths:
            raise SystemExit(f"duplicate provider path {path}: {paths[path]}, {name}")
        paths[path] = name


def validate_no_orphan_providers(config: dict[str, Any]) -> None:
    providers = set(config["rule-providers"])
    used: set[str] = set()
    for rule in config["rules"]:
        used.update(find_ruleset_refs(rule))
    orphaned = providers - used
    if orphaned:
        raise SystemExit(f"unused generated providers: {', '.join(sorted(orphaned))}")


def validate_generated_config(
    dist: Path,
    config: dict[str, Any],
    require_no_orphans: bool = True,
) -> None:
    validate_unique_provider_paths(config)
    validate_generated_rulesets(config["rules"], set(config["rule-providers"]))
    validate_generated_artifacts(dist, config["rule-providers"])
    if require_no_orphans:
        validate_no_orphan_providers(config)


def validate_rule_counts(name: str, original: Counter[str], rebuilt: Counter[str]) -> None:
    missing = original - rebuilt
    unexpected = rebuilt - original
    if missing or unexpected:
        raise SystemExit(
            f"{name}: verification failed; missing={len(missing)} unexpected={len(unexpected)}"
        )


def is_provider_from_base_suite(provider: dict[str, Any], base_url: str, suite: str) -> bool:
    url = provider.get("url")
    return isinstance(url, str) and url.startswith(
        public_url(base_url, "dist", suite) + "/"
    )


def ruleset_provider_name(rule: Any) -> str | None:
    refs = find_ruleset_refs(rule)
    return refs[0] if len(refs) == 1 else None


def refresh_complete_config(
    complete_config: dict[str, Any],
    generated_config: dict[str, Any],
    previous_manifest: dict[str, Any] | None,
    base_url: str,
) -> dict[str, Any]:
    old_providers = complete_config.get("rule-providers") or {}
    old_rules = complete_config.get("rules") or []
    new_providers = generated_config.get("rule-providers") or {}
    new_rules = generated_config.get("rules") or []

    if not isinstance(old_providers, dict) or not isinstance(old_rules, list):
        raise SystemExit("complete config must contain rule-providers mapping and rules list")
    if not isinstance(new_providers, dict) or not isinstance(new_rules, list):
        raise SystemExit("generated config must contain rule-providers mapping and rules list")

    managed_old_names: set[str] = set()
    if previous_manifest is not None:
        manifest_providers = previous_manifest.get("providers")
        if not isinstance(manifest_providers, dict):
            raise SystemExit("previous managed state missing providers mapping")
        for name, state in manifest_providers.items():
            if not isinstance(state, dict):
                raise SystemExit(f"previous managed state for {name} must be a mapping")
            provider = old_providers.get(name)
            if provider is None:
                managed_old_names.add(name)
                continue
            if not isinstance(provider, dict):
                raise SystemExit(f"{name}: managed provider definition must be a mapping")
            expected_fingerprint = state.get("fingerprint")
            if provider_fingerprint(provider) != expected_fingerprint:
                raise SystemExit(
                    f"{name}: managed provider was modified outside converter; refusing to overwrite"
                )
            managed_old_names.add(name)
    else:
        managed_old_names = {
            name
            for name, provider in old_providers.items()
            if isinstance(provider, dict)
            and isinstance(provider.get("url"), str)
            and provider["url"].startswith(public_url(base_url, "dist") + "/")
            and isinstance(provider.get("path"), str)
            and provider["path"].startswith("./ruleset/")
        }

    collisions = sorted((set(new_providers) & set(old_providers)) - managed_old_names)
    if collisions:
        raise SystemExit(
            "generated providers collide with unmanaged complete-config providers: "
            + ", ".join(collisions)
        )

    new_rulesets = [rule for rule in new_rules if find_ruleset_refs(rule)]

    refreshed = dict(complete_config)
    refreshed_providers = {
        name: provider
        for name, provider in old_providers.items()
        if name not in managed_old_names and name not in new_providers
    }
    refreshed_providers.update(new_providers)
    refreshed["rule-providers"] = refreshed_providers

    managed_rule_indexes: list[int] = []
    retained_rules: list[Any] = []
    for index, rule in enumerate(old_rules):
        refs = set(find_ruleset_refs(rule))
        managed_refs = refs & managed_old_names
        if managed_refs and refs - managed_old_names:
            raise SystemExit(
                f"cannot safely refresh rule with mixed managed and unmanaged providers: {rule}"
            )
        if managed_refs:
            managed_rule_indexes.append(index)
            continue
        retained_rules.append(rule)

    if not managed_rule_indexes and new_rulesets:
        raise SystemExit("complete config contains no previous managed RULE-SET block")
    if managed_rule_indexes:
        expected = list(range(managed_rule_indexes[0], managed_rule_indexes[-1] + 1))
        if managed_rule_indexes != expected:
            raise SystemExit("complete config managed RULE-SET block is not contiguous")
        insert_at = managed_rule_indexes[0]
    else:
        insert_at = len(retained_rules)

    refreshed["rules"] = [
        *retained_rules[:insert_at],
        *new_rulesets,
        *retained_rules[insert_at:],
    ]
    validate_generated_rulesets(refreshed["rules"], set(refreshed_providers))
    return refreshed


def write_yaml_mapping_atomic(path: Path, data: dict[str, Any]) -> None:
    write_yaml_atomic(path, data)

