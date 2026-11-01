"""The Sing-box-only part of the converter.

This module deliberately has no provider downloader or Clash pipeline.  It
serializes the already normalized payloads produced by convert.py.
"""
from __future__ import annotations

import ipaddress
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.request
from http.client import IncompleteRead

from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from ..data_sources import GEOLITE2_ASSETS, GEOLITE2_RELEASE
from ..model import Provider
from ..net import read_capped_response as _read_capped, retry_after_seconds, ssl_context
from ..rules import parse_ruleset_reference, simple_ruleset_wrapper, split_top_level_commas
from ..timing import BuildTiming, activate, current_timing, observe_external, timed
from ..views import DnsView
from .singbox_srs import canonicalize_decompiled_rules as _canonicalize_decompiled_rules
from .singbox_srs import representatives as _representatives
from .singbox_srs import semantic_matcher_equivalent as _semantic_matcher_equivalent


class SingBoxExportError(RuntimeError):
    pass


def _policy_action(policy: str, policy_map: dict[str, str] | None = None) -> dict[str, Any]:
    mapped = (policy_map or {}).get(policy, policy)
    if policy not in {"DIRECT", "REJECT", "REJECT-DROP"} and mapped in {"DIRECT", "REJECT", "REJECT-DROP"} and mapped != "DIRECT":
        raise SingBoxExportError(f"policy mapping cannot introduce intrinsic rejection policy: {policy!r} -> {mapped!r}")
    if policy in {"DIRECT", "REJECT", "REJECT-DROP"}:
        mapped = policy
    if mapped == "DIRECT":
        return {"action": "route", "outbound": "direct"}
    if mapped == "REJECT":
        return {"action": "reject"}
    if mapped == "REJECT-DROP":
        return {"action": "reject", "method": "drop"}
    if mapped in {"REJECT", "REJECT-DROP"}:
        raise SingBoxExportError(f"policy mapping cannot route intrinsic rejection policy: {policy!r} -> {mapped!r}")
    return {"action": "route", "outbound": mapped}


def _wildcard_regex(value: str) -> str:
    if not value:
        raise ValueError("empty wildcard")
    out = ""
    for char in value:
        if char == "*":
            out += ".*"
        elif char == "?":
            out += "."
        else:
            out += re.escape(char)
    return "(?i)^" + out + "$"


def _domain_value(value: str) -> tuple[str, str]:
    value = value.strip()
    if value.startswith("+."):
        return "domain_suffix", value[2:].strip(".").lower()
    if value.startswith("."):
        return "domain_regex", "(?i)^.+\\." + re.escape(value[1:].strip(".")) + "$"
    if "*" in value or "?" in value:
        return "domain_regex", _wildcard_regex(value)
    return "domain", value.rstrip(".").lower()


def _matcher(kind: str, value: str, context: str) -> tuple[str, Any]:
    kind = kind.upper()
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return _domain_value(value if kind == "DOMAIN" else "+." + value.lstrip("."))
    if kind == "DOMAIN-KEYWORD":
        return "domain_keyword", value.strip().lower()
    if kind == "DOMAIN-REGEX":
        return "domain_regex", value
    if kind == "DOMAIN-WILDCARD":
        return "domain_regex", _wildcard_regex(value)
    if kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise SingBoxExportError(f"{context}: invalid CIDR {value!r}") from exc
        return ("source_ip_cidr" if kind == "SRC-IP-CIDR" else "ip_cidr"), [str(network)]
    if kind in {"IP-ASN", "SRC-IP-ASN"}:
        raise SingBoxExportError(f"{context}: ASN expansion is required before SRS serialization ({kind})")
    if kind in {"NETWORK", "PROCESS-NAME", "PROCESS-PATH", "PROCESS-PATH-REGEX"}:
        fields = {"NETWORK": "network", "PROCESS-NAME": "process_name", "PROCESS-PATH": "process_path", "PROCESS-PATH-REGEX": "process_path_regex"}
        return fields[kind], [value.lower() if kind == "NETWORK" else value]
    if kind in {"DST-PORT", "SRC-PORT"}:
        field = "port" if kind == "DST-PORT" else "source_port"
        single: list[int] = []
        ranges: list[str] = []
        for item in value.split("/"):
            try:
                if "-" in item:
                    left, right = item.split("-", 1)
                    if not (0 <= int(left) <= int(right) <= 65535): raise ValueError
                    ranges.append(f"{int(left)}:{int(right)}")
                else:
                    number = int(item)
                    if not 0 <= number <= 65535: raise ValueError
                    single.append(number)
            except ValueError as exc:
                raise SingBoxExportError(f"{context}: invalid port {value!r}") from exc
        result: list[tuple[str, Any]] = []
        if single: result.append((field, single))
        if ranges: result.append((field + "_range", ranges))
        return result  # type: ignore[return-value]
    raise SingBoxExportError(f"{context}: unsupported matcher {kind!r}")


ASN_INDEX_VERSION = 2
ASN_INDEX_FILENAME = "asn-index-v2.json"
DNS_MATCHER_FIELDS = {"domain", "domain_suffix", "domain_keyword", "domain_regex"}
CLASSICAL_KINDS = frozenset({
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD",
    "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "NETWORK", "PROCESS-NAME", "PROCESS-PATH",
    "PROCESS-PATH-REGEX", "DST-PORT", "SRC-PORT", "IP-ASN", "SRC-IP-ASN",
})

def _default_asn_resolver(asns: set[str]) -> dict[str, list[str]]:
    """Resolve ASN to CIDRs only for this exporter; never mutates main IR."""
    context = ssl_context()
    timing = current_timing()
    result: dict[str, list[str]] = {asn: [] for asn in asns}
    def download(url: str) -> bytes:
        data = bytearray()
        for attempt in range(4):
            headers = {"User-Agent": "mihomo-mrs-converter"}
            if data: headers["Range"] = f"bytes={len(data)}-"
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers=headers), context=context, timeout=60) as response:
                    if data and response.status != 206: raise SingBoxExportError("ASN server ignored HTTP Range resume")
                    expected = response.headers.get("Content-Length")
                    expected_total = len(data) + int(expected) if expected else None
                    remaining = 128 * 1024 * 1024 - len(data)
                    data.extend(_read_capped(response, remaining, url))
                if expected_total is None or len(data) >= expected_total: return bytes(data)
            except IncompleteRead as exc:
                data.extend(exc.partial)
            except urllib.error.HTTPError as exc:
                if exc.code not in {408, 429, 500, 502, 503, 504} or attempt == 3:
                    raise SingBoxExportError(f"ASN database download failed: HTTP {exc.code}") from exc
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                delay = min(retry_after_seconds(retry_after), 8.0) if retry_after else 2 ** attempt
                time.sleep(delay)
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                if attempt == 3:
                    raise SingBoxExportError("ASN database download failed after 4 attempts")
                time.sleep(2 ** attempt)
            if attempt == 3: raise SingBoxExportError("ASN database download remained incomplete")
        raise SingBoxExportError("ASN database download failed")

    cache_root = Path(os.environ.get("GEOLITE2_CACHE_DIR", ".cache/geolite2")) / GEOLITE2_RELEASE
    index_path = cache_root / ASN_INDEX_FILENAME
    manifest = {asset["name"]: asset["sha256"] for asset in GEOLITE2_ASSETS}

    def valid_metadata(value: Any) -> dict[str, Any] | None:
        if not isinstance(value, dict) or value.get("version") != ASN_INDEX_VERSION or value.get("release") != GEOLITE2_RELEASE:
            return None
        if value.get("assets") != manifest or not isinstance(value.get("asns"), dict):
            return None
        return value

    def requested_entries(value: dict[str, Any]) -> tuple[dict[str, list[str]], set[str]]:
        """Validate only entries that will be used by this route."""
        entries = value["asns"]
        valid: dict[str, list[str]] = {}
        missing: set[str] = set()
        for asn in asns:
            networks = entries.get(asn)
            if not isinstance(asn, str) or not asn.isdigit() or not isinstance(networks, list) or not networks:
                missing.add(asn)
                continue
            normalized: list[str] = []
            try:
                for network in networks:
                    if not isinstance(network, str):
                        raise ValueError
                    normalized.append(str(ipaddress.ip_network(network, strict=False)))
            except (TypeError, ValueError):
                missing.add(asn)
                continue
            valid[asn] = list(dict.fromkeys(normalized))
        return valid, missing

    sparse_index: dict[str, list[str]] = {}
    cache_valid = False
    cache_file_bytes = 0
    if index_path.exists():
        try:
            with timed("Sing-box ASN cache file read"):
                cache_file = index_path.read_text(encoding="utf-8")
            cache_file_bytes = len(cache_file.encode("utf-8"))
            with timed("Sing-box ASN cache JSON parse"):
                cache_value = json.loads(cache_file)
            sparse_value = valid_metadata(cache_value)
            if sparse_value is not None:
                cache_valid = True
                sparse_index = sparse_value["asns"]
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            cache_valid = False

    cached: dict[str, list[str]] = {}
    missing: set[str] = set(asns)
    if cache_valid:
        with timed("Sing-box ASN requested-entry validation"):
            cached, missing = requested_entries({"asns": sparse_index})
        if not missing:
            if timing is not None:
                timing.notes["GeoLite2 assets"] = "sparse index hit; raw assets not reopened"
                timing.notes["ASN cache"] = f"requested ASNs: {len(asns)}, cache hits: {len(cached)}, cache misses: 0"
                timing.notes["ASN index"] = f"hit, {cache_file_bytes} bytes"
            return cached

    if timing is not None:
        timing.notes["ASN cache"] = f"requested ASNs: {len(asns)}, cache hits: {len(cached)}, cache misses: {len(missing)}"

    new_entries: dict[str, list[str]] = {asn: [] for asn in missing}
    rows_scanned = 0
    matched_rows = 0
    cache_hits = 0
    downloads = 0
    for asset in GEOLITE2_ASSETS:
        cache_path = cache_root / asset["name"]
        raw = None
        if cache_path.exists():
            with timed(f"Sing-box ASN asset read {asset['name']}"):
                candidate = cache_path.read_bytes()
            with timed(f"Sing-box ASN checksum {asset['name']}"):
                valid = hashlib.sha256(candidate).hexdigest() == asset["sha256"]
            if valid:
                raw = candidate
                cache_hits += 1
            else:
                cache_path.unlink()
        if raw is None:
            with timed(f"Sing-box ASN asset read/download {asset['name']}"):
                raw = download(asset["url"])
            downloads += 1
        with timed(f"Sing-box ASN checksum {asset['name']}"):
            actual_sha256 = hashlib.sha256(raw).hexdigest()
        if actual_sha256 != asset["sha256"]:
            raise SingBoxExportError(
                f"GeoLite2 asset checksum mismatch for {asset['name']}: "
                f"expected {asset['sha256']}, got {actual_sha256}"
            )
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        if not cache_path.exists():
            cache_path.write_bytes(raw)
        matched_networks: list[tuple[str, str]] = []
        with timed(f"Sing-box ASN CSV scan {asset['name']}"):
            for row in csv.DictReader(io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")):
                rows_scanned += 1
                asn = row.get("autonomous_system_number")
                if asn not in missing or not row.get("network"):
                    continue
                matched_rows += 1
                matched_networks.append((asn, row["network"]))
        with timed("Sing-box ASN matched CIDR parse"):
            for asn, network in matched_networks:
                new_entries[asn].append(str(ipaddress.ip_network(network, strict=False)))
    cache_root.mkdir(parents=True, exist_ok=True)
    retained_entries = {asn: networks for asn, networks in sparse_index.items() if asn not in missing}
    index_payload = {
        "version": ASN_INDEX_VERSION,
        "release": GEOLITE2_RELEASE,
        "assets": {asset["name"]: asset["sha256"] for asset in GEOLITE2_ASSETS},
        "asns": {
            asn: list(dict.fromkeys(retained_entries.get(asn, []) + new_entries.get(asn, [])))
            for asn in sorted(set(retained_entries) | set(new_entries))
        },
    }
    with timed("Sing-box ASN cache write"):
        temporary = index_path.with_name(f".{index_path.name}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(index_payload, handle, ensure_ascii=False, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, index_path)
        finally:
            temporary.unlink(missing_ok=True)
    if timing is not None:
        timing.notes["GeoLite2 assets"] = f"{cache_hits} cache hits / {downloads} downloads"
        timing.notes["ASN index"] = f"sparse cache, {index_path.stat().st_size} bytes"
        timing.notes["ASN CSV"] = f"rows scanned: {rows_scanned}, matched rows: {matched_rows}, new ASNs: {len(new_entries)}"
    result = {asn: list(retained_entries.get(asn, []) + new_entries.get(asn, [])) for asn in asns}
    result = {asn: list(dict.fromkeys(networks)) for asn, networks in result.items()}
    missing_asns = sorted(asn for asn, networks in result.items() if not networks)
    if missing_asns:
        raise SingBoxExportError("ASN database has no prefix for: " + ", ".join(missing_asns))
    return result



def collect_required_asns(providers: Iterable[Provider]) -> set[str]:
    """Return the ASNs that classical payloads need expanded before compiling."""
    required: set[str] = set()
    for provider in providers:
        if provider.behavior.value != "classical":
            continue
        for rule in provider.payload:
            if rule.kind in {"IP-ASN", "SRC-IP-ASN"} and len(rule.parts) > 1:
                required.add(rule.parts[1])
    return required


def _append_matcher(result: list[dict[str, Any]], parsed: Any) -> None:
    if isinstance(parsed, list):
        for field, value in parsed:
            result.append({field: value})
        return
    field, value = parsed
    result.append({field: value if isinstance(value, list) else [value]})


def _payload_matchers(provider: Provider, asn_map: dict[str, list[str]]) -> list[dict[str, Any]]:
    """Convert one typed provider payload into Sing-box matcher objects."""
    result: list[dict[str, Any]] = []
    behavior = provider.behavior.value
    for number, entry in enumerate(provider.payload):
        context = f"provider {provider.name} payload[{number}] raw={entry.as_rule()!r}"
        if behavior == "domain":
            field, value = _domain_value(entry.as_rule())
            result.append({field: [value]})
            continue
        if behavior == "ipcidr":
            result.append({"ip_cidr": [str(entry.network)]})
            continue
        rule = entry
        if len(rule.parts) < 2:
            raise SingBoxExportError(f"{context}: missing matcher value")
        if rule.kind in {"IP-ASN", "SRC-IP-ASN"}:
            kind = "SRC-IP-CIDR" if rule.kind == "SRC-IP-ASN" else "IP-CIDR"
            for network in asn_map.get(rule.parts[1], []):
                _append_matcher(result, _matcher(kind, network, context))
            continue
        if rule.kind not in CLASSICAL_KINDS:
            raise SingBoxExportError(f"{context}: unsupported classical rule kind {rule.kind!r}")
        # Sing-box does not actively resolve domains for destination-IP
        # matching, so every matcher belongs to the same logical artifact.
        _append_matcher(result, _matcher(rule.kind, rule.parts[1], context))
    return result


def _aggregate(matchers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Only destination matcher families are OR-safe to combine.  Every other
    # matcher remains its own object, preventing accidental IP AND port rules.
    destination = {"domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"}
    result: list[dict[str, Any]] = []
    bucket: dict[str, list[Any]] = {}
    for matcher in matchers:
        if set(matcher) <= destination:
            for field, values in matcher.items():
                bucket.setdefault(field, []).extend(values)
        else:
            result.append(matcher)
    if bucket:
        result.insert(0, {field: list(dict.fromkeys(values)) for field, values in bucket.items()})
    return result


def _groups(optimized: Any) -> list[dict[str, Any]]:
    """Group contiguous RULE-SET occurrences by segment identity.

    ``no-resolve`` changes Mihomo semantics but not Sing-box destination-IP
    semantics, and the segment identity is explicit, so neither can split or
    merge a logical group.
    """
    groups: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    segments_by_provider = optimized.provider_segments()
    for index, raw in enumerate(optimized.rules):
        wrapper = simple_ruleset_wrapper(raw)
        if wrapper is None:
            current = None
            continue
        reference = parse_ruleset_reference(raw)
        if reference is None:
            current = None
            continue
        provider = wrapper[0][1]
        segment = segments_by_provider.get(provider)
        if segment is None:
            raise SingBoxExportError(f"RULE-SET {provider!r} has no segment identity")
        key = (reference.policy, reference.wrapper_kind, segment)
        if current is None or current["key"] != key:
            current = {
                "id": f"group-{len(groups) + 1:02d}",
                "key": key,
                "tag": segment,
                "policy": reference.policy,
                "wrapper": reference.wrapper_kind,
                "providers": [],
                "indexes": [],
            }
            groups.append(current)
        current["providers"].append(provider)
        current["indexes"].append(index)
    return groups


def _subrule_actions(sub_rules: dict[str, Any], name: str, policy_map: dict[str, str] | None = None) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    members = sub_rules.get(name)
    if members is None:
        raise SingBoxExportError(f"SUB-RULE {name!r} is not defined")
    actions: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for index, raw in enumerate(members):
        parts = split_top_level_commas(raw)
        if len(parts) == 3 and parts[0].upper() == "NETWORK" and parts[1].upper() in {"TCP", "UDP"}:
            actions.append(({"network": [parts[1].lower()]}, _policy_action(parts[2], policy_map)))
        elif len(parts) == 2 and parts[0].upper() == "MATCH":
            if index != len(members) - 1:
                raise SingBoxExportError(f"sub-rules[{name!r}][{index}]: MATCH must be the terminal member")
            actions.append(({}, _policy_action(parts[1], policy_map)))
        else:
            raise SingBoxExportError(f"sub-rules[{name!r}][{index}]: unsupported member {raw!r}")
    if not actions or actions[-1][0]:
        raise SingBoxExportError(f"SUB-RULE {name!r} has no terminal MATCH")
    return actions


def _route_rules(
    optimized: Any,
    groups: list[dict[str, Any]],
    group_rules: dict[str, dict[str, Any]],
    policy_map: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    by_index = {index: group for group in groups for index in group["indexes"]}
    rules: list[dict[str, Any]] = []
    final: str | None = None
    for index, raw in enumerate(optimized.rules):
        if not isinstance(raw, str):
            raise SingBoxExportError(f"rules[{index}]: rule must be a string")
        parts = split_top_level_commas(raw)
        kind = parts[0].upper() if parts else ""
        if kind == "MATCH":
            if index != len(optimized.rules) - 1 or len(parts) != 2:
                raise SingBoxExportError(f"rules[{index}]: MATCH must be terminal and have one policy")
            action = _policy_action(parts[1], policy_map)
            if action["action"] == "route":
                final = action["outbound"]
            else:
                rules.append(action)
            continue
        group = by_index.get(index)
        if group is not None:
            if index != group["indexes"][0]:
                continue
            actions = (
                _subrule_actions(optimized.sub_rules, group["policy"], policy_map)
                if group["wrapper"] == "SUB-RULE"
                else [({}, _policy_action(group["policy"], policy_map))]
            )
            artifact_tag = group_rules[group["id"]]["tag"]
            for extra, action in actions:
                rules.append({"rule_set": [artifact_tag], **extra, **action})
            continue
        if kind == "NETWORK" and len(parts) == 3 and parts[1].upper() in {"TCP", "UDP"}:
            rules.append({"network": [parts[1].lower()], **_policy_action(parts[2], policy_map)})
            continue
        if kind == "RULE-SET":
            raise SingBoxExportError(f"rules[{index}]: RULE-SET was not assigned a segment")
        if len(parts) < 3:
            raise SingBoxExportError(f"rules[{index}]: malformed top-level rule {raw!r}")
        policy_index = len(parts) - 1
        modifiers: list[str] = []
        # Current project format places modifiers after the policy.
        while policy_index > 1 and parts[policy_index].lower() in {"no-resolve", "src"}:
            modifiers.insert(0, parts[policy_index])
            policy_index -= 1
        policy = parts[policy_index]
        if any(item.lower() not in {"no-resolve", "src"} for item in modifiers):
            raise SingBoxExportError(f"rules[{index}]: unsupported modifier in {raw!r}")
        matcher_parts = parts[:policy_index]
        if not policy or len(matcher_parts) < 2:
            raise SingBoxExportError(f"rules[{index}]: malformed top-level rule {raw!r}")
        for field, value in _matcher_objects(matcher_parts[0].upper(), ",".join(matcher_parts[1:]), f"rules[{index}]"):
            rules.append({field: value, **_policy_action(policy, policy_map)})
    return rules, final


def _matcher_objects(kind: str, value: str, context: str) -> list[tuple[str, Any]]:
    parsed = _matcher(kind, value, context)
    if isinstance(parsed, list):
        return list(parsed)
    field, parsed_value = parsed
    return [(field, parsed_value if isinstance(parsed_value, list) else [parsed_value])]


def _compile_and_verify(
    sing_box: str,
    tag: str,
    source_rules: list[dict[str, Any]],
    stage: Path,
    source_dir: Path,
    binary_dir: Path,
    dns_only: bool = False,
) -> Path:
    """Compile one rule set and prove the binary matches its source semantics."""
    label = "DNS" if dns_only else "route"
    source = source_dir / f"{tag}.json"
    source.write_text(
        json.dumps({"version": 2, "rules": source_rules}, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    binary = binary_dir / f"{tag}.srs"
    observe_external("sing-box", f"compile {label} {tag}", subprocess.run, [sing_box, "rule-set", "compile", str(source), "-o", str(binary)], check=True, capture_output=True, text=True)
    decompiled = stage / f"{tag}.decompiled.json"
    observe_external("sing-box", f"decompile {label} {tag}", subprocess.run, [sing_box, "rule-set", "decompile", str(binary), "-o", str(decompiled)], check=True, capture_output=True, text=True)
    decoded = json.loads(decompiled.read_text(encoding="utf-8"))
    decompiled_rules = decoded.get("rules", [])
    if dns_only:
        if any(set(rule) - DNS_MATCHER_FIELDS for rule in _canonicalize_decompiled_rules(decompiled_rules)):
            raise SingBoxExportError(f"DNS {tag}: decompiled SRS contains a non-domain matcher")
    elif not _semantic_matcher_equivalent(source_rules, decompiled_rules):
        raise SingBoxExportError(f"artifact {tag}: source/decompiled matcher mismatch")
    for probe in _representatives(source_rules):
        source_match = observe_external("sing-box", f"match {label} source {tag}", subprocess.run, [sing_box, "rule-set", "match", "-f", "source", str(source), probe], capture_output=True, text=True)
        binary_match = observe_external("sing-box", f"match {label} binary {tag}", subprocess.run, [sing_box, "rule-set", "match", "-f", "binary", str(binary), probe], capture_output=True, text=True)
        if (source_match.returncode == 0) != (binary_match.returncode == 0):
            raise SingBoxExportError(f"artifact {tag}: source/binary semantic mismatch for {probe!r}")
    return binary


def export_singbox_dns(
    views: Mapping[str, DnsView], output_dist: Path, sing_box: str | None
) -> dict[str, Any]:
    """Compile the shared normalized DNS domain view into pure domain SRS files."""
    if not sing_box:
        raise SingBoxExportError("sing-box binary not found; DNS SRS output requires sing-box")
    stage = Path(tempfile.mkdtemp(prefix="singbox-dns-export-", dir=output_dist.parent))
    try:
        source_dir, binary_dir = stage / "source", stage / "dns"
        source_dir.mkdir(); binary_dir.mkdir()
        result: dict[str, Any] = {"groups": {}, "srs": []}

        def process_group(group: str) -> tuple[str, str, dict[str, int], BuildTiming]:
            sub_timing = BuildTiming()
            with activate(sub_timing):
                view = views[group]
                matchers: list[dict[str, Any]] = []
                for entry in view.domains:
                    field, value = _domain_value(entry.as_rule())
                    matchers.append({field: [value]})
                for number, rule in enumerate(view.classical):
                    if len(rule.parts) < 2:
                        raise SingBoxExportError(f"DNS {group} classical[{number}]: missing matcher value")
                    field, value = _matcher(rule.kind, rule.parts[1], f"DNS {group} classical[{number}]")
                    matchers.append({field: [value]})
                source_rules = _aggregate(matchers)
                if not source_rules:
                    raise SingBoxExportError(f"DNS {group}: generated empty SRS")
                binary = _compile_and_verify(
                    sing_box, f"{group}-domain", source_rules, stage, source_dir, binary_dir, dns_only=True
                )
                target = output_dist / "dns" / "singbox"
                target.mkdir(parents=True, exist_ok=True)
                shutil.copy2(binary, target / binary.name)
                stats = {"domain": len(view.domains), "classical-domain": len(view.classical)}
            return group, binary.name, stats, sub_timing

        dns_workers = int(os.environ.get("CONVERTER_SINGBOX_WORKERS", str(min(2, max(1, os.cpu_count() or 1)))))
        group_list = list(views)
        if len(group_list) <= 1 or dns_workers <= 1:
            completed_dns = [process_group(group) for group in group_list]
        else:
            with ThreadPoolExecutor(max_workers=min(dns_workers, len(group_list)), thread_name_prefix="sb-dns") as pool:
                completed_dns = list(pool.map(process_group, group_list))

        timing = current_timing()
        for group, binary_name, stats, sub_timing in completed_dns:
            if timing is not None:
                timing.merge(sub_timing)
            result["groups"][group] = stats
            result["srs"].append(binary_name)
        return result
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def export_singbox(
    optimized: Any,
    output_dist: Path,
    base_url: str,
    sing_box: str | None,
    asn_resolver: Callable[[set[str]], dict[str, list[str]]] | None = None,
    policy_map: dict[str, str] | None = None,
) -> dict[str, Any]:
    if not sing_box:
        raise SingBoxExportError("sing-box binary not found; install Sing-box and retry")
    route_started = time.perf_counter()
    with timed("Sing-box group discovery"):
        groups = _groups(optimized)
    if not groups:
        raise SingBoxExportError("no RULE-SET segments available for Sing-box export")
    providers = optimized.provider_map()
    selected = [providers[name] for group in groups for name in group["providers"]]
    with timed("Sing-box ASN discovery"):
        required_asns = collect_required_asns(selected)
    timing = current_timing()
    if timing is not None:
        timing.notes["ASN required"] = f"{len(required_asns)} unique ASNs"
        timing.notes["ASN resolver calls"] = "1" if required_asns else "0"
    asn_map: dict[str, list[str]] = {}
    if required_asns:
        resolver = asn_resolver or _default_asn_resolver
        with timed("Sing-box ASN cache/index lookup"):
            asn_map = resolver(required_asns)
        missing_asns = sorted(asn for asn in required_asns if not asn_map.get(asn))
        if missing_asns:
            raise SingBoxExportError("ASN resolver returned no prefix for: " + ", ".join(missing_asns))
    stage = Path(tempfile.mkdtemp(prefix="singbox-export-", dir=output_dist.parent))
    try:
        source_dir, binary_dir = stage / "source", stage / "singbox"
        source_dir.mkdir(); binary_dir.mkdir()
        group_rules: dict[str, dict[str, Any]] = {}
        artifacts: list[tuple[str, list[dict[str, Any]]]] = []
        used_artifact_tags: set[str] = set()
        for group in groups:
            with timed("Sing-box matcher conversion"):
                matchers: list[dict[str, Any]] = []
                for provider in group["providers"]:
                    matchers.extend(_payload_matchers(providers[provider], asn_map))
            with timed("Sing-box aggregation"):
                source_rules = _aggregate(matchers)
            if not source_rules:
                raise SingBoxExportError(f"segment {group['tag']}: generated empty SRS")
            artifact_tag = group["tag"]
            if artifact_tag in used_artifact_tags:
                collision = 2
                while f"{artifact_tag}-{collision}" in used_artifact_tags:
                    collision += 1
                artifact_tag = f"{artifact_tag}-{collision}"
            used_artifact_tags.add(artifact_tag)
            group_rules[group["id"]] = {"tag": artifact_tag, "rules": source_rules}
            artifacts.append((artifact_tag, source_rules))

        def process_artifact(item: tuple[str, list[dict[str, Any]]]) -> tuple[str, float, BuildTiming]:
            artifact_tag, source_rules = item
            artifact_timing = BuildTiming()
            artifact_started = time.perf_counter()
            with activate(artifact_timing):
                _compile_and_verify(sing_box, artifact_tag, source_rules, stage, source_dir, binary_dir)
            elapsed = time.perf_counter() - artifact_started
            return artifact_tag, elapsed, artifact_timing

        num_workers = max(1, min(8, int(os.environ.get("CONVERTER_SINGBOX_WORKERS", "1"))))
        artifact_times: dict[str, float] = {}

        def record(tag: str, elapsed: float, sub_timing: BuildTiming) -> None:
            artifact_times[tag] = elapsed
            active = current_timing()
            if active is not None:
                active.merge(sub_timing)
                active.phases[f"Sing-box artifact {tag}"] = elapsed

        if len(artifacts) <= 1 or num_workers <= 1:
            for item in artifacts:
                record(*process_artifact(item))
        else:
            with ThreadPoolExecutor(max_workers=min(num_workers, len(artifacts)), thread_name_prefix="sb-artifact") as pool:
                # Maintain deterministic order of results
                for tag, elapsed, sub_timing in pool.map(process_artifact, artifacts):
                    record(tag, elapsed, sub_timing)

        with timed("Sing-box route generation"):
            route_rules, final = _route_rules(optimized, groups, group_rules, policy_map)
        route: dict[str, Any] = {"route": {"rule_set": [{"type": "remote", "tag": tag, "format": "binary", "url": f"{base_url.rstrip('/')}/dist/singbox/{tag}.srs", "update_interval": "2d"} for tag, _source_rules in artifacts], "rules": route_rules}}
        if final is not None:
            route["route"]["final"] = final
        target_dir = output_dist / "singbox"
        target_dir.mkdir(parents=True, exist_ok=True)
        for stale in target_dir.glob("*.srs"):
            stale.unlink()
        with timed("Sing-box canonical SRS copy"):
            for binary in sorted(binary_dir.glob("*.srs")):
                shutil.copy2(binary, target_dir / binary.name)
        (output_dist / "generated").mkdir(parents=True, exist_ok=True)
        with timed("Sing-box source JSON write"):
            (output_dist / "generated" / "singbox-rules.json").write_text(
                json.dumps(route, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
            )
        timing = current_timing()
        if timing is not None:
            timing.phases["Sing-box route total"] = time.perf_counter() - route_started
            for artifact_tag, elapsed in artifact_times.items():
                print(f"Sing-box {artifact_tag}: {elapsed:.2f}s")
        return {
            "segments": len(groups),
            "srs": [tag + ".srs" for tag, _source_rules in artifacts],
            "route": route,
        }
    finally:
        shutil.rmtree(stage, ignore_errors=True)
