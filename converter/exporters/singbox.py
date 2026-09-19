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
from contextlib import nullcontext
import urllib.error
import urllib.request
from http.client import IncompleteRead

from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .dns import collect_dns_domain_payloads
from ..rules import DNS_DOMAIN_KINDS, parse_rule, parse_ruleset_reference, simple_ruleset_wrapper, split_top_level_commas
from ..model import parse_provider_identity
from ..net import read_capped_response as _read_capped, retry_after_seconds, ssl_context
from ..data_sources import GEOLITE2_ASSETS, GEOLITE2_RELEASE
from ..timing import current_timing, observe_external
from .singbox_asn import ASN_INDEX_FILENAME, ASN_INDEX_VERSION
from .singbox_asn import collect_required_asns as _collect_required_asns
from .singbox_srs import canonicalize_decompiled_rules as _canonicalize_decompiled_rules
from .singbox_srs import representatives as _representatives
from .singbox_srs import semantic_matcher_equivalent as _semantic_matcher_equivalent


class SingBoxExportError(RuntimeError):
    pass


def _timed(name: str):
    timing = current_timing()
    return timing.phase(name) if timing is not None else nullcontext()


def _github_api_json(url: str) -> Any:
    """Fetch GitHub REST metadata, authenticating only api.github.com."""
    parsed = urlparse(url)
    headers = {
        "User-Agent": "mihomo-mrs-converter",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token and parsed.hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    context = ssl_context()
    max_attempts = 4
    retryable_statuses = {408, 429, 500, 502, 503, 504}
    for attempt in range(max_attempts):
        try:
            with urllib.request.urlopen(request, context=context, timeout=60) as response:
                return json.loads(_read_capped(response, 4 * 1024 * 1024, url))
        except urllib.error.HTTPError as exc:
            remaining = exc.headers.get("X-RateLimit-Remaining") if exc.headers else None
            reset = exc.headers.get("X-RateLimit-Reset") if exc.headers else None
            rate_limited = exc.code == 429 or (exc.code == 403 and remaining == "0")
            if rate_limited:
                detail = f"status={exc.code}, remaining={remaining or 'unknown'}, reset={reset or 'unknown'}"
                raise SingBoxExportError(f"GitHub API rate limit exceeded ({detail})") from exc
            if exc.code not in retryable_statuses or attempt == max_attempts - 1:
                raise SingBoxExportError(
                    f"GitHub API request failed: HTTP {exc.code} on attempt {attempt + 1}/{max_attempts}"
                ) from exc
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            delay = min(retry_after_seconds(retry_after), 8.0) if retry_after else 2 ** attempt
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if attempt == max_attempts - 1:
                raise SingBoxExportError(
                    f"GitHub API request failed: {type(exc).__name__} on attempt {attempt + 1}/{max_attempts}"
                ) from exc
            time.sleep(2 ** attempt)
    raise SingBoxExportError("GitHub API request failed")


def _policy_action(policy: str) -> dict[str, Any]:
    if policy == "DIRECT":
        return {"action": "route", "outbound": "direct"}
    if policy == "REJECT":
        return {"action": "reject"}
    if policy == "REJECT-DROP":
        return {"action": "reject", "method": "drop"}
    return {"action": "route", "outbound": policy}


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


def _default_asn_resolver(asns: set[str]) -> dict[str, list[str]]:
    """Resolve ASN to CIDRs only for this exporter; never mutates main IR."""
    context = ssl_context()
    timing = current_timing()
    result = {asn: [] for asn in asns}
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
            with _timed("Sing-box ASN cache file read"):
                cache_file = index_path.read_text(encoding="utf-8")
            cache_file_bytes = len(cache_file.encode("utf-8"))
            with _timed("Sing-box ASN cache JSON parse"):
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
        with _timed("Sing-box ASN requested-entry validation"):
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
            with _timed(f"Sing-box ASN asset read {asset['name']}"):
                candidate = cache_path.read_bytes()
            with _timed(f"Sing-box ASN checksum {asset['name']}"):
                valid = hashlib.sha256(candidate).hexdigest() == asset["sha256"]
            if valid:
                raw = candidate
                cache_hits += 1
            else:
                cache_path.unlink()
        if raw is None:
            with _timed(f"Sing-box ASN asset read/download {asset['name']}"):
                raw = download(asset["url"])
            downloads += 1
        with _timed(f"Sing-box ASN checksum {asset['name']}"):
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
        with _timed(f"Sing-box ASN CSV scan {asset['name']}"):
            for row in csv.DictReader(io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")):
                rows_scanned += 1
                asn = row.get("autonomous_system_number")
                if asn not in missing or not row.get("network"):
                    continue
                matched_rows += 1
                matched_networks.append((asn, row["network"]))
        with _timed("Sing-box ASN matched CIDR parse"):
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
    with _timed("Sing-box ASN cache write"):
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
    missing = sorted(asn for asn, networks in result.items() if not networks)
    if missing:
        raise SingBoxExportError("ASN database has no prefix for: " + ", ".join(missing))
    return result


def _provider_matchers(name: str, behavior: str, payload: list[str], asn_resolver: Callable[[set[str]], dict[str, list[str]]]) -> list[tuple[str, dict[str, Any]]]:
    result: list[tuple[str, dict[str, Any]]] = []
    for number, raw in enumerate(payload):
        context = f"provider {name} payload[{number}] raw={raw!r}"
        rule = parse_rule(raw)
        if behavior == "domain":
            field, value = _domain_value(raw)
            result.append(("base", {field: [value]}))
            continue
        if behavior == "ipcidr":
            field, value = _matcher("IP-CIDR", raw, context)
            result.append(("base", {field: value}))
            continue
        if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD", "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "NETWORK", "PROCESS-NAME", "PROCESS-PATH", "PROCESS-PATH-REGEX", "DST-PORT", "SRC-PORT", "IP-ASN", "SRC-IP-ASN"}:
            if len(rule.parts) < 2:
                raise SingBoxExportError(f"{context}: missing matcher value")
            if rule.kind in {"IP-ASN", "SRC-IP-ASN"}:
                raise SingBoxExportError(f"{context}: ASN expansion must be performed before serialization")
            parsed = _matcher(rule.kind, rule.parts[1], context)
            # Sing-box does not actively resolve domains for destination-IP
            # matching. Keep all matchers in the same logical artifact.
            bucket = "base"
            if isinstance(parsed, list):
                for field, value in parsed: result.append((bucket, {field: value}))
            else:
                field, value = parsed
                result.append((bucket, {field: value if isinstance(value, list) else [value]}))
            continue
        raise SingBoxExportError(f"{context}: unsupported classical rule kind {rule.kind!r}")
    return result


def _aggregate(matchers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Only destination matcher families are OR-safe to combine.  Every other
    # matcher remains its own object, preventing accidental IP AND port rules.
    destination = {"domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"}
    result: list[dict[str, Any]] = []
    bucket: dict[str, list[Any]] = {}
    for matcher in matchers:
        if set(matcher) <= destination:
            for field, values in matcher.items(): bucket.setdefault(field, []).extend(values)
        else:
            result.append(matcher)
    if bucket:
        result.insert(0, {field: list(dict.fromkeys(values)) for field, values in bucket.items()})
    return result


def _aggregate_buckets(matchers: list[tuple[str, dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    values = [matcher for _bucket, matcher in matchers]
    return {"base": _aggregate(values)} if values else {}


def _groups(config: dict[str, Any], segment_names: dict[str, str] | None = None) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    occurrence: dict[tuple[str, tuple[str, ...], str], int] = {}
    for index, raw in enumerate(config.get("rules", [])):
        wrapper = simple_ruleset_wrapper(raw)
        if wrapper is None:
            current = None
            continue
        reference = parse_ruleset_reference(raw)
        assert reference is not None
        provider = wrapper[0][1]
        # no-resolve changes Mihomo semantics, but not Sing-box destination-IP
        # semantics.  Do not let it split an otherwise identical logical
        # segment or create a separate artifact.
        logical_modifiers = tuple(item for item in reference.modifiers if item.lower() != "no-resolve")
        key = (reference.policy, logical_modifiers, reference.wrapper_kind)
        if current is None or current["key"] != key:
            occurrence[key] = occurrence.get(key, 0) + 1
            ordinal = occurrence[key]
            # Provider names are the canonical identity after convert.py has
            # merged and applied segment-names.yaml (e.g. China-ip-part-02).
            # Do not derive identity from policy occurrence: Direct and China
            # may both route DIRECT while remaining distinct logical segments.
            identity = parse_provider_identity(provider)
            base = identity.segment if identity else None
            if base in (segment_names or {}):
                base = segment_names[base]
            if base and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", base):
                # Keep the logical group identity free of no-resolve, which
                # has no distinct Sing-box destination-IP semantics.
                tag = base
            else:
                tag = f"segment-{len(groups) + 1:02d}-{ordinal:02d}"
            current = {"id": f"group-{len(groups) + 1:02d}", "key": key, "tag": tag, "policy": reference.policy, "wrapper": reference.wrapper_kind, "providers": [], "indexes": []}
            groups.append(current)
        current["providers"].append(provider)
        current["indexes"].append(index)
    return groups


def _subrule_actions(config: dict[str, Any], name: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    members = (config.get("sub-rules") or {}).get(name)
    if members is None:
        raise SingBoxExportError(f"SUB-RULE {name!r} is not defined")
    actions: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for index, raw in enumerate(members):
        parts = split_top_level_commas(raw)
        if len(parts) == 3 and parts[0].upper() == "NETWORK" and parts[1].upper() in {"TCP", "UDP"}:
            actions.append(({"network": [parts[1].lower()]}, _policy_action(parts[2])))
        elif len(parts) == 2 and parts[0].upper() == "MATCH":
            actions.append(({}, _policy_action(parts[1])))
        else:
            raise SingBoxExportError(f"sub-rules[{name!r}][{index}]: unsupported member {raw!r}")
    if not actions or not any(not match for match, _ in actions):
        raise SingBoxExportError(f"SUB-RULE {name!r} has no terminal MATCH")
    return actions


def _route_rules(config: dict[str, Any], groups: list[dict[str, Any]], group_buckets: dict[str, dict[str, list[dict[str, Any]]]]) -> tuple[list[dict[str, Any]], str | None]:
    by_index = {index: group for group in groups for index in group["indexes"]}
    rules: list[dict[str, Any]] = []
    final: str | None = None
    for index, raw in enumerate(config.get("rules", [])):
        if not isinstance(raw, str): raise SingBoxExportError(f"rules[{index}]: rule must be a string")
        parts = split_top_level_commas(raw)
        kind = parts[0].upper() if parts else ""
        if kind == "MATCH":
            if index != len(config["rules"]) - 1 or len(parts) != 2: raise SingBoxExportError(f"rules[{index}]: MATCH must be terminal and have one policy")
            action = _policy_action(parts[1])
            if action["action"] == "route": final = action["outbound"]
            else: rules.append(action)
            continue
        group = by_index.get(index)
        if group is not None:
            if index != group["indexes"][0]: continue
            actions = _subrule_actions(config, group["policy"]) if group["wrapper"] == "SUB-RULE" else [({}, _policy_action(group["policy"]))]
            def emit(bucket: str) -> None:
                if bucket not in group_buckets[group["id"]]:
                    return
                artifact_tag = group_buckets[group["id"]][bucket]["tag"]
                for extra, action in actions:
                    rules.append({"rule_set": [artifact_tag], **extra, **action})
            emit("base")
            continue
        if kind == "NETWORK" and len(parts) == 3 and parts[1].upper() in {"TCP", "UDP"}:
            rules.append({"network": [parts[1].lower()], **_policy_action(parts[2])}); continue
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
        matcher_kind = matcher_parts[0].upper()
        parsed = _matcher(matcher_kind, ",".join(matcher_parts[1:]), f"rules[{index}]")
        if isinstance(parsed, list):
            for field, value in parsed:
                rules.append({field: value, **_policy_action(policy)})
        else:
            field, value = parsed
            entry = {field: value if isinstance(value, list) else [value], **_policy_action(policy)}
            rules.append(entry)
    return rules, final


def export_singbox_dns(
    config: dict[str, Any], final_payloads: dict[str, list[str]], output_dist: Path,
    base_url: str, sing_box: str | None,
) -> dict[str, Any]:
    """Compile the shared normalized DNS domain view into two pure SRS files."""
    if not sing_box:
        raise SingBoxExportError("sing-box binary not found; DNS SRS output requires sing-box")
    dns_payloads = collect_dns_domain_payloads(config, final_payloads, DNS_DOMAIN_KINDS)
    stage = Path(tempfile.mkdtemp(prefix="singbox-dns-export-", dir=output_dist.parent))
    try:
        source_dir, binary_dir = stage / "source", stage / "dns"
        source_dir.mkdir(); binary_dir.mkdir()
        result: dict[str, Any] = {"groups": {}, "srs": []}
        for group in ("China", "Global"):
            domain_payload, classical_payload = dns_payloads[group]
            matchers: list[dict[str, Any]] = []
            for raw in domain_payload:
                field, value = _domain_value(raw)
                matchers.append({field: [value]})
            for number, raw in enumerate(classical_payload):
                parsed = parse_rule(raw)
                if parsed.kind not in DNS_DOMAIN_KINDS:
                    raise SingBoxExportError(f"DNS {group} classical[{number}]: unsupported matcher {parsed.kind!r}")
                if len(parsed.parts) < 2:
                    raise SingBoxExportError(f"DNS {group} classical[{number}]: missing matcher value")
                field, value = _matcher(parsed.kind, parsed.parts[1], f"DNS {group} classical[{number}]")
                matchers.append({field: [value]})
            source_rules = _aggregate(matchers)
            if not source_rules:
                raise SingBoxExportError(f"DNS {group}: generated empty SRS")
            source = source_dir / f"{group}-domain.json"
            binary = binary_dir / f"{group}-domain.srs"
            source.write_text(json.dumps({"version": 2, "rules": source_rules}, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
            observe_external("sing-box", f"compile DNS {group}", subprocess.run, [sing_box, "rule-set", "compile", str(source), "-o", str(binary)], check=True, capture_output=True, text=True)
            decompiled = stage / f"{group}-domain.decompiled.json"
            observe_external("sing-box", f"decompile DNS {group}", subprocess.run, [sing_box, "rule-set", "decompile", str(binary), "-o", str(decompiled)], check=True, capture_output=True, text=True)
            decoded = json.loads(decompiled.read_text(encoding="utf-8"))
            decompiled_rules = _canonicalize_decompiled_rules(decoded.get("rules", []))
            allowed = {"domain", "domain_suffix", "domain_keyword", "domain_regex"}
            if any(set(rule) - allowed for rule in decompiled_rules):
                raise SingBoxExportError(f"DNS {group}: decompiled SRS contains a non-domain matcher")
            for probe in _representatives(source_rules):
                source_match = observe_external("sing-box", f"match DNS source {group}", subprocess.run, [sing_box, "rule-set", "match", "-f", "source", str(source), probe], capture_output=True, text=True)
                binary_match = observe_external("sing-box", f"match DNS binary {group}", subprocess.run, [sing_box, "rule-set", "match", "-f", "binary", str(binary), probe], capture_output=True, text=True)
                if (source_match.returncode == 0) != (binary_match.returncode == 0):
                    raise SingBoxExportError(f"DNS {group}: source/binary semantic mismatch for {probe!r}")
            target = output_dist / "dns" / "singbox"
            target.mkdir(parents=True, exist_ok=True)
            shutil.copy2(binary, target / binary.name)
            result["groups"][group] = {"domain": len(domain_payload), "classical-domain": len(classical_payload)}
            result["srs"].append(binary.name)
        return result
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def export_singbox(config: dict[str, Any], final_payloads: dict[str, list[str]], output_dist: Path, base_url: str, sing_box: str | None, asn_resolver: Callable[[set[str]], dict[str, list[str]]] | None = None, segment_names: dict[str, str] | None = None) -> dict[str, Any]:
    if not sing_box: raise SingBoxExportError("sing-box binary not found; install Sing-box and retry")
    route_started = time.perf_counter()
    with _timed("Sing-box group discovery"):
        groups = _groups(config, segment_names)
    asn_resolver = asn_resolver or _default_asn_resolver
    if not groups: raise SingBoxExportError("no RULE-SET segments available for Sing-box export")
    with _timed("Sing-box ASN discovery"):
        required_asns = _collect_required_asns(groups, final_payloads)
    timing = current_timing()
    if timing is not None:
        timing.notes["ASN required"] = f"{len(required_asns)} unique ASNs"
        timing.notes["ASN resolver calls"] = "1" if required_asns else "0"
    asn_map: dict[str, list[str]] = {}
    if required_asns:
        with _timed("Sing-box ASN cache/index lookup"):
            asn_map = asn_resolver(required_asns)
        missing_asns = sorted(asn for asn in required_asns if not asn_map.get(asn))
        if missing_asns:
            raise SingBoxExportError("ASN resolver returned no prefix for: " + ", ".join(missing_asns))
    stage = Path(tempfile.mkdtemp(prefix="singbox-export-", dir=output_dist.parent))
    try:
        source_dir, binary_dir = stage / "source", stage / "singbox"
        source_dir.mkdir(); binary_dir.mkdir()
        group_buckets: dict[str, dict[str, dict[str, Any]]] = {}
        artifacts: list[tuple[str, list[dict[str, Any]]]] = []
        used_artifact_tags: set[str] = set()
        for group in groups:
            matchers: list[tuple[str, dict[str, Any]]] = []
            for provider in group["providers"]:
                if provider not in final_payloads:
                    raise SingBoxExportError(f"provider {provider}: final source payload unavailable")
                behavior = config["rule-providers"][provider].get("behavior")
                if behavior not in {"domain", "ipcidr", "classical"}: raise SingBoxExportError(f"provider {provider}: unsupported behavior {behavior!r}")
                payload = final_payloads[provider]
                asn_values = set()
                for raw in payload:
                    parsed = parse_rule(raw)
                    if parsed.kind in {"IP-ASN", "SRC-IP-ASN"} and len(parsed.parts) > 1:
                        asn_values.add(parsed.parts[1])
                if asn_values:
                    with _timed("Sing-box ASN payload expansion"):
                        expanded = asn_map
                        expanded_payload: list[str] = []
                        for raw in payload:
                            parsed = parse_rule(raw)
                            if parsed.kind in {"IP-ASN", "SRC-IP-ASN"}:
                                for network in expanded.get(parsed.parts[1], []):
                                    suffix = ",no-resolve" if any(item.lower() == "no-resolve" for item in parsed.parts[2:]) else ""
                                    expanded_payload.append(("SRC-IP-CIDR," if parsed.kind == "SRC-IP-ASN" else "IP-CIDR,") + network + suffix)
                            else:
                                expanded_payload.append(raw)
                        payload = expanded_payload
                with _timed("Sing-box matcher conversion"):
                        matchers.extend(_provider_matchers(provider, behavior, payload, asn_resolver))
            with _timed("Sing-box aggregation"):
                buckets = _aggregate_buckets(matchers)
            group_buckets[group["id"]] = {}
            for bucket, source_rules in buckets.items():
                suffix = ""
                artifact_tag = group["tag"] + suffix
                if artifact_tag in used_artifact_tags:
                    collision = 2
                    while f"{artifact_tag}-{collision}" in used_artifact_tags:
                        collision += 1
                    artifact_tag = f"{artifact_tag}-{collision}"
                used_artifact_tags.add(artifact_tag)
                group_buckets[group["id"]][bucket] = {"tag": artifact_tag, "rules": source_rules}
                artifacts.append((artifact_tag, source_rules))
            if not buckets: raise SingBoxExportError(f"segment {group['tag']}: generated empty SRS")
        artifact_times: dict[str, float] = {}
        for artifact_tag, source_rules in artifacts:
            artifact_started = time.perf_counter()
            source = source_dir / f"{artifact_tag}.json"
            with _timed("Sing-box source JSON write"):
                source.write_text(json.dumps({"version": 2, "rules": source_rules}, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
            binary = binary_dir / f"{artifact_tag}.srs"
            with _timed("Sing-box compile"):
                observe_external("sing-box", f"compile route {artifact_tag}", subprocess.run, [sing_box, "rule-set", "compile", str(source), "-o", str(binary)], check=True, capture_output=True, text=True)
            decompiled = stage / f"{artifact_tag}.decompiled.json"
            with _timed("Sing-box decompile"):
                observe_external("sing-box", f"decompile route {artifact_tag}", subprocess.run, [sing_box, "rule-set", "decompile", str(binary), "-o", str(decompiled)], check=True, capture_output=True, text=True)
            with _timed("Sing-box decoded JSON parse"):
                decoded = json.loads(decompiled.read_text(encoding="utf-8"))
                decompiled_rules = decoded.get("rules", [])
            if not _semantic_matcher_equivalent(source_rules, decompiled_rules):
                raise SingBoxExportError(f"artifact {artifact_tag}: source/decompiled matcher mismatch")
            with _timed("Sing-box representative probes"):
                for probe in _representatives(source_rules):
                    source_match = observe_external("sing-box", f"match route source {artifact_tag}", subprocess.run, [sing_box, "rule-set", "match", "-f", "source", str(source), probe], capture_output=True, text=True)
                    binary_match = observe_external("sing-box", f"match route binary {artifact_tag}", subprocess.run, [sing_box, "rule-set", "match", "-f", "binary", str(binary), probe], capture_output=True, text=True)
                    if (source_match.returncode == 0) != (binary_match.returncode == 0): raise SingBoxExportError(f"artifact {artifact_tag}: source/binary semantic mismatch for {probe!r}")
            artifact_times[artifact_tag] = time.perf_counter() - artifact_started
            timing = current_timing()
            if timing is not None:
                timing.phases[f"Sing-box artifact {artifact_tag}"] = artifact_times[artifact_tag]
        with _timed("Sing-box route generation"):
            route_rules, final = _route_rules(config, groups, group_buckets)
        route = {"route": {"rule_set": [{"type": "remote", "tag": tag, "format": "binary", "url": f"{base_url.rstrip('/')}/dist/singbox/{tag}.srs", "update_interval": "2d"} for tag, _source_rules in artifacts], "rules": route_rules}}
        if final is not None: route["route"]["final"] = final
        route_path = stage / "singbox-rules.json"
        with _timed("Sing-box source JSON write"):
            route_path.write_text(json.dumps(route, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        target_dir = output_dist / "singbox"
        target_dir.mkdir(parents=True, exist_ok=True)
        for stale in target_dir.glob("*.srs"):
            stale.unlink()
        with _timed("Sing-box canonical SRS copy"):
            binaries = list(binary_dir.glob("*.srs"))
            for binary in binaries:
                shutil.copy2(binary, target_dir / binary.name)
        (output_dist / "generated").mkdir(parents=True, exist_ok=True)
        shutil.copy2(route_path, output_dist / "generated/singbox-rules.json")
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
