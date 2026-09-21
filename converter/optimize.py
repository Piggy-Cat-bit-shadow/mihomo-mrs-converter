"""Pure in-memory provider consolidation, deduplication and naming."""

from collections import Counter
from typing import Any, Iterator

from .model import DedupStats, NormalizedProvider, ProviderMetadata, parse_provider_identity
from .semantics import parse_ip_network
from .rules import (
    _rewrite_expression,
    find_ruleset_refs,
    iter_all_rules,
    parse_ruleset_reference,
    ruleset_routing_signature,
    ruleset_suffix_for_behavior,
    simple_ruleset_wrapper,
    wrap_ruleset_rule,
)

BEHAVIOR_ORDER = {"domain": 0, "classical": 1, "ipcidr": 2}


def _domain_suffix(rule: str) -> str | None:
    value = rule.strip().lower()
    return value[2:].rstrip(".") if value.startswith("+.") and len(value) > 2 else None


def domain_covered_by_suffix(domain: str, suffixes: set[str]) -> bool:
    value = domain.strip().lower().rstrip(".")
    return any(".".join(value.split(".")[i:]) in suffixes for i in range(len(value.split("."))))


def suffix_covered_by_parent_suffix(suffix: str, suffixes: set[str]) -> bool:
    labels = suffix.split(".")
    return any(".".join(labels[i:]) in suffixes for i in range(1, len(labels)))


def dedup_domain_payload(rules: list[str]) -> tuple[list[str], DedupStats]:
    stats = DedupStats(input_count=len(rules))
    unique: list[str] = []
    seen: set[str] = set()
    for rule in rules:
        if rule in seen:
            stats.exact_duplicates_removed += 1
        else:
            seen.add(rule)
            unique.append(rule)
    suffixes = {suffix for rule in unique if (suffix := _domain_suffix(rule)) is not None}
    output: list[str] = []
    for rule in unique:
        suffix = _domain_suffix(rule)
        if suffix is not None and suffix_covered_by_parent_suffix(suffix, suffixes):
            stats.suffix_covered_by_parent_suffix += 1
        elif suffix is None and domain_covered_by_suffix(rule, suffixes):
            stats.domain_covered_by_suffix += 1
        else:
            output.append(rule)
    stats.output_count = len(output)
    return output, stats


def dedup_ipcidr_payload(rules: list[str]) -> tuple[list[str], DedupStats]:
    stats = DedupStats(input_count=len(rules))
    unique: list[str] = []
    seen: set[str] = set()
    for rule in rules:
        if rule in seen:
            stats.ipcidr_duplicates_removed += 1
        else:
            seen.add(rule)
            unique.append(rule)
    networks = {network for rule in unique if (network := parse_ip_network(rule)) is not None}
    output: list[str] = []
    for rule in unique:
        network = parse_ip_network(rule)
        covered = False
        if network is not None:
            covered = any(network.supernet(new_prefix=prefix) in networks for prefix in range(network.prefixlen - 1, -1, -1))
        if covered:
            stats.ipcidr_covered_by_parent += 1
        else:
            output.append(rule)
    stats.output_count = len(output)
    return output, stats


def dedup_exact_rules(rules: list[str]) -> tuple[list[str], int]:
    output: list[str] = []
    seen: set[str] = set()
    for rule in rules:
        if rule not in seen:
            seen.add(rule)
            output.append(rule)
    return output, len(rules) - len(output)


def merge_metadata(providers: list[dict[str, Any]]) -> dict[str, Any] | None:
    for key in ("proxy", "size-limit"):
        values = [provider.get(key) for provider in providers]
        if any(value is None for value in values) and any(value is not None for value in values):
            return None
        if len({repr(value) for value in values}) > 1:
            return None
    result: dict[str, Any] = {"behavior": providers[0]["behavior"]}
    intervals = [value for value in (provider.get("interval") for provider in providers) if isinstance(value, int)]
    if intervals:
        result["interval"] = min(intervals)
    for key in ("proxy", "size-limit"):
        if providers[0].get(key) is not None:
            result[key] = providers[0][key]
    return result


def iter_ruleset_blocks(rules: list[Any], providers: dict[str, dict[str, Any]]) -> Iterator[tuple[int, int, tuple[str, str], tuple[str, str], list[str]]]:
    """Yield contiguous, wrapper- and routing-compatible RULE-SET blocks."""
    index = 0
    while index < len(rules):
        wrapper = simple_ruleset_wrapper(rules[index])
        if wrapper is None or wrapper[0][1] not in providers:
            index += 1
            continue
        reference = parse_ruleset_reference(rules[index])
        if reference is None:
            raise ValueError(f"invalid ruleset reference: {rules[index]}")
        routing = ruleset_routing_signature(reference)
        wrapper_signature = (wrapper[1], wrapper[2])
        names = [wrapper[0][1]]
        end = index + 1
        while end < len(rules):
            candidate = simple_ruleset_wrapper(rules[end])
            if candidate is None or candidate[0][1] not in providers:
                break
            next_reference = parse_ruleset_reference(rules[end])
            if next_reference is None:
                raise ValueError(f"invalid ruleset reference: {rules[end]}")
            if ruleset_routing_signature(next_reference) != routing or (candidate[1], candidate[2]) != wrapper_signature:
                break
            names.append(candidate[0][1])
            end += 1
        yield index, end, routing, wrapper_signature, names
        index = end


def optimize_config(
    config: dict[str, Any], payloads: dict[str, list[str]], segment_mapping: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, list[str]], dict[str, DedupStats]]:
    """Perform all provider transformations without touching the filesystem."""
    providers = config["rule-providers"]
    rules = list(config.get("rules", []))
    final_providers: dict[str, dict[str, Any]] = {}
    final_payloads: dict[str, list[str]] = {}
    stats: dict[str, DedupStats] = {}
    rewritten_rules: list[Any] = []
    handled: set[str] = set()
    rename_map: dict[str, list[str]] = {}
    segment_index = 0
    matched_anchors: set[str] = set()

    block_by_start = {start: (end, routing, wrapper, names) for start, end, routing, wrapper, names in iter_ruleset_blocks(rules, providers)}
    index = 0
    while index < len(rules):
        if index not in block_by_start:
            item = rules[index]
            rewritten_rules.append(_rewrite_expression(item, {}, {}) if isinstance(item, str) else item)
            handled.update(find_ruleset_refs(item))
            index += 1
            continue
        end, routing, wrapper_signature, names = block_by_start[index]
        segment_index += 1
        segment_key = f"merged-segment-{segment_index:02d}"
        matches = [
            (anchor, mapped_name)
            for anchor, mapped_name in (segment_mapping or {}).items()
            if any(
                name == anchor
                or name.startswith(anchor + "-")
                or (parse_provider_identity(name) and parse_provider_identity(name).segment == anchor)
                for name in names
            )
        ]
        if len(matches) > 1:
            raise ValueError(f"{segment_key}: multiple configured anchors match providers {names}")
        mapped_segment_name = matches[0][1] if matches else None
        if matches:
            matched_anchors.add(matches[0][0])
        groups: dict[tuple[str, str], list[str]] = {}
        group_modifiers: dict[tuple[str, str], set[str]] = {}
        for offset, name in enumerate(names):
            reference = parse_ruleset_reference(rules[index + offset])
            if reference is None:
                raise ValueError(f"invalid ruleset reference: {rules[index + offset]}")
            behavior = providers[name]["behavior"]
            modifiers = tuple(ruleset_suffix_for_behavior(reference.modifiers, behavior))
            key = (behavior, reference.policy)
            groups.setdefault(key, []).append(name)
            group_modifiers.setdefault(key, set()).update(modifiers)
        output_names: list[tuple[str, str, tuple[str, ...], list[str]]] = []
        for (behavior, policy), group in sorted(groups.items(), key=lambda item: BEHAVIOR_ORDER[item[0][0]]):
            modifiers = tuple(sorted(group_modifiers[(behavior, policy)]))
            compatible = merge_metadata([providers[name] for name in group])
            chunks = [payloads[name] for name in group]
            payload = [item for chunk in chunks for item in chunk]
            if behavior == "domain":
                payload, stat = dedup_domain_payload(payload)
                stats[f"segment-{segment_index:02d}-domain"] = stat
            elif behavior == "ipcidr":
                payload, stat = dedup_ipcidr_payload(payload)
                stats[f"segment-{segment_index:02d}-ip"] = stat
            if compatible is None:
                output_group = group
                for name in output_group:
                    final_providers[name] = providers[name]
                    final_payloads[name] = list(payloads[name])
                    output_names.append((name, policy, modifiers, [name]))
            else:
                label = "ip" if behavior == "ipcidr" else behavior
                base = f"merged-segment-{segment_index:02d}-{label}"
                name = base
                if name in final_providers:
                    part = 2
                    while f"{base}-part-{part:02d}" in final_providers:
                        part += 1
                    name = f"{base}-part-{part:02d}"
                final_providers[name] = compatible
                final_payloads[name] = payload
                output_names.append((name, policy, modifiers, list(group)))
            handled.update(group)
        for name, policy, modifiers, source_names in output_names:
            mapped = name
            if mapped_segment_name is not None and mapped.startswith(segment_key + "-"):
                mapped = mapped_segment_name + mapped[len(segment_key):]
            provider = final_providers.pop(name)
            payload = final_payloads.pop(name)
            if mapped in final_providers:
                part = 2
                base = mapped
                while f"{base}-part-{part:02d}" in final_providers:
                    part += 1
                mapped = f"{base}-part-{part:02d}"
            final_providers[mapped] = provider
            final_payloads[mapped] = payload
            for source_name in source_names:
                rename_map.setdefault(source_name, []).append(mapped)
            rule_parts = ["RULE-SET", mapped]
            if wrapper_signature[0].upper() != "SUB-RULE":
                rule_parts.append(policy)
            rule_parts.extend(modifiers)
            rule = ",".join(rule_parts)
            rewritten_rules.append(wrap_ruleset_rule(rule, wrapper_signature))
        index = end

    for name, provider in providers.items():
        if name not in handled:
            final_providers[name] = provider
            final_payloads[name] = list(payloads[name])
            rename_map.setdefault(name, []).append(name)

    final_behaviors = {
        name: provider.get("behavior", "") for name, provider in final_providers.items()
    }
    rewritten_sub_rules = {
        name: rewrite_rules(members, rename_map, final_behaviors)
        for name, members in (config.get("sub-rules") or {}).items()
    }

    rewritten_config = {
        **{key: value for key, value in config.items() if key not in {"rule-providers", "rules", "sub-rules"}},
        "rule-providers": final_providers,
        "rules": rewritten_rules,
        "sub-rules": rewritten_sub_rules,
    }
    referenced = {name for rule in iter_all_rules(rewritten_config) for name in find_ruleset_refs(rule)}
    ordered = {name: final_providers[name] for name in final_providers if name in referenced or name in final_payloads}
    unused_anchors = set(segment_mapping or {}) - matched_anchors
    if unused_anchors:
        raise ValueError(f"configured segment anchor(s) did not match any merged segment: {sorted(unused_anchors)}")
    return {**rewritten_config, "rule-providers": ordered}, {name: final_payloads[name] for name in ordered}, stats


def rewrite_rules(rules: list[Any], replacements: dict[str, list[str]], provider_behaviors: dict[str, str]) -> list[Any]:
    output: list[Any] = []
    for item in rules:
        if not isinstance(item, str):
            output.append(item)
            continue
        wrapper = simple_ruleset_wrapper(item)
        if wrapper is not None and wrapper[0][1] in replacements:
            parts, prefix, suffix = wrapper
            reference = parse_ruleset_reference(item)
            if reference is None:
                raise ValueError(f"invalid ruleset reference: {item}")
            for name in replacements[parts[1]]:
                if prefix.upper() == "SUB-RULE":
                    nested = ",".join(["RULE-SET", name, *ruleset_suffix_for_behavior(tuple(parts[2:]), provider_behaviors[name])])
                else:
                    nested = ",".join(["RULE-SET", name, reference.policy, *ruleset_suffix_for_behavior(reference.modifiers, provider_behaviors[name])])
                output.append(",".join(part for part in (prefix, f"({nested})" if prefix or suffix else nested, suffix) if part))
        else:
            output.append(_rewrite_expression(item, replacements, provider_behaviors))
    return output
