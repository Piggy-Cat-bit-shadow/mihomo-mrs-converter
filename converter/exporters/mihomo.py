"""Mihomo final-config normalization and publication."""

from pathlib import Path
import tempfile
from typing import Any

from ..artifacts import convert_source_to_mrs, public_url, write_yaml_payload
from ..rules import (
    _ruleset_parts_in_expression,
    parse_rule,
    find_ruleset_refs,
    split_top_level_commas,
    strip_balanced_outer_parentheses,
)
from ..semantics import is_target_ip_kind


def normalize_no_active_resolve(config: dict[str, Any], payloads: dict[str, list[str]]) -> dict[str, Any]:
    providers = config.get("rule-providers", {})
    target_providers = {
        name for name, provider in providers.items()
        if provider.get("behavior") == "ipcidr"
        or any(is_target_ip_kind(parse_rule(raw).kind) for raw in payloads.get(name, []))
    }
    rules: list[Any] = []

    def normalize_ruleset_expression(expression: str) -> str:
        _, was_wrapped = strip_balanced_outer_parentheses(expression)
        direct = _ruleset_parts_in_expression(expression)
        if direct is not None:
            provider = direct[1]
            modifiers = [item for item in direct[2:] if item.lower() != "no-resolve"]
            if provider in target_providers:
                modifiers.append("no-resolve")
            result = ",".join([*direct[:2], *modifiers])
            return f"({result})" if was_wrapped else result
        inner, wrapped = strip_balanced_outer_parentheses(expression)
        parts = split_top_level_commas(inner if wrapped else expression)
        rewritten = []
        for part in parts:
            _, is_wrapped = strip_balanced_outer_parentheses(part)
            rewritten.append(normalize_ruleset_expression(part) if is_wrapped else part)
        result = ",".join(rewritten)
        return f"({result})" if wrapped else result

    def normalize_rule(raw: Any) -> Any:
        if not isinstance(raw, str):
            return raw
        if find_ruleset_refs(raw):
            raw = normalize_ruleset_expression(raw)
        parts = raw.split(",")
        if is_target_ip_kind(parts[0]):
            raw = ",".join([*parts[:2], *[item for item in parts[2:] if item.lower() != "no-resolve"], "no-resolve"])
        return raw

    rules = [normalize_rule(raw) for raw in config.get("rules", [])]
    sub_rules = {
        name: [normalize_rule(raw) for raw in members]
        for name, members in (config.get("sub-rules") or {}).items()
    }
    return {**config, "rules": rules, "sub-rules": sub_rules}


def materialize_final_config(
    config: dict[str, Any], payloads: dict[str, list[str]], output_dist: Path,
    base_url: str, mihomo: str | None,
) -> dict[str, Any]:
    """Create final artifacts once, after semantic identity is stable."""
    providers: dict[str, dict[str, Any]] = {}
    for name, provider in config["rule-providers"].items():
        updated = dict(provider)
        behavior = provider["behavior"]
        payload = payloads.get(name, [])
        if behavior in {"domain", "ipcidr"} and mihomo:
            source_dir = "ipcidr" if behavior == "ipcidr" else "domain"
            artifact = output_dist / source_dir / f"{name}.mrs"
            with tempfile.TemporaryDirectory(prefix="mihomo-mrs-provider-") as scratch:
                source = Path(scratch) / f"{name}.yaml"
                write_yaml_payload(source, payload)
                convert_source_to_mrs(mihomo, behavior, source, artifact)
            updated.update({"type": "http", "format": "mrs", "url": public_url(base_url, "dist", source_dir, f"{name}.mrs"), "path": f"./ruleset/{name}.mrs"})
        else:
            folder = "classical"
            artifact = output_dist / folder / f"{name}.yaml"
            write_yaml_payload(artifact, payload)
            updated.update({"type": "http", "format": "yaml", "url": public_url(base_url, "dist", folder, f"{name}.yaml"), "path": f"./ruleset/{name}.yaml"})
        size_limit = provider.get("size-limit", 0)
        if isinstance(size_limit, bool) or not isinstance(size_limit, int) or size_limit < 0:
            raise ValueError(f"{name}: size-limit must be a non-negative byte count")
        providers[name] = updated
    return {**config, "rule-providers": providers}
