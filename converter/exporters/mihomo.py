"""Mihomo final-config normalization and publication."""

from pathlib import Path
from typing import Any

from ..artifacts import copy_file, dist_relative_from_url, public_url
from ..rules import parse_rule, parse_ruleset_reference
from ..semantics import is_target_ip_kind


def normalize_no_active_resolve(config: dict[str, Any], payloads: dict[str, list[str]]) -> dict[str, Any]:
    providers = config.get("rule-providers", {})
    target_providers = {
        name for name, provider in providers.items()
        if any(is_target_ip_kind(parse_rule(raw).kind) for raw in payloads.get(name, []))
    }
    rules: list[Any] = []
    for raw in config.get("rules", []):
        if not isinstance(raw, str):
            rules.append(raw)
            continue
        reference = parse_ruleset_reference(raw)
        if reference and reference.provider in target_providers and "no-resolve" not in {item.lower() for item in reference.modifiers}:
            raw = raw + ",no-resolve"
        parts = raw.split(",")
        if is_target_ip_kind(parts[0]) and "no-resolve" not in {item.lower() for item in parts[2:]}:
            raw = ",".join([*parts, "no-resolve"])
        rules.append(raw)
    return {**config, "rules": rules}


def publish_final_config(config: dict[str, Any], work_dist: Path, final_dist: Path, base_url: str) -> dict[str, Any]:
    providers: dict[str, dict[str, Any]] = {}
    for name, provider in config["rule-providers"].items():
        updated = dict(provider)
        relative = dist_relative_from_url(str(provider.get("url", "")))
        if relative is not None:
            source = work_dist / relative
            destination = final_dist / relative
            if source.exists():
                copy_file(source, destination)
            updated["url"] = public_url(base_url, "dist", *relative.parts)
            updated["path"] = f"./ruleset/{relative.with_suffix('').as_posix()}{relative.suffix}"
        providers[name] = updated
    return {**config, "rule-providers": providers}
