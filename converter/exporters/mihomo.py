"""Mihomo final-config normalization and publication."""

from pathlib import Path
from typing import Any

from ..artifacts import convert_source_to_mrs, public_url, write_yaml_payload
from ..rules import parse_rule, parse_ruleset_reference, simple_ruleset_wrapper
from ..semantics import is_target_ip_kind


def normalize_no_active_resolve(config: dict[str, Any], payloads: dict[str, list[str]]) -> dict[str, Any]:
    providers = config.get("rule-providers", {})
    target_providers = {
        name for name, provider in providers.items()
        if provider.get("behavior") == "ipcidr"
        or any(is_target_ip_kind(parse_rule(raw).kind) for raw in payloads.get(name, []))
    }
    rules: list[Any] = []
    for raw in config.get("rules", []):
        if not isinstance(raw, str):
            rules.append(raw)
            continue
        try:
            reference = parse_ruleset_reference(raw)
        except SystemExit:
            reference = None
        if reference and reference.provider in target_providers and "no-resolve" not in {item.lower() for item in reference.modifiers}:
            wrapper = simple_ruleset_wrapper(raw)
            if wrapper is not None and wrapper[1].upper() == "SUB-RULE":
                parts, prefix, suffix = wrapper
                nested = ",".join(["RULE-SET", parts[1], *parts[2:], "no-resolve"])
                raw = ",".join(item for item in (prefix, f"({nested})", suffix) if item)
            else:
                raw = raw + ",no-resolve"
        parts = raw.split(",")
        if is_target_ip_kind(parts[0]) and "no-resolve" not in {item.lower() for item in parts[2:]}:
            raw = ",".join([*parts, "no-resolve"])
        rules.append(raw)
    return {**config, "rules": rules}


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
            source = output_dist / "source" / source_dir / f"{name}.yaml"
            artifact = output_dist / source_dir / f"{name}.mrs"
            write_yaml_payload(source, payload)
            convert_source_to_mrs(mihomo, behavior, source, artifact)
            updated.update({"type": "http", "format": "mrs", "url": public_url(base_url, "dist", source_dir, f"{name}.mrs"), "path": f"./ruleset/{name}.mrs"})
        else:
            folder = "classical" if behavior == "classical" else f"source/{'ipcidr' if behavior == 'ipcidr' else 'domain'}"
            artifact = output_dist / folder / f"{name}.yaml"
            write_yaml_payload(artifact, payload)
            updated.update({"type": "http", "format": "yaml", "url": public_url(base_url, "dist", folder, f"{name}.yaml"), "path": f"./ruleset/{name}.yaml"})
        providers[name] = updated
    return {**config, "rule-providers": providers}


def publish_final_config(config: dict[str, Any], work_dist: Path, final_dist: Path, base_url: str) -> dict[str, Any]:
    """Legacy name retained only for callers outside the production pipeline."""
    raise RuntimeError("publish_final_config is obsolete; call materialize_final_config")
