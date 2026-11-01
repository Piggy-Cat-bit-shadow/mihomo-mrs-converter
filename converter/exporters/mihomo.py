"""Mihomo final-config normalization and publication."""

from dataclasses import replace
from pathlib import Path
import tempfile
from typing import Any

from ..artifacts import convert_sources_to_mrs, public_url, write_yaml_payload
from ..model import OptimizedConfig
from ..payload import payload_has_target_ip, serialize_payload
from ..rules import (
    ensure_single_no_resolve,
    find_ruleset_refs,
    is_target_ip_kind,
    rewrite_ruleset_expressions,
)


def normalize_no_active_resolve(optimized: OptimizedConfig) -> OptimizedConfig:
    """Keep target-IP matching free of client-side resolution.

    Domain providers must not carry a stale ``no-resolve``; IP providers and
    classical providers containing target-IP matchers must carry exactly one.
    """
    target_providers = {
        provider.name
        for provider in optimized.providers
        if payload_has_target_ip(provider.behavior.value, provider.payload)
    }

    def normalize_expression(parts: list[str], wrapped: bool) -> str:
        modifiers = [item for item in parts[2:] if item.lower() != "no-resolve"]
        if parts[1] in target_providers:
            modifiers.append("no-resolve")
        result = ",".join([*parts[:2], *modifiers])
        return f"({result})" if wrapped else result

    def normalize_rule(raw: Any) -> Any:
        if not isinstance(raw, str):
            return raw
        if find_ruleset_refs(raw):
            raw = rewrite_ruleset_expressions(raw, normalize_expression)
        parts = raw.split(",")
        if is_target_ip_kind(parts[0]):
            raw = ",".join(ensure_single_no_resolve(parts))
        return raw

    return replace(
        optimized,
        rules=tuple(normalize_rule(raw) for raw in optimized.rules),
        sub_rules={
            name: tuple(normalize_rule(raw) for raw in members)
            for name, members in optimized.sub_rules.items()
        },
    )


def materialize_final_config(
    optimized: OptimizedConfig, output_dist: Path, base_url: str, mihomo: str | None,
) -> dict[str, Any]:
    """Create final artifacts once, after semantic identity is stable."""
    providers: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="mihomo-mrs-providers-") as scratch:
        jobs: list[tuple[str, Path, Path]] = []
        for provider in optimized.providers:
            name = provider.name
            updated = provider.as_config()
            payload = serialize_payload(provider.payload)
            behavior = provider.behavior.value
            if behavior in {"domain", "ipcidr"} and mihomo:
                source_dir = "ipcidr" if behavior == "ipcidr" else "domain"
                source = Path(scratch) / f"{name}.yaml"
                write_yaml_payload(source, payload)
                jobs.append((behavior, source, output_dist / source_dir / f"{name}.mrs"))
                updated.update({"type": "http", "format": "mrs", "url": public_url(base_url, "dist", source_dir, f"{name}.mrs"), "path": f"./ruleset/{name}.mrs"})
            else:
                folder = "classical"
                write_yaml_payload(output_dist / folder / f"{name}.yaml", payload)
                updated.update({"type": "http", "format": "yaml", "url": public_url(base_url, "dist", folder, f"{name}.yaml"), "path": f"./ruleset/{name}.yaml"})
            size_limit = provider.metadata.size_limit
            if isinstance(size_limit, bool) or (size_limit is not None and (not isinstance(size_limit, int) or size_limit < 0)):
                raise ValueError(f"{name}: size-limit must be a non-negative byte count")
            providers[name] = updated
        if mihomo:
            convert_sources_to_mrs(mihomo, jobs)
    config = optimized.as_config()
    return {**config, "rule-providers": providers}
