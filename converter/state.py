"""Managed ownership state and complete-config refresh helpers."""

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from .artifacts import public_url, write_yaml_atomic
from .rules import find_ruleset_refs, iter_all_rules, normalize, parse_ruleset_reference

MANAGED_STATE_FILENAME = "managed-state.yaml"


def provider_fingerprint(provider: dict[str, Any]) -> str:
    payload = json.dumps(provider, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_managed_manifest(base_url: str, providers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    manifest = {
        "version": 2,
        "base_url": base_url.rstrip("/"),
        "providers": {
            name: {"name": name, "url": provider.get("url"), "path": provider.get("path"), "behavior": provider.get("behavior"), "format": provider.get("format"), "fingerprint": provider_fingerprint(provider)}
            for name, provider in providers.items()
        },
    }
    manifest["generation"] = provider_fingerprint({"base_url": manifest["base_url"], "providers": manifest["providers"]})
    return manifest


def managed_manifest_path(dist: Path) -> Path:
    return dist.parent / ".state" / MANAGED_STATE_FILENAME


def read_managed_manifest(dist: Path) -> dict[str, Any] | None:
    path = managed_manifest_path(dist)
    if not path.exists():
        return None
    manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != 2
        or not isinstance(manifest.get("base_url"), str)
        or not isinstance(manifest.get("providers"), dict)
    ):
        raise SystemExit(f"{path}: invalid managed state schema")
    generation = manifest.get("generation")
    if not isinstance(generation, str) or not generation.strip():
        raise SystemExit(f"{path}: managed state v2 requires non-empty generation field")
    generation_path = dist / ".generation"
    if not generation_path.exists():
        raise SystemExit(f"{path}: dist/.generation marker missing; refusing incremental refresh")
    if generation_path.read_text(encoding="utf-8").strip() != generation:
        raise SystemExit(f"{path}: dist/state generation mismatch; refusing incremental refresh")
    for name, state in manifest["providers"].items():
        if not isinstance(name, str) or not isinstance(state, dict) or not isinstance(state.get("fingerprint"), str):
            raise SystemExit(f"{path}: invalid managed provider state")
    return manifest


def write_managed_manifest(dist: Path, base_url: str, providers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    manifest = build_managed_manifest(base_url, providers)
    path = managed_manifest_path(dist)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_yaml_atomic(path, manifest)
    if "generation" in manifest and dist.exists():
        (dist / ".generation").write_text(manifest["generation"] + "\n", encoding="utf-8")
    return manifest


def refresh_complete_config(
    complete_config: dict[str, Any], final_config: dict[str, Any], previous: dict[str, Any] | None, base_url: str,
) -> dict[str, Any]:
    """Synchronize converter-owned providers and their contiguous RULE-SET block.

    The complete config is user-owned, so anything outside the previous managed
    manifest is preserved. Ambiguous rule expressions and ownership changes are
    rejected instead of being rewritten partially.
    """
    old_providers = complete_config.get("rule-providers") or {}
    old_rules = complete_config.get("rules") or []
    new_providers = final_config.get("rule-providers") or {}
    new_rules = final_config.get("rules") or []
    if not isinstance(old_providers, dict) or not isinstance(old_rules, list):
        raise SystemExit("complete config must contain rule-providers mapping and rules list")
    if not isinstance(new_providers, dict) or not isinstance(new_rules, list):
        raise SystemExit("generated config must contain rule-providers mapping and rules list")

    managed_old_names: set[str] = set()
    if previous is not None:
        manifest_providers = previous.get("providers")
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
            if provider_fingerprint(provider) != state.get("fingerprint"):
                raise SystemExit(
                    f"{name}: managed provider was modified outside converter; refusing to overwrite"
                )
            managed_old_names.add(name)
    else:
        managed_old_names = set()

    collisions = sorted((set(new_providers) & set(old_providers)) - managed_old_names)
    if collisions:
        raise SystemExit(
            "generated providers collide with unmanaged complete-config providers: "
            + ", ".join(collisions)
        )

    new_rulesets = [rule for rule in new_rules if find_ruleset_refs(rule)]
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
        else:
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

    # Complete-config sub-rules cannot reference managed providers
    old_sub_rules = complete_config.get("sub-rules")
    if isinstance(old_sub_rules, dict):
        for sub_name, sub_members in old_sub_rules.items():
            if isinstance(sub_members, list):
                for member in sub_members:
                    sub_refs = set(find_ruleset_refs(member))
                    if sub_refs & managed_old_names or sub_refs & set(new_providers):
                        raise SystemExit(
                            f"complete-config managed provider appears in sub-rules[{sub_name!r}]; unsupported"
                        )

    refreshed_providers = {
        name: provider for name, provider in old_providers.items()
        if name not in managed_old_names and name not in new_providers
    }
    refreshed_providers.update(new_providers)
    refreshed = dict(complete_config)
    refreshed["rule-providers"] = refreshed_providers
    refreshed["rules"] = [
        *retained_rules[:insert_at], *new_rulesets, *retained_rules[insert_at:]
    ]

    referenced = {name for rule in iter_all_rules(refreshed) for name in find_ruleset_refs(rule)}
    missing = referenced - set(refreshed_providers)
    if missing:
        raise SystemExit(f"complete config contains missing RULE-SET provider(s): {sorted(missing)}")
    return refreshed


def bootstrap_managed_manifest(complete_config: dict[str, Any], final_config: dict[str, Any], base_url: str) -> dict[str, Any]:
    """Adopt only an exact existing generated provider/rule block."""
    old_providers = complete_config.get("rule-providers") or {}
    new_providers = final_config.get("rule-providers") or {}
    if not isinstance(old_providers, dict) or set(old_providers) != set(new_providers):
        raise SystemExit("bootstrap requires complete-config providers to exactly match generated providers")
    for name, provider in new_providers.items():
        if provider_fingerprint(old_providers[name]) != provider_fingerprint(provider):
            raise SystemExit(f"bootstrap provider mismatch: {name}")

    old_sub_rules = complete_config.get("sub-rules")
    if isinstance(old_sub_rules, dict):
        for sub_name, sub_members in old_sub_rules.items():
            if isinstance(sub_members, list):
                for member in sub_members:
                    if set(find_ruleset_refs(member)) & set(new_providers):
                        raise SystemExit(
                            f"complete-config managed provider appears in sub-rules[{sub_name!r}]; unsupported"
                        )

    managed_names = set(new_providers)
    complete_rules = complete_config.get("rules") or []
    managed_indexes = [
        index for index, rule in enumerate(complete_rules)
        if set(find_ruleset_refs(rule)) & managed_names
    ]
    if not managed_indexes or managed_indexes != list(range(managed_indexes[0], managed_indexes[-1] + 1)):
        raise SystemExit("bootstrap requires one contiguous generated RULE-SET block")

    # Semantic exact comparison: candidate rules in complete-config must match generated rules exactly
    generated_rulesets = [rule for rule in (final_config.get("rules") or []) if find_ruleset_refs(rule)]
    candidate_rules = [complete_rules[i] for i in managed_indexes]
    if len(candidate_rules) != len(generated_rulesets):
        raise SystemExit("bootstrap candidate RULE-SET block length does not match generated rules")

    for cand, gen in zip(candidate_rules, generated_rulesets):
        # Normalize comma spacing
        if normalize(cand) == normalize(gen):
            continue
        # Compare structured parsed reference
        cand_ref = parse_ruleset_reference(cand)
        gen_ref = parse_ruleset_reference(gen)
        if cand_ref != gen_ref or cand_ref is None:
            raise SystemExit(
                f"bootstrap RULE-SET policy or modifier mismatch: candidate {cand!r} != generated {gen!r}"
            )

    return build_managed_manifest(base_url, new_providers)
