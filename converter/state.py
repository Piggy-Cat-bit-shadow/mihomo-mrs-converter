"""Managed ownership state and complete-config refresh helpers."""

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from .artifacts import public_url, write_yaml_atomic
from .rules import find_ruleset_refs, iter_all_rules

MANAGED_STATE_FILENAME = "managed-state.yaml"


def provider_fingerprint(provider: dict[str, Any]) -> str:
    payload = json.dumps(provider, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_managed_manifest(base_url: str, providers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "version": 2,
        "base_url": base_url.rstrip("/"),
        "providers": {
            name: {"name": name, "url": provider.get("url"), "path": provider.get("path"), "behavior": provider.get("behavior"), "format": provider.get("format"), "fingerprint": provider_fingerprint(provider)}
            for name, provider in providers.items()
        },
    }


def managed_manifest_path(dist: Path) -> Path:
    return dist.parent / ".state" / MANAGED_STATE_FILENAME


def read_managed_manifest(dist: Path) -> dict[str, Any] | None:
    path = managed_manifest_path(dist)
    if not path.exists():
        return None
    manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("providers"), dict):
        raise SystemExit(f"{path}: managed state missing providers mapping")
    # v1 suite fields are deliberately ignored during migration.
    return manifest


def write_managed_manifest(dist: Path, base_url: str, providers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    manifest = build_managed_manifest(base_url, providers)
    path = managed_manifest_path(dist)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_yaml_atomic(path, manifest)
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
        managed_url_prefix = public_url(base_url, "dist") + "/"
        managed_old_names = {
            name for name, provider in old_providers.items()
            if isinstance(provider, dict)
            and isinstance(provider.get("url"), str)
            and provider["url"].startswith(managed_url_prefix)
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
