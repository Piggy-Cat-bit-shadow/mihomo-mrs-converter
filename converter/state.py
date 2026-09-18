"""Managed ownership state and complete-config refresh helpers."""

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from .artifacts import write_yaml_atomic
from .rules import find_ruleset_refs

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
    """Refresh only providers still owned by the previous managed manifest."""
    existing = complete_config.get("rule-providers") or {}
    previous_providers = (previous or {}).get("providers") or {}
    replacements: dict[str, dict[str, Any]] = {}
    for name, old in previous_providers.items():
        if name not in existing or name not in final_config.get("rule-providers", {}):
            continue
        if provider_fingerprint(existing[name]) != old.get("fingerprint"):
            raise ValueError(f"complete config provider {name} was edited outside managed ownership")
        replacements[name] = final_config["rule-providers"][name]
    merged = dict(complete_config)
    merged["rule-providers"] = {**existing, **replacements}
    return merged
