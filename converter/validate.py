"""Shared structural validation for final configs and published artifacts."""

from pathlib import Path
from typing import Any

from .artifacts import generated_artifact_path
from .rules import find_ruleset_refs


def validate_config(dist: Path, config: dict[str, Any], require_no_orphans: bool = True) -> None:
    providers = config.get("rule-providers") or {}
    paths: dict[str, str] = {}
    used: set[str] = set()
    for name, provider in providers.items():
        path = provider.get("path")
        if isinstance(path, str) and path in paths:
            raise ValueError(f"duplicate provider path {path}: {paths[path]}, {name}")
        if isinstance(path, str): paths[path] = name
        artifact = generated_artifact_path(dist, provider)
        if artifact is not None and not artifact.exists():
            raise ValueError(f"missing artifact for {name}: {artifact}")
    for rule in config.get("rules", []):
        refs = find_ruleset_refs(rule)
        missing = set(refs) - set(providers)
        if missing: raise ValueError(f"missing referenced provider(s): {sorted(missing)}")
        used.update(refs)
    if require_no_orphans and set(providers) - used:
        raise ValueError(f"orphan provider(s): {sorted(set(providers) - used)}")
