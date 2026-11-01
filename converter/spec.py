"""Static input contract for ``rules.yaml``.

This module owns the shape of the converter input.  It deliberately has no
dependency on the build pipeline or the exporters so that ``preflight`` can
validate configuration without importing (or running) any build code.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .identifiers import validate_artifact_id


def validate_input_schema(path: Path, value: Any) -> None:
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must be a YAML mapping")
    providers = value.get("rule-providers")
    if not isinstance(providers, dict):
        raise SystemExit(f"{path}: rule-providers must be a mapping")
    for name, provider in providers.items():
        validate_artifact_id(name, f"{path}: rule-providers key {name!r}")
        if not isinstance(provider, dict):
            raise SystemExit(f"{path}: rule-providers.{name} must be a mapping")
        for field in ("type", "behavior", "format", "url", "path", "proxy"):
            if field in provider and not isinstance(provider[field], str):
                raise SystemExit(f"{path}: rule-providers.{name}.{field} must be a string")
        for field in ("interval", "size-limit"):
            if field in provider and (isinstance(provider[field], bool) or not isinstance(provider[field], int) or provider[field] < 0):
                raise SystemExit(f"{path}: rule-providers.{name}.{field} must be a non-negative integer")
        if "header" in provider and (
            not isinstance(provider["header"], dict)
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in provider["header"].items())
        ):
            raise SystemExit(f"{path}: rule-providers.{name}.header must map strings to strings")
    if not isinstance(value.get("rules"), list) or any(not isinstance(item, str) for item in value["rules"]):
        raise SystemExit(f"{path}: rules must be a list of strings")
    sub_rules = value.get("sub-rules")
    if sub_rules is not None:
        if not isinstance(sub_rules, dict):
            raise SystemExit(f"{path}: sub-rules must be a mapping")
        for name, members in sub_rules.items():
            validate_artifact_id(name, f"{path}: sub-rules name {name!r}")
            if not isinstance(members, list):
                raise SystemExit(f"{path}: sub-rules.{name} must be a list")
            for index, member in enumerate(members):
                if not isinstance(member, str):
                    raise SystemExit(f"{path}: sub-rules.{name}[{index}] must be a string")
