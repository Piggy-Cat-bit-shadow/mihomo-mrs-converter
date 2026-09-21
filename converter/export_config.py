"""Validated shared exporter profile loaded from config/export.yaml."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .identifiers import validate_artifact_id
from .yamlio import load_yaml_unique


DEFAULT_DNS_GROUPS = {
    "China": frozenset({"direct", "china"}),
    "Global": frozenset({"ai", "global"}),
}


@dataclass(frozen=True)
class ExportProfile:
    egern_policy_map: dict[str, str]
    singbox_policy_map: dict[str, str]
    dns_groups: dict[str, frozenset[str]]
    allowed_unsupported: dict[str, frozenset[str]]


def _string_map(value: object, path: Path, label: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise SystemExit(f"{path}: {label} must be a string mapping")
    return dict(value)


def load_export_profile(path: Path | None) -> ExportProfile:
    if path is None:
        return ExportProfile({}, {}, dict(DEFAULT_DNS_GROUPS), {})
    value = load_yaml_unique(path) or {}
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: export config must be a mapping")
    egern = value.get("egern") or {}
    singbox = value.get("singbox") or {}
    dns = value.get("dns") or {}
    if not all(isinstance(item, dict) for item in (egern, singbox, dns)):
        raise SystemExit(f"{path}: egern, singbox, and dns profiles must be mappings")
    groups_raw = dns.get("groups", DEFAULT_DNS_GROUPS)
    if not isinstance(groups_raw, dict) or not groups_raw:
        raise SystemExit(f"{path}: dns.groups must be a non-empty mapping")
    groups: dict[str, frozenset[str]] = {}
    for name, raw in groups_raw.items():
        validate_artifact_id(name, f"{path}: dns.groups name {name!r}")
        roles = raw.get("roles") if isinstance(raw, dict) else raw
        if not isinstance(roles, list) or not roles or not all(isinstance(role, str) and role for role in roles):
            raise SystemExit(f"{path}: dns.groups entries require a non-empty roles list")
        if name in groups or any(role in used for used in groups.values() for role in roles):
            raise SystemExit(f"{path}: dns group names and roles must be unique")
        groups[name] = frozenset(roles)
    allowed: dict[str, frozenset[str]] = {}
    for client in ("egern", "loon"):
        raw = (value.get(client) or {}).get("allowed-unsupported", [])
        if not isinstance(raw, list) or not all(isinstance(kind, str) and kind for kind in raw):
            raise SystemExit(f"{path}: {client}.allowed-unsupported must be a list of strings")
        allowed[client] = frozenset(raw)
    return ExportProfile(
        _string_map(egern.get("policy-map"), path, "egern.policy-map"),
        _string_map(singbox.get("policy-map"), path, "singbox.policy-map"),
        groups,
        allowed,
    )
