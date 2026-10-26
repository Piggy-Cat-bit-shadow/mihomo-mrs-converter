"""Validated segment metadata shared by the build pipeline and audits."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .identifiers import validate_artifact_id
from .optimize import iter_ruleset_blocks, matching_segment_anchors
from .yamlio import load_yaml_unique


VALID_ROLES = frozenset({"direct", "ai", "global", "china", "reject"})
VALID_REJECT_MODES = frozenset({"reject", "drop"})


@dataclass(frozen=True)
class SegmentSpec:
    anchor: str
    name: str
    role: str
    reject_mode: str | None = None


def load_segment_specs(path: Path | None) -> tuple[SegmentSpec, ...]:
    """Load and fail-fast validate the configured segment identities."""
    if path is None:
        return ()
    try:
        value = load_yaml_unique(path)
    except OSError as exc:
        raise SystemExit(f"{path}: unable to read segment metadata: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("segments"), dict):
        raise SystemExit(f"{path}: segments must be a mapping")

    specs: list[SegmentSpec] = []
    anchors: set[str] = set()
    names: set[str] = set()
    for anchor, raw in value["segments"].items():
        validate_artifact_id(anchor, f"{path}: segment anchor {anchor!r}")
        if anchor.startswith("merged-segment-"):
            raise SystemExit(f"{path}: ordinal segment keys are not supported: {anchor}")
        if anchor in anchors:
            raise SystemExit(f"{path}: duplicate segment anchor: {anchor}")
        if not isinstance(raw, dict):
            raise SystemExit(f"{path}: segment {anchor!r} must be a mapping")
        name = raw.get("name")
        role = raw.get("role")
        if not isinstance(name, str) or not name.strip():
            raise SystemExit(f"{path}: segment {anchor!r} requires a non-empty string name")
        validate_artifact_id(name, f"{path}: segment name {name!r}")
        if not isinstance(role, str) or not role.strip():
            raise SystemExit(f"{path}: segment {anchor!r} requires a non-empty string role")
        if role not in VALID_ROLES:
            raise SystemExit(f"{path}: segment {anchor!r} has unknown role: {role!r}")
        reject_mode = raw.get("reject-mode")
        if role == "reject":
            if not isinstance(reject_mode, str) or reject_mode not in VALID_REJECT_MODES:
                raise SystemExit(f"{path}: reject segment {anchor!r} requires reject-mode: reject or drop")
        elif "reject-mode" in raw:
            raise SystemExit(f"{path}: reject-mode is only valid for role=reject: {anchor}")
        if name in names:
            raise SystemExit(f"{path}: duplicate segment name: {name}")
        anchors.add(anchor)
        names.add(name)
        specs.append(SegmentSpec(anchor, name, role, reject_mode))
    return tuple(specs)


def segment_mapping(specs: tuple[SegmentSpec, ...]) -> dict[str, str]:
    return {spec.anchor: spec.name for spec in specs}


def segment_roles(specs: tuple[SegmentSpec, ...]) -> dict[str, str]:
    return {spec.name: spec.role for spec in specs}


def resolve_segment_roles(
    config: dict[str, Any], mapping: dict[str, str], explicit_roles: dict[str, str],
) -> dict[str, str]:
    """Inherit unnamed block roles only from unanimous explicit routing peers.

    Routing peers have both the same policy and the same wrapper. Inheritance
    changes DNS metadata only; it never joins blocks or rewrites routing rules.
    """
    roles = dict(explicit_roles)
    peers: dict[tuple[str, str], set[str]] = {}
    unnamed: list[tuple[str, tuple[str, str]]] = []
    for ordinal, (_, _, routing, _, names) in enumerate(
        iter_ruleset_blocks(config.get("rules", []), config["rule-providers"], mapping), 1
    ):
        matches = matching_segment_anchors(names, mapping)
        if len(matches) > 1:
            raise ValueError(f"multiple configured anchors match providers {names}: {matches}")
        if matches:
            peers.setdefault(routing, set()).add(explicit_roles[matches[0][1]])
        else:
            unnamed.append((f"merged-segment-{ordinal:02d}", routing))
    for name, routing in unnamed:
        candidates = peers.get(routing, set())
        if len(candidates) != 1:
            raise ValueError(
                f"DNS segment {name!r} cannot inherit an unambiguous role for "
                f"wrapper/policy {routing}: explicit peer roles={sorted(candidates)}"
            )
        roles[name] = next(iter(candidates))
    return roles


def segment_reject_modes(specs: tuple[SegmentSpec, ...]) -> dict[str, str]:
    return {spec.name: spec.reject_mode for spec in specs if spec.role == "reject" and spec.reject_mode is not None}
