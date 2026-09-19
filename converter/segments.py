"""Validated segment metadata shared by the build pipeline and audits."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .yamlio import load_yaml_unique


VALID_ROLES = frozenset({"direct", "ai", "global", "china", "reject"})


@dataclass(frozen=True)
class SegmentSpec:
    anchor: str
    name: str
    role: str


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
        if not isinstance(anchor, str) or not anchor.strip():
            raise SystemExit(f"{path}: segment anchor must be a non-empty string")
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
        if not isinstance(role, str) or not role.strip():
            raise SystemExit(f"{path}: segment {anchor!r} requires a non-empty string role")
        if role not in VALID_ROLES:
            raise SystemExit(f"{path}: segment {anchor!r} has unknown role: {role!r}")
        if name in names:
            raise SystemExit(f"{path}: duplicate segment name: {name}")
        anchors.add(anchor)
        names.add(name)
        specs.append(SegmentSpec(anchor, name, role))
    return tuple(specs)


def segment_mapping(specs: tuple[SegmentSpec, ...]) -> dict[str, str]:
    return {spec.anchor: spec.name for spec in specs}


def segment_roles(specs: tuple[SegmentSpec, ...]) -> dict[str, str]:
    return {spec.name: spec.role for spec in specs}
