"""Validated segment metadata and the single segment planner.

A *segment* is a contiguous run of RULE-SET rules that share routing (wrapper,
policy) and source identity.  Planning segments is pure text work, so the same
planner serves the build, static preflight and the production audit instead of
each of them re-deriving block order.

Segment identity is explicit: a configured anchor matches a block when one of
the block's **source provider keys** is that anchor.  Nothing here inspects
artifact name suffixes, so inserting an unrelated provider can neither rename a
neighbouring segment nor make one segment look like another.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .identifiers import validate_artifact_id
from .model import PlannedBlock
from .rules import parse_ruleset_reference, ruleset_routing_signature, simple_ruleset_wrapper
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


def expected_reject_policy(spec: SegmentSpec) -> str:
    if spec.reject_mode == "reject":
        return "REJECT"
    if spec.reject_mode == "drop":
        return "REJECT-DROP"
    raise ValueError(f"production reject segment has no valid reject-mode: {spec.name}")


def _matched_anchors(sources: Sequence[str], mapping: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(anchor for anchor in mapping if anchor in sources)


def plan_blocks(
    rules: Sequence[Any],
    provider_sources: Mapping[str, str],
    mapping: Mapping[str, str] | None = None,
) -> tuple[PlannedBlock, ...]:
    """Group compatible RULE-SET rules into planned blocks with stable identity.

    ``provider_sources`` maps the provider names used by ``rules`` to the input
    provider key they were generated from; a configured anchor matches a block
    when it is one of those keys.
    """
    segment_mapping_ = dict(mapping or {})
    provider_names = set(provider_sources)
    blocks: list[PlannedBlock] = []
    matched: set[str] = set()
    index = 0
    while index < len(rules):
        wrapper = simple_ruleset_wrapper(rules[index])
        if wrapper is None or wrapper[0][1] not in provider_names:
            index += 1
            continue
        reference = parse_ruleset_reference(rules[index])
        if reference is None:
            raise ValueError(f"invalid ruleset reference: {rules[index]}")
        routing = ruleset_routing_signature(reference)
        wrapper_signature = (wrapper[1], wrapper[2])
        providers = [wrapper[0][1]]
        sources = [provider_sources[providers[0]]]
        anchors = _matched_anchors(sources, segment_mapping_)
        end = index + 1
        while end < len(rules):
            candidate = simple_ruleset_wrapper(rules[end])
            if candidate is None or candidate[0][1] not in provider_names:
                break
            next_reference = parse_ruleset_reference(rules[end])
            if next_reference is None:
                raise ValueError(f"invalid ruleset reference: {rules[end]}")
            if ruleset_routing_signature(next_reference) != routing or (candidate[1], candidate[2]) != wrapper_signature:
                break
            next_sources = [provider_sources[candidate[0][1]]]
            next_anchors = _matched_anchors(next_sources, segment_mapping_)
            if anchors and next_anchors and next_anchors != anchors:
                break
            anchors = anchors or next_anchors
            providers.append(candidate[0][1])
            sources.extend(next_sources)
            end += 1
        ordinal = len(blocks) + 1
        segment = segment_mapping_[anchors[0]] if anchors else None
        if anchors:
            matched.add(anchors[0])
        blocks.append(
            PlannedBlock(
                start=index,
                end=end,
                ordinal=ordinal,
                routing=routing,
                wrapper=wrapper_signature,
                providers=tuple(providers),
                sources=tuple(dict.fromkeys(sources)),
                segment=segment,
                name=segment if segment is not None else f"merged-segment-{ordinal:02d}",
            )
        )
        index = end
    unused = sorted(set(segment_mapping_) - matched)
    if unused:
        raise ValueError(f"configured segment anchor(s) did not match any merged segment: {unused}")
    return tuple(blocks)


def plan_config(config: dict[str, Any], mapping: Mapping[str, str] | None = None) -> tuple[PlannedBlock, ...]:
    """Plan the segments of a raw input config (provider names are their sources)."""
    providers = config.get("rule-providers") or {}
    return plan_blocks(config.get("rules") or [], {name: name for name in providers}, mapping)


def resolve_segment_roles(
    blocks: Sequence[PlannedBlock], explicit_roles: Mapping[str, str]
) -> dict[str, str]:
    """Assign a DNS role to every planned segment.

    Unnamed blocks inherit a role only from the unanimous explicit peers that
    share their routing.  Inheritance changes DNS metadata only; it never joins
    blocks or rewrites routing rules.
    """
    roles: dict[str, str] = {}
    peers: dict[tuple[str, str], set[str]] = {}
    unnamed: list[PlannedBlock] = []
    for block in blocks:
        if block.segment is None:
            unnamed.append(block)
            continue
        role = explicit_roles.get(block.segment)
        if role is None:
            raise ValueError(f"segment {block.segment!r} has no configured role")
        roles[block.name] = role
        peers.setdefault(block.routing, set()).add(role)
    for block in unnamed:
        candidates = peers.get(block.routing, set())
        if len(candidates) != 1:
            raise ValueError(
                f"DNS segment {block.name!r} cannot inherit an unambiguous role for "
                f"wrapper/policy {block.routing}: explicit peer roles={sorted(candidates)}"
            )
        roles[block.name] = next(iter(candidates))
    return roles
