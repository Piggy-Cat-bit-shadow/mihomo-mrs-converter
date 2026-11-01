"""Validated segment metadata and the single segment planner.

A *segment* is a contiguous run of RULE-SET rules that share routing (wrapper,
policy) and source identity.  Planning segments is pure text work, so the same
planner serves the build, static preflight and the production audit instead of
each of them re-deriving block order.

Identity versus decoration
--------------------------
A configured anchor binds a block's routing identity, so it is semantic; the
display name and role are metadata.  Optional metadata that cannot be used
(blank/unsafe/duplicate name, unknown role, `reject-mode` on a non-reject
segment) is resolved deterministically with a warning instead of aborting the
build, because aborting on decoration is what used to turn unrelated edits into
red builds.  Errors that would change rule semantics stay fatal:

* a `reject` segment without a valid `reject-mode` (the reject policy would be
  guessed) still fails;
* an unnamed block whose DNS role cannot be inherited unambiguously still fails;
* the reserved ``merged-segment-`` namespace cannot be claimed by configuration.
"""
from __future__ import annotations

import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .identifiers import is_valid_artifact_id
from .model import PlannedBlock
from .rules import parse_ruleset_reference, ruleset_routing_signature, simple_ruleset_wrapper
from .yamlio import load_yaml_unique

VALID_ROLES = frozenset({"direct", "ai", "global", "china", "reject"})
VALID_REJECT_MODES = frozenset({"reject", "drop"})
RESERVED_SEGMENT_PREFIX = "merged-segment-"


@dataclass(frozen=True)
class SegmentSpec:
    anchor: str
    name: str
    role: str | None = None
    reject_mode: str | None = None


def warn(message: str) -> None:
    """Report a tolerated configuration problem without failing the build."""
    print(f"warning: {message}", file=sys.stderr)


def _fallback_name(anchor: str, used: set[str]) -> str:
    """Deterministic, collision-free artifact name derived from the anchor."""
    candidate = re.sub(r"[^A-Za-z0-9._-]+", "-", anchor).strip(".-") or "segment"
    if candidate.lower().startswith(RESERVED_SEGMENT_PREFIX):
        candidate = f"segment-{candidate}"
    base = candidate
    index = 2
    while candidate.lower() in used:
        candidate = f"{base}-{index}"
        index += 1
    return candidate


def _name_problem(name: Any) -> str | None:
    if not isinstance(name, str) or not name.strip():
        return "a non-empty string name is required"
    if not is_valid_artifact_id(name):
        return f"name {name!r} is not a safe artifact name"
    if name.lower().startswith(RESERVED_SEGMENT_PREFIX):
        return f"name {name!r} uses the reserved {RESERVED_SEGMENT_PREFIX!r} namespace"
    return None


def load_segment_specs(path: Path | None) -> tuple[SegmentSpec, ...]:
    """Load segment metadata, tolerating broken optional naming metadata."""
    if path is None:
        return ()
    try:
        value = load_yaml_unique(path)
    except OSError as exc:
        raise SystemExit(f"{path}: unable to read segment metadata: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("segments"), dict):
        raise SystemExit(f"{path}: segments must be a mapping")

    entries: list[tuple[str, dict[str, Any]]] = []
    for anchor, raw in value["segments"].items():
        if not isinstance(anchor, str) or not is_valid_artifact_id(anchor):
            warn(f"{path}: segment anchor {anchor!r} is not a usable identifier; ignoring it")
            continue
        if anchor.lower().startswith(RESERVED_SEGMENT_PREFIX):
            warn(
                f"{path}: segment anchor {anchor!r} uses the reserved "
                f"{RESERVED_SEGMENT_PREFIX!r} namespace; ignoring it"
            )
            continue
        if not isinstance(raw, dict):
            warn(f"{path}: segment {anchor!r} must be a mapping; ignoring its metadata")
            raw = {}
        entries.append((anchor, raw))

    # Keep every configured name that is usable, before deriving fallbacks, so a
    # fallback can never displace a name the user actually configured elsewhere.
    chosen: dict[str, str] = {}
    owners: dict[str, str] = {}
    used: set[str] = set()
    for anchor, raw in entries:
        name = raw.get("name")
        if _name_problem(name) is not None:
            continue
        folded = name.lower()
        if folded in used:
            continue
        used.add(folded)
        owners[folded] = anchor
        chosen[anchor] = name

    specs: list[SegmentSpec] = []
    for anchor, raw in entries:
        name = chosen.get(anchor)
        if name is None:
            configured = raw.get("name")
            problem = _name_problem(configured)
            if problem is None:
                problem = f"name {configured!r} is already used by segment {owners[configured.lower()]!r}"
            fallback = _fallback_name(anchor, used)
            used.add(fallback.lower())
            warn(f"{path}: segment {anchor!r}: {problem}; using {fallback!r}")
            name = fallback

        role_value = raw.get("role")
        role = role_value if isinstance(role_value, str) and role_value in VALID_ROLES else None
        if role is None:
            if role_value is None:
                warn(f"{path}: segment {anchor!r}: no role configured; it will not join a DNS group")
            else:
                warn(
                    f"{path}: segment {anchor!r}: unknown role {role_value!r}; "
                    f"it will not join a DNS group"
                )

        reject_mode = raw.get("reject-mode")
        if role == "reject":
            if not isinstance(reject_mode, str) or reject_mode not in VALID_REJECT_MODES:
                raise SystemExit(f"{path}: reject segment {anchor!r} requires reject-mode: reject or drop")
        elif reject_mode is not None:
            warn(
                f"{path}: segment {anchor!r}: reject-mode is only used by reject segments; "
                f"ignoring {reject_mode!r}"
            )
            reject_mode = None

        specs.append(SegmentSpec(anchor, name, role, reject_mode))
    return tuple(specs)


def segment_mapping(specs: tuple[SegmentSpec, ...]) -> dict[str, str]:
    return {spec.anchor: spec.name for spec in specs}


def segment_roles(specs: tuple[SegmentSpec, ...]) -> dict[str, str]:
    return {spec.name: spec.role for spec in specs if spec.role is not None}


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
    when it is one of those keys.  Anchors that match nothing are reported and
    ignored: the affected block keeps a generated identity instead of aborting
    the whole build.
    """
    segment_names = dict(mapping or {})
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
        anchors = _matched_anchors(sources, segment_names)
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
            next_anchors = _matched_anchors(next_sources, segment_names)
            if anchors and next_anchors and next_anchors != anchors:
                break
            anchors = anchors or next_anchors
            providers.append(candidate[0][1])
            sources.extend(next_sources)
            end += 1
        ordinal = len(blocks) + 1
        segment = segment_names[anchors[0]] if anchors else None
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
    unused = sorted(set(segment_names) - matched)
    if unused:
        warn(f"configured segment anchor(s) did not match any provider: {unused}; they were ignored")
    return tuple(blocks)


def plan_config(config: dict[str, Any], mapping: Mapping[str, str] | None = None) -> tuple[PlannedBlock, ...]:
    """Plan the segments of a raw input config (provider names are their sources)."""
    providers = config.get("rule-providers") or {}
    return plan_blocks(config.get("rules") or [], {name: name for name in providers}, mapping)


def resolve_segment_roles(
    blocks: Sequence[PlannedBlock], explicit_roles: Mapping[str, str | None]
) -> dict[str, str]:
    """Assign a DNS role to every planned segment that has one.

    Unnamed blocks inherit a role only from the unanimous explicit peers that
    share their routing.  Inheritance changes DNS metadata only; it never joins
    blocks or rewrites routing rules.  A named segment without a usable role is
    simply excluded from DNS grouping; the exporters then fail closed when a
    configured DNS group requires a role that no segment provides.
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
            continue
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
