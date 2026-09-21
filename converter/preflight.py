"""Fast, static preflight checks for build configuration and platform contracts.

No network access and no external binaries (mihomo / sing-box) are invoked.
This fails fast before downloading remote providers or running heavy compiler pipelines.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .export_config import ExportProfile, load_export_profile
from .model import parse_provider_identity, provider_segment
from .optimize import iter_ruleset_blocks
from .pipeline import validate_input_schema
from .rules import (
    find_ruleset_refs,
    iter_all_rules,
    parse_egern_network_rule,
    parse_egern_sub_rule_members,
    parse_rule,
    parse_ruleset_reference,
    simple_ruleset_wrapper,
    split_top_level_commas,
    strip_balanced_outer_parentheses,
)
from .segments import SegmentSpec, load_segment_specs, segment_mapping
from .yamlio import load_yaml_unique


class PreflightError(Exception):
    """Raised when configuration violates static structural or contract requirements."""
    pass


def _expected_reject_policy(spec: SegmentSpec) -> str:
    if spec.reject_mode == "reject":
        return "REJECT"
    if spec.reject_mode == "drop":
        return "REJECT-DROP"
    raise PreflightError(f"production reject segment has no valid reject-mode: {spec.name}")


def run_preflight(
    input_path: Path | None = None,
    segment_names_path: Path | None = None,
    export_config_path: Path | None = None,
) -> None:
    """Run all offline preflight checks against input rules, segments, and export profiles."""
    if input_path is None and segment_names_path is None and export_config_path is None:
        raise PreflightError("no configuration files specified for preflight")

    data: dict[str, Any] | None = None
    providers: dict[str, Any] = {}
    rules: list[Any] = []
    sub_rules: dict[str, Any] = {}

    if input_path is not None:
        if not input_path.exists():
            raise PreflightError(f"input configuration does not exist: {input_path}")

        # 1. Load and validate input YAML schema
        try:
            data = load_yaml_unique(input_path)
        except Exception as exc:
            raise PreflightError(f"failed to parse YAML {input_path}: {exc}") from exc

        try:
            validate_input_schema(input_path, data)
        except SystemExit as exc:
            raise PreflightError(f"input schema error: {exc}") from exc

        providers = data.get("rule-providers") or {}
        rules = data.get("rules") or []
        sub_rules = data.get("sub-rules") or {}

        # 2. Check rule references and provider existence
        all_rules_iter = list(iter_all_rules(data))
        referenced: set[str] = set()
        for raw in all_rules_iter:
            for ref in find_ruleset_refs(raw):
                referenced.add(ref)

        missing_providers = sorted(referenced - set(providers))
        if missing_providers:
            raise PreflightError(f"input references missing provider(s): {missing_providers}")

        # 3. Check RULE-SET references have valid policies and structure
        for index, raw in enumerate(rules):
            wrapper = simple_ruleset_wrapper(raw)
            if wrapper is not None:
                try:
                    ref = parse_ruleset_reference(raw)
                except SystemExit as exc:
                    raise PreflightError(f"rules[{index}]: invalid RULE-SET reference: {exc}") from exc
                if ref is None or not ref.policy:
                    raise PreflightError(f"rules[{index}]: RULE-SET reference has no policy: {raw!r}")

        # Check SUB-RULE structure and terminal MATCH
        for sub_name, members in sub_rules.items():
            if not members:
                raise PreflightError(f"sub-rules[{sub_name!r}] is empty")
            has_terminal_match = False
            for index, member in enumerate(members):
                parts = split_top_level_commas(member)
                kind = parts[0].upper() if parts else ""
                if kind == "MATCH":
                    if index == len(members) - 1:
                        has_terminal_match = True
                    else:
                        raise PreflightError(f"sub-rules[{sub_name!r}][{index}]: MATCH must be terminal")
                elif kind == "NETWORK":
                    if len(parts) != 3 or parts[1].upper() not in {"TCP", "UDP"}:
                        raise PreflightError(f"sub-rules[{sub_name!r}][{index}]: unsupported NETWORK rule: {member!r}")
                elif kind == "RULE-SET" or simple_ruleset_wrapper(member) is not None:
                    pass
            parsed_egern_members = parse_egern_sub_rule_members(members)
            if parsed_egern_members is None:
                raise PreflightError(f"sub-rules[{sub_name!r}] has members incompatible with Egern sub-rule exporter")
            if not has_terminal_match:
                raise PreflightError(f"sub-rules[{sub_name!r}] has no terminal MATCH")

        # Check terminal MATCH in rules before segment block mapping
        match_rules = [
            raw for raw in rules
            if isinstance(raw, str) and raw.strip().upper().startswith("MATCH,")
        ]
        if not match_rules:
            raise PreflightError("rules has no terminal MATCH rule")
        if not isinstance(rules[-1], str) or not rules[-1].strip().upper().startswith("MATCH,"):
            raise PreflightError("MATCH rule must be the final rule in rules")

    # 4. Check Segment Metadata & Mapping if provided
    specs: tuple[SegmentSpec, ...] | None = None
    if segment_names_path is not None:
        if not segment_names_path.exists():
            raise PreflightError(f"segment metadata does not exist: {segment_names_path}")
        try:
            specs = load_segment_specs(segment_names_path)
        except SystemExit as exc:
            raise PreflightError(f"segment metadata schema error: {exc}") from exc
        if not specs:
            raise PreflightError(f"segment metadata is empty: {segment_names_path}")

        if input_path is not None:
            mapping = segment_mapping(specs)
            spec_by_anchor = {spec.anchor: spec for spec in specs}
            spec_by_name = {spec.name: spec for spec in specs}

            # Verify segments match blocks and anchors exist in providers or blocks
            matched_anchors: set[str] = set()
            for start, end, routing, wrapper_sig, names in iter_ruleset_blocks(rules, providers):
                matches = [
                    (anchor, mapped_name)
                    for anchor, mapped_name in mapping.items()
                    if any(
                        name == anchor
                        or name.startswith(anchor + "-")
                        or (parse_provider_identity(name) and parse_provider_identity(name).segment == anchor)
                        for name in names
                    )
                ]
                if len(matches) > 1:
                    raise PreflightError(f"multiple configured anchors match providers {names}: {[m[0] for m in matches]}")
                if matches:
                    matched_anchors.add(matches[0][0])

            unused_anchors = sorted(set(mapping) - matched_anchors)
            if unused_anchors:
                raise PreflightError(f"configured segment anchor(s) did not match any merged segment block: {unused_anchors}")

            # Check Reject Segments Policy & Contract
            expected_reject_policies: dict[str, str] = {}
            for spec in specs:
                if spec.role == "reject":
                    expected_reject_policies[spec.name] = _expected_reject_policy(spec)

            for index, raw in enumerate(rules):
                refs = find_ruleset_refs(raw)
                if len(refs) != 1:
                    continue
                ref_name = refs[0]
                matching_anchor = next((anchor for anchor in mapping if ref_name == anchor or ref_name.startswith(anchor + "-")), None)
                seg_name = mapping.get(matching_anchor) if matching_anchor else provider_segment(ref_name)
                if seg_name in expected_reject_policies:
                    ref = parse_ruleset_reference(raw)
                    if ref is not None:
                        expected = expected_reject_policies[seg_name]
                        if ref.wrapper_kind == "SUB-RULE":
                            sub_members = sub_rules.get(ref.policy, [])
                            for member in sub_members:
                                parts = split_top_level_commas(member)
                                if parts and parts[0].upper() == "MATCH" and len(parts) >= 2:
                                    if parts[1] != expected:
                                        raise PreflightError(
                                            f"production reject segment {seg_name} routed through sub-rule {ref.policy} "
                                            f"with mismatching terminal policy: expected {expected}, got {parts[1]}"
                                        )
                        elif ref.policy != expected:
                            raise PreflightError(
                                f"production reject policy mismatch for segment {seg_name} in rule {raw!r}: "
                                f"expected {expected}, got {ref.policy}"
                            )

    # 5. Check Export Config Profile if provided (independently of segment_names_path)
    profile: ExportProfile | None = None
    if export_config_path is not None:
        if not export_config_path.exists():
            raise PreflightError(f"export config does not exist: {export_config_path}")
        try:
            profile = load_export_profile(export_config_path)
        except SystemExit as exc:
            raise PreflightError(f"export config schema error: {exc}") from exc

        # Check Egern policy map
        for src_policy, target_policy in profile.egern_policy_map.items():
            if target_policy not in {"DIRECT", "REJECT", "REJECT-DROP"} and not target_policy.strip():
                raise PreflightError(f"export config: invalid Egern policy mapping target: {target_policy!r}")

        # Check Sing-box policy map: policy mapping cannot introduce intrinsic rejection policy
        for src_policy, target_policy in profile.singbox_policy_map.items():
            if src_policy not in {"DIRECT", "REJECT", "REJECT-DROP"} and target_policy in {"DIRECT", "REJECT", "REJECT-DROP"} and target_policy != "DIRECT" and target_policy != "direct":
                raise PreflightError(
                    f"export config: Sing-box policy mapping cannot introduce intrinsic rejection policy: "
                    f"{src_policy!r} -> {target_policy!r}"
                )

    # 6. Cross-validation between Segment Metadata and Export Profile
    if specs is not None and profile is not None:
        all_spec_roles = {spec.role for spec in specs}
        for group_name, roles in profile.dns_groups.items():
            for role in roles:
                if role not in all_spec_roles:
                    raise PreflightError(
                        f"export config: DNS group {group_name!r} references role {role!r} "
                        f"which is not assigned to any configured segment"
                    )



def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Static preflight validation for rules, segments, and export configs.")
    parser.add_argument("input", nargs="?", type=Path, default=None, help="Path to rules.yaml")
    parser.add_argument("--segment-names", type=Path, help="Path to segment-names.yaml")
    parser.add_argument("--export-config", type=Path, help="Path to config/export.yaml")
    args = parser.parse_args(argv)

    try:
        run_preflight(args.input, args.segment_names, args.export_config)
        print("preflight: ok")
    except PreflightError as exc:
        print(f"preflight error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
