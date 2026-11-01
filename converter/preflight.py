"""Fast, static preflight checks for build configuration and platform contracts.

No network access and no external binaries (mihomo / sing-box) are invoked.
This fails fast before downloading remote providers or running heavy compiler
pipelines, and it shares the segment planner and input schema with the build so
there is only one definition of "valid input".
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .export_config import ExportProfile, load_export_profile
from .model import PlannedBlock
from .rules import (
    find_ruleset_refs,
    iter_all_rules,
    parse_egern_sub_rule_members,
    parse_ruleset_reference,
    simple_ruleset_wrapper,
    split_top_level_commas,
)
from .segments import (
    SegmentSpec,
    expected_reject_policy,
    load_segment_specs,
    plan_config,
    resolve_segment_roles,
    segment_mapping,
    segment_roles,
)
from .spec import validate_input_schema
from .yamlio import load_yaml_unique


class PreflightError(Exception):
    """Raised when configuration violates static structural or contract requirements."""





def _check_sub_rules(sub_rules: dict[str, Any]) -> None:
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
        if parse_egern_sub_rule_members(members) is None:
            raise PreflightError(f"sub-rules[{sub_name!r}] has members incompatible with Egern sub-rule exporter")
        if not has_terminal_match:
            raise PreflightError(f"sub-rules[{sub_name!r}] has no terminal MATCH")


def _check_reject_routing(
    blocks: tuple[PlannedBlock, ...],
    rules: list[Any],
    sub_rules: dict[str, Any],
    expected: dict[str, str],
) -> None:
    for block in blocks:
        if block.segment is None or block.segment not in expected:
            continue
        wrapper, policy = block.routing
        want = expected[block.segment]
        if wrapper.upper() == "SUB-RULE":
            for member in sub_rules.get(policy, []):
                parts = split_top_level_commas(member)
                if parts and parts[0].upper() == "MATCH" and len(parts) >= 2 and parts[1] != want:
                    raise PreflightError(
                        f"production reject segment {block.segment} routed through sub-rule {policy} "
                        f"with mismatching terminal policy: expected {want}, got {parts[1]}"
                    )
        elif policy != want:
            raise PreflightError(
                f"production reject policy mismatch for segment {block.segment} in rule "
                f"{rules[block.start]!r}: expected {want}, got {policy}"
            )


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
        try:
            data = load_yaml_unique(input_path)
        except Exception as exc:
            raise PreflightError(f"failed to parse YAML {input_path}: {exc}") from exc
        try:
            validate_input_schema(input_path, data)
        except SystemExit as exc:
            raise PreflightError(f"input schema error: {exc}") from exc

        assert data is not None
        providers = data.get("rule-providers") or {}
        rules = data.get("rules") or []
        sub_rules = data.get("sub-rules") or {}

        referenced = {ref for raw in iter_all_rules(data) for ref in find_ruleset_refs(raw)}
        missing_providers = sorted(referenced - set(providers))
        if missing_providers:
            raise PreflightError(f"input references missing provider(s): {missing_providers}")

        for index, raw in enumerate(rules):
            if simple_ruleset_wrapper(raw) is None:
                continue
            try:
                reference = parse_ruleset_reference(raw)
            except SystemExit as exc:
                raise PreflightError(f"rules[{index}]: invalid RULE-SET reference: {exc}") from exc
            if reference is None or not reference.policy:
                raise PreflightError(f"rules[{index}]: RULE-SET reference has no policy: {raw!r}")

        _check_sub_rules(sub_rules)

        match_rules = [
            raw for raw in rules
            if isinstance(raw, str) and raw.strip().upper().startswith("MATCH,")
        ]
        if not match_rules:
            raise PreflightError("rules has no terminal MATCH rule")
        if not isinstance(rules[-1], str) or not rules[-1].strip().upper().startswith("MATCH,"):
            raise PreflightError("MATCH rule must be the final rule in rules")

        for index, raw in enumerate(rules):
            if simple_ruleset_wrapper(raw) is None:
                continue
            try:
                reference = parse_ruleset_reference(raw)
            except SystemExit:
                continue  # already reported by the RULE-SET structure check above
            if reference is not None and reference.wrapper_kind == "SUB-RULE" and reference.policy not in sub_rules:
                raise PreflightError(
                    f"rules[{index}]: SUB-RULE {reference.policy!r} is not defined in sub-rules"
                )

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
            try:
                blocks = plan_config(data or {}, mapping)
                resolve_segment_roles(blocks, segment_roles(specs))
            except ValueError as exc:
                raise PreflightError(str(exc)) from exc
            try:
                reject_policies = {
                    spec.name: expected_reject_policy(spec) for spec in specs if spec.role == "reject"
                }
            except ValueError as exc:
                raise PreflightError(str(exc)) from exc
            _check_reject_routing(blocks, rules, sub_rules, reject_policies)

    profile: ExportProfile | None = None
    if export_config_path is not None:
        if not export_config_path.exists():
            raise PreflightError(f"export config does not exist: {export_config_path}")
        try:
            profile = load_export_profile(export_config_path)
        except SystemExit as exc:
            raise PreflightError(f"export config schema error: {exc}") from exc

        for src_policy, target_policy in profile.egern_policy_map.items():
            if target_policy not in {"DIRECT", "REJECT", "REJECT-DROP"} and not target_policy.strip():
                raise PreflightError(f"export config: invalid Egern policy mapping target: {target_policy!r}")

        for src_policy, target_policy in profile.singbox_policy_map.items():
            if src_policy not in {"DIRECT", "REJECT", "REJECT-DROP"} and target_policy in {"DIRECT", "REJECT", "REJECT-DROP"} and target_policy != "DIRECT" and target_policy != "direct":
                raise PreflightError(
                    f"export config: Sing-box policy mapping cannot introduce intrinsic rejection policy: "
                    f"{src_policy!r} -> {target_policy!r}"
                )

    if specs is not None and profile is not None:
        all_spec_roles = {spec.role for spec in specs if spec.role is not None}
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
