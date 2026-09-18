"""Single semantic build pipeline: normalize, optimize, materialize, publish."""

import os
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from .artifacts import write_yaml_atomic
from .exporters.dns import export_dns
from .exporters.egern import export_egern
from .exporters.loon import export_loon
from .exporters.mihomo import materialize_final_config, normalize_no_active_resolve
from .exporters.singbox import export_singbox, export_singbox_dns
from .model import BuildConfig, BuildContext, BuildResult
from .optimize import optimize_config
from .providers import process_provider
from .rules import find_ruleset_refs, iter_all_rules
from .state import read_managed_manifest, refresh_complete_config, write_managed_manifest
from .validate import validate_final_config


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must be a YAML mapping")
    if not isinstance(value.get("rule-providers", {}), dict) or not isinstance(value.get("rules", []), list):
        raise SystemExit(f"{path}: rule-providers mapping and rules list are required")
    return value


def _segment_mapping(root: Path) -> dict[str, Any]:
    path = root / "segment-names.yaml"
    if not path.exists():
        return {}
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("segments", {}), dict):
        raise SystemExit(f"{path}: expected a segments mapping")
    mapping = value["segments"]
    for old, value in mapping.items():
        if not isinstance(old, str) or not isinstance(value, dict):
            raise SystemExit(f"{path}: each segment mapping must contain name and anchor")
        if not isinstance(value.get("name"), str) or not isinstance(value.get("anchor"), str) or not value["anchor"]:
            raise SystemExit(f"{path}: each segment mapping requires string name and non-empty anchor")
    return mapping


def build(config: BuildConfig) -> BuildResult:
    data = _load_yaml(config.input)
    providers = data.get("rule-providers") or {}
    rules = data.get("rules") or []
    referenced = {name for rule in iter_all_rules(data) for name in find_ruleset_refs(rule)}
    missing = referenced - set(providers)
    if missing:
        raise SystemExit(f"input references missing provider(s): {sorted(missing)}")

    context = BuildContext(memory_cache={}, used_names=set(referenced))
    generated: dict[str, dict[str, Any]] = {}
    payloads: dict[str, list[str]] = {}
    replacements: dict[str, list[str]] = {}
    behaviors: dict[str, str] = {}
    for name, provider in providers.items():
        if name not in referenced:
            continue
        result = process_provider(name, provider, context)
        replacements[name] = result.generated_names
        for normalized in result.providers:
            generated[normalized.name] = normalized.as_config()
            payloads[normalized.name] = list(normalized.payload)
            behaviors[normalized.name] = normalized.behavior.value
        print(f"{name}: ok ({sum(result.original_rules.values())} rules -> {', '.join(result.generated_names)})")

    from .optimize import rewrite_rules
    rewritten = rewrite_rules(rules, replacements, behaviors)
    rewritten_sub_rules = {
        name: rewrite_rules(members, replacements, behaviors)
        for name, members in (data.get("sub-rules") or {}).items()
    }
    semantic = {
        **{key: value for key, value in data.items() if key not in {"rule-providers", "rules", "sub-rules"}},
        "rule-providers": generated,
        "rules": rewritten,
        "sub-rules": rewritten_sub_rules,
    }
    mapping = _segment_mapping(Path.cwd())
    optimized, final_payloads, dedup_stats = optimize_config(semantic, payloads, mapping)
    optimized = normalize_no_active_resolve(optimized, final_payloads)

    previous = read_managed_manifest(config.dist)
    refreshed_complete: dict[str, Any] | None = None
    complete_output = config.complete_output or config.complete_config
    complete_before = complete_output.read_bytes() if complete_output and complete_output.exists() else None
    state_path = config.dist.parent / ".state" / "managed-state.yaml"
    state_before = state_path.read_bytes() if state_path.exists() else None
    publish_dist = Path(tempfile.mkdtemp(prefix="mihomo-mrs-publish-", dir=config.dist.parent))
    old_dist = config.dist.with_name(f".{config.dist.name}.previous")
    try:
        final = materialize_final_config(optimized, final_payloads, publish_dist, config.base_url, config.mihomo_bin)
        validate_final_config(publish_dist, final)
        exporter_stats: dict[str, Any] = {}
        exporter_stats["egern"] = export_egern(final, final_payloads, publish_dist, config.base_url)
        exporter_stats["loon"] = export_loon(final, final_payloads, publish_dist, config.base_url)
        exporter_stats["singbox"] = export_singbox(final, final_payloads, publish_dist, config.base_url, config.sing_box_bin, segment_names=mapping)
        exporter_stats["singbox-dns"] = export_singbox_dns(final, final_payloads, publish_dist, config.base_url, config.sing_box_bin)
        exporter_stats["dns"] = export_dns(final, final_payloads, publish_dist, config.base_url, config.mihomo_bin)
        write_yaml_atomic(publish_dist / "generated" / "mihomo-rules.yaml", final)
        if config.complete_config:
            complete = _load_yaml(config.complete_config)
            refreshed_complete = refresh_complete_config(complete, final, previous, config.base_url)

        if old_dist.exists():
            shutil.rmtree(old_dist)
        if config.dist.exists():
            os.replace(config.dist, old_dist)
        os.replace(publish_dist, config.dist)
        write_managed_manifest(config.dist, config.base_url, final["rule-providers"])
        if refreshed_complete is not None and complete_output is not None:
            write_yaml_atomic(complete_output, refreshed_complete)
        shutil.rmtree(old_dist, ignore_errors=True)
    except BaseException:
        shutil.rmtree(publish_dist, ignore_errors=True)
        if config.dist.exists() and old_dist.exists():
            shutil.rmtree(config.dist)
        if old_dist.exists():
            os.replace(old_dist, config.dist)
        if state_before is None:
            state_path.unlink(missing_ok=True)
        else:
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_bytes(state_before)
        if complete_output is not None:
            if complete_before is None:
                complete_output.unlink(missing_ok=True)
            else:
                complete_output.parent.mkdir(parents=True, exist_ok=True)
                complete_output.write_bytes(complete_before)
        raise

    return BuildResult(final, final_payloads, dedup_stats, exporter_stats)
