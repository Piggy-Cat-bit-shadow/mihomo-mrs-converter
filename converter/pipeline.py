"""Single semantic build pipeline: normalize, optimize, materialize, publish."""

import os
import re
import shutil
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import yaml

from .artifacts import write_yaml_atomic
from .exporters.dns import export_dns
from .exporters.egern import export_egern
from .exporters.loon import export_loon
from .exporters.mihomo import materialize_final_config, normalize_no_active_resolve
from .exporters.singbox import export_singbox, export_singbox_dns
from .export_config import ExportProfile, load_export_profile
from .model import BuildConfig, BuildContext, BuildResult
from .optimize import optimize_config
from .providers import prefetch_provider_texts, process_provider
from .rules import find_ruleset_refs, iter_all_rules
from .segments import load_segment_specs, segment_mapping, segment_roles
from .state import bootstrap_managed_manifest, build_managed_manifest, read_managed_manifest, refresh_complete_config, write_managed_manifest
from .timing import BuildTiming, activate
from .validate import validate_final_config
from .yamlio import load_yaml_unique


def _load_yaml(path: Path) -> dict[str, Any]:
    value = load_yaml_unique(path)
    validate_input_schema(path, value)
    return value


def validate_input_schema(path: Path, value: Any) -> None:
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must be a YAML mapping")
    providers = value.get("rule-providers")
    if not isinstance(providers, dict):
        raise SystemExit(f"{path}: rule-providers must be a mapping")
    for name, provider in providers.items():
        if not isinstance(name, str) or not name:
            raise SystemExit(f"{path}: provider name must be a non-empty string")
        if not isinstance(provider, dict):
            raise SystemExit(f"{path}: rule-providers.{name} must be a mapping")
        for field in ("type", "behavior", "format", "url", "path", "proxy"):
            if field in provider and not isinstance(provider[field], str):
                raise SystemExit(f"{path}: rule-providers.{name}.{field} must be a string")
        for field in ("interval", "size-limit"):
            if field in provider and (isinstance(provider[field], bool) or not isinstance(provider[field], int) or provider[field] < 0):
                raise SystemExit(f"{path}: rule-providers.{name}.{field} must be a non-negative integer")
        if "header" in provider and (not isinstance(provider["header"], dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in provider["header"].items())):
            raise SystemExit(f"{path}: rule-providers.{name}.header must map strings to strings")
    if not isinstance(value.get("rules"), list) or any(not isinstance(item, str) for item in value["rules"]):
        raise SystemExit(f"{path}: rules must be a list of strings")
    sub_rules = value.get("sub-rules")
    if sub_rules is not None:
        if not isinstance(sub_rules, dict):
            raise SystemExit(f"{path}: sub-rules must be a mapping")
        for name, members in sub_rules.items():
            if not isinstance(name, str) or not name:
                raise SystemExit(f"{path}: sub-rules names must be non-empty strings")
            if not isinstance(members, list):
                raise SystemExit(f"{path}: sub-rules.{name} must be a list")
            for index, member in enumerate(members):
                if not isinstance(member, str):
                    raise SystemExit(f"{path}: sub-rules.{name}[{index}] must be a string")


def _load_export_config(path: Path | None) -> ExportProfile:
    return load_export_profile(path)


def _segment_mapping(path: Path | None) -> dict[str, str]:
    return segment_mapping(load_segment_specs(path))


def _segment_roles(path: Path | None) -> dict[str, str]:
    return segment_roles(load_segment_specs(path))


def build(config: BuildConfig) -> BuildResult:
    build_started = time.perf_counter()
    timing = BuildTiming()
    data = _load_yaml(config.input)
    providers = data.get("rule-providers") or {}
    rules = data.get("rules") or []
    referenced = {name for rule in iter_all_rules(data) for name in find_ruleset_refs(rule)}
    missing = referenced - set(providers)
    if missing:
        raise SystemExit(f"input references missing provider(s): {sorted(missing)}")

    context = BuildContext(memory_cache={}, used_names=set(referenced))
    prefetch_started = time.perf_counter()
    prefetch = prefetch_provider_texts(providers, referenced, context.memory_cache, config.provider_cache)
    timing.phases["provider prefetch"] = time.perf_counter() - prefetch_started
    timing.notes["provider prefetch"] = (
        f"{len(referenced)} providers (unique: {prefetch.unique_requests}, mem-hits: {prefetch.cache_hits}, "
        f"disk-hits: {prefetch.disk_hits}, downloads: {prefetch.downloads})"
    )
    print(
        f"provider prefetch: {len(referenced)} providers in {timing.phases['provider prefetch']:.2f}s "
        f"(unique requests: {prefetch.unique_requests}, memory hits: {prefetch.cache_hits}, disk hits: {prefetch.disk_hits}, downloads: {prefetch.downloads})"
    )
    generated: dict[str, dict[str, Any]] = {}
    payloads: dict[str, list[str]] = {}
    replacements: dict[str, list[str]] = {}
    behaviors: dict[str, str] = {}
    processing_started = time.perf_counter()
    for name, provider in providers.items():
        if name not in referenced:
            continue
        result = process_provider(name, provider, context, prefetch.texts.get(name))
        replacements[name] = result.generated_names
        for normalized in result.providers:
            generated[normalized.name] = normalized.as_config()
            payloads[normalized.name] = list(normalized.payload)
            behaviors[normalized.name] = normalized.behavior.value
        print(f"{name}: ok ({sum(result.original_rules.values())} rules -> {', '.join(result.generated_names)})")
    timing.phases["provider processing"] = time.perf_counter() - processing_started
    print(f"provider processing: {timing.phases['provider processing']:.2f}s")

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
    mapping = _segment_mapping(config.segment_names)
    segment_roles = _segment_roles(config.segment_names)
    export_profile = _load_export_config(config.export_config)
    with timing.phase("optimize config"):
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
    export_started = time.perf_counter()
    try:
        with activate(timing):
            with timing.phase("materialize Mihomo"):
                final = materialize_final_config(optimized, final_payloads, publish_dist, config.base_url, config.mihomo_bin)
            with timing.phase("validate final config"):
                validate_final_config(publish_dist, final)
            exporter_calls = {
                "egern": ("Egern export", export_egern, (final, final_payloads, publish_dist, config.base_url, export_profile.egern_policy_map, export_profile.allowed_unsupported.get("egern", frozenset()))),
                "loon": ("Loon export", export_loon, (final, final_payloads, publish_dist, config.base_url, export_profile.allowed_unsupported.get("loon", frozenset()))),
                "singbox": ("Sing-box route export", export_singbox, (final, final_payloads, publish_dist, config.base_url, config.sing_box_bin, None, mapping, export_profile.singbox_policy_map)),
                "singbox-dns": ("Sing-box DNS export", export_singbox_dns, (final, final_payloads, publish_dist, config.base_url, config.sing_box_bin, segment_roles, export_profile.dns_groups)),
                "dns": ("DNS export", export_dns, (final, final_payloads, publish_dist, config.base_url, config.mihomo_bin, segment_roles, export_profile.dns_groups)),
            }
            def run_export(item: tuple[str, Any, tuple[Any, ...]]) -> tuple[str, Any, BuildTiming]:
                key, (_label, function, args) = item
                started = time.perf_counter()
                worker_timing = BuildTiming()
                with activate(worker_timing):
                    result = function(*args)
                worker_timing.phases[exporter_calls[key][0]] = time.perf_counter() - started
                return key, result, worker_timing
            parallel_started = time.perf_counter()
            worker_count = int(os.environ.get("CONVERTER_EXPORT_WORKERS", "5"))
            if worker_count < 1:
                raise ValueError("CONVERTER_EXPORT_WORKERS must be positive")
            with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="export") as pool:
                completed = list(pool.map(run_export, exporter_calls.items()))
            timing.phases["parallel exporter wall-clock"] = time.perf_counter() - parallel_started
            exporter_stats = {}
            for key, result, worker_timing in completed:
                timing.merge(worker_timing)
                exporter_stats[key] = result
            with timing.phase("write generated Mihomo"):
                write_yaml_atomic(publish_dist / "generated" / "mihomo-rules.yaml", final)
            if config.complete_config:
                with timing.phase("refresh complete config"):
                    complete = _load_yaml(config.complete_config)
                    if previous is None and config.bootstrap_managed:
                        previous = bootstrap_managed_manifest(complete, final, config.base_url)
                    refreshed_complete = refresh_complete_config(complete, final, previous, config.base_url)
                    if previous is None and not config.bootstrap_managed:
                        raise SystemExit("complete config has no managed state; rerun with --bootstrap-managed after verifying ownership")
            else:
                timing.mark_skipped("refresh complete config")

            with timing.phase("atomic dist publish"):
                generation = build_managed_manifest(config.base_url, final["rule-providers"])["generation"]
                (publish_dist / ".generation").write_text(generation + "\n", encoding="utf-8")
                if old_dist.exists():
                    shutil.rmtree(old_dist)
                if config.dist.exists():
                    os.replace(config.dist, old_dist)
                os.replace(publish_dist, config.dist)
            with timing.phase("managed-state write"):
                write_managed_manifest(config.dist, config.base_url, final["rule-providers"])
            if refreshed_complete is not None and complete_output is not None:
                with timing.phase("write complete config"):
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

    timing.phases["total export/publish"] = time.perf_counter() - export_started
    timing.phases["total build"] = time.perf_counter() - build_started
    timing.notes["generated providers"] = f"{len(final.get('rule-providers', {}))} total"
    mrs_count = sum(1 for p in final.get("rule-providers", {}).values() if p.get("format") == "mrs")
    yaml_count = sum(1 for p in final.get("rule-providers", {}).values() if p.get("format") == "yaml")
    timing.notes["artifacts generated"] = f"{mrs_count} MRS, {yaml_count} YAML"
    timing.print_report()
    timing.write_step_summary()
    return BuildResult(final, final_payloads, dedup_stats, exporter_stats)
