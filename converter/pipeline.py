"""Single semantic build pipeline: normalize, optimize, materialize, publish."""

import os
import shutil
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .artifacts import write_yaml_atomic
from .export_config import load_export_profile
from .exporters.dns import export_dns
from .exporters.egern import export_egern
from .exporters.loon import export_loon
from .exporters.mihomo import materialize_final_config, normalize_no_active_resolve
from .exporters.singbox import export_singbox, export_singbox_dns
from .model import BuildConfig, BuildContext, BuildResult, NormalizedProvider, SemanticConfig
from .optimize import optimize_config
from .providers import prefetch_provider_texts, process_provider
from .rules import find_ruleset_refs, iter_all_rules, rewrite_rules
from .segments import load_segment_specs, resolve_segment_roles, segment_mapping, segment_roles
from .spec import validate_input_schema
from .state import bootstrap_managed_manifest, build_managed_manifest, read_managed_manifest, refresh_complete_config, write_managed_manifest
from .timing import BuildTiming, activate
from .validate import validate_final_config
from .views import build_dns_views, build_segment_views
from .yamlio import load_yaml_unique


def _load_yaml(path: Path) -> dict[str, Any]:
    value = load_yaml_unique(path)
    validate_input_schema(path, value)
    return value


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
    normalized: list[NormalizedProvider] = []
    processing_started = time.perf_counter()
    for name, provider in providers.items():
        if name not in referenced:
            continue
        generated = process_provider(name, provider, context, prefetch.texts.get(name))
        normalized.extend(generated)
        print(f"{name}: ok ({sum(len(item.payload) for item in generated)} rules -> {', '.join(item.name for item in generated)})")
    timing.phases["provider processing"] = time.perf_counter() - processing_started
    print(f"provider processing: {timing.phases['provider processing']:.2f}s")

    replacements: dict[str, list[str]] = {}
    behaviors: dict[str, str] = {}
    for provider in normalized:
        replacements.setdefault(provider.source, []).append(provider.name)
        behaviors[provider.name] = provider.behavior.value
    rewritten_rules = rewrite_rules(rules, replacements, behaviors)
    rewritten_sub_rules = {
        name: tuple(rewrite_rules(members, replacements, behaviors))
        for name, members in (data.get("sub-rules") or {}).items()
    }
    semantic = SemanticConfig(
        providers=tuple(normalized),
        rules=tuple(rewritten_rules),
        sub_rules=rewritten_sub_rules,
        extras={key: value for key, value in data.items() if key not in {"rule-providers", "rules", "sub-rules"}},
    )
    specs = load_segment_specs(config.segment_names)
    mapping = segment_mapping(specs)
    explicit_roles = segment_roles(specs)
    export_profile = load_export_profile(config.export_config)
    with timing.phase("optimize config"):
        optimized = optimize_config(semantic, mapping)
        optimized = normalize_no_active_resolve(optimized)
        segment_roles_map = resolve_segment_roles(optimized.blocks, explicit_roles) if mapping else {}
    with timing.phase("build views"):
        views = build_segment_views(optimized.providers)
        dns_views = build_dns_views(optimized.providers, segment_roles_map, export_profile.dns_groups)
    present_roles = {
        segment_roles_map[provider.segment]
        for provider in optimized.providers
        if provider.segment in segment_roles_map
    }


    previous = read_managed_manifest(config.dist)
    dist_existed_before = config.dist.exists()
    refreshed_complete: dict[str, Any] | None = None
    complete_output = config.complete_output or config.complete_config
    complete_before = complete_output.read_bytes() if complete_output and complete_output.exists() else None
    state_path = config.dist.parent / ".state" / "managed-state.yaml"
    state_before = state_path.read_bytes() if state_path.exists() else None
    config.dist.parent.mkdir(parents=True, exist_ok=True)
    publish_dist = Path(tempfile.mkdtemp(prefix="mihomo-mrs-publish-", dir=config.dist.parent))
    old_dist = config.dist.with_name(f".{config.dist.name}.previous")
    export_started = time.perf_counter()
    required_roles = frozenset().union(*export_profile.dns_groups.values())
    try:
        with activate(timing):
            with timing.phase("materialize Mihomo"):
                final = materialize_final_config(optimized, publish_dist, config.base_url, config.mihomo_bin)
            with timing.phase("validate final config"):
                validate_final_config(publish_dist, final)
            exporter_calls: dict[str, tuple[str, Any, tuple[Any, ...]]] = {
                "egern": ("Egern export", export_egern, (optimized, views, publish_dist, config.base_url, export_profile.egern_policy_map, export_profile.allowed_unsupported.get("egern", frozenset()))),
                "loon": ("Loon export", export_loon, (optimized, views, publish_dist, config.base_url, export_profile.allowed_unsupported.get("loon", frozenset()))),
                "singbox": ("Sing-box route export", export_singbox, (optimized, publish_dist, config.base_url, config.sing_box_bin, None, export_profile.singbox_policy_map)),
                "singbox-dns": ("Sing-box DNS export", export_singbox_dns, (dns_views, publish_dist, config.sing_box_bin)),
                "dns": ("DNS export", export_dns, (dns_views, publish_dist, config.mihomo_bin, required_roles, present_roles)),
            }
            def run_export(item: tuple[str, tuple[str, Any, tuple[Any, ...]]]) -> tuple[str, Any, BuildTiming]:
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
            for key, result, worker_timing in completed:
                timing.merge(worker_timing)
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
                (publish_dist / ".generation").write_text(generation + "\n", encoding="utf-8", newline="\n")
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
        if not dist_existed_before:
            if config.dist.exists():
                shutil.rmtree(config.dist, ignore_errors=True)
        else:
            if config.dist.exists() and old_dist.exists():
                shutil.rmtree(config.dist, ignore_errors=True)
            if old_dist.exists():
                os.replace(old_dist, config.dist)
        shutil.rmtree(old_dist, ignore_errors=True)
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
    return BuildResult(final)
