"""Command-line orchestration for the converter package."""

from .pipeline import *

def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Mihomo rule-providers to MRS safely.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument(
        "--base-url",
        required=True,
        help="Public raw URL prefix for this repository, for example https://raw.githubusercontent.com/owner/repo/main",
    )
    parser.add_argument("--mihomo", default=os.environ.get("MIHOMO_BIN") or shutil.which("mihomo"))
    parser.add_argument("--allow-no-mihomo", action="store_true")
    parser.add_argument("--sing-box", default=os.environ.get("SING_BOX_BIN") or shutil.which("sing-box"))
    parser.add_argument("--allow-no-sing-box", action="store_true")
    parser.add_argument(
        "--complete-config",
        type=Path,
        help="Optional full Mihomo/Clash config to refresh with this run's generated providers and rules.",
    )
    parser.add_argument(
        "--complete-output",
        type=Path,
        help="Output path for --complete-config. Defaults to overwriting --complete-config.",
    )
    parser.add_argument(
        "--allow-orphan-providers",
        action="store_true",
        help="Retained for compatibility; unreferenced input providers are ignored.",
    )
    args = parser.parse_args()

    if not args.mihomo and not args.allow_no_mihomo:
        raise SystemExit("mihomo binary not found; install it or pass --allow-no-mihomo for source-only output")
    if not args.sing_box and not args.allow_no_sing_box:
        raise SystemExit("sing-box binary not found; install it or pass --allow-no-sing-box for source-only output")

    data = load_yaml(args.input)
    providers = data.get("rule-providers") or {}
    rules = data.get("rules") or []
    if not isinstance(providers, dict) or not isinstance(rules, list):
        raise SystemExit("input must contain rule-providers mapping and rules list")
    validate_top_level_rulesets(rules, set(providers))
    referenced_provider_names = {
        name
        for rule in rules
        for name in find_ruleset_refs(rule)
    }

    previous_manifest = read_managed_manifest(args.dist, FINAL_SUITE)
    complete_config = load_yaml_mapping(args.complete_config) if args.complete_config else None

    staging = Path(tempfile.mkdtemp(prefix="mihomo-mrs-build-", dir=args.dist.parent))

    generated_providers: dict[str, dict[str, Any]] = {}
    provider_behaviors: dict[str, str] = {}
    replacements: dict[str, list[str]] = {}
    source_payloads: dict[str, list[str]] = {}
    options = BuildOptions(
        dist=staging,
        base_url=args.base_url,
        mihomo=args.mihomo,
        used_names=set(referenced_provider_names),
        used_paths=set(),
        memory_cache={},
    )

    for name, provider in providers.items():
        if name not in referenced_provider_names:
            continue
        if not isinstance(provider, dict):
            raise SystemExit(f"{name}: provider must be a mapping")
        if (
            provider.get("format") == "mrs"
            and args.mihomo
            and not args.allow_no_mihomo
        ):
            raise SystemExit(
                f"external MRS provider {name} has no lossless normalized source; "
                "use YAML/text source for multi-client export"
            )
        result = process_provider(
            name=name,
            provider=provider,
            options=options,
        )
        overlap = set(generated_providers) & set(result.providers)
        if overlap:
            raise SystemExit(f"generated provider name collision: {', '.join(sorted(overlap))}")
        generated_providers.update(result.providers)
        source_payloads.update(result.source_payloads)
        for generated_name, generated_provider in result.providers.items():
            provider_behaviors[generated_name] = generated_provider["behavior"]
        replacements[name] = result.generated_names
        print(f"{name}: ok ({len(result.original_rules)} rules -> {', '.join(result.generated_names)})")

    rewritten_rules = rewrite_rules(rules, replacements, provider_behaviors)
    generated = {
        **{key: value for key, value in data.items() if key not in {"rule-providers", "rules"}},
        "rule-providers": generated_providers,
        "rules": rewritten_rules,
    }
    require_no_orphans = not args.allow_orphan_providers
    validate_generated_config(staging, generated, require_no_orphans=require_no_orphans)
    merged = build_merged_config(
        rules,
        replacements,
        generated_providers,
        provider_behaviors,
        source_payloads,
        options,
    )
    merged = {
        **{key: value for key, value in data.items() if key not in {"rule-providers", "rules"}},
        **merged,
    }
    validate_generated_config(staging, merged, require_no_orphans=require_no_orphans)
    merged_suite = materialize_suite_config(
        merged,
        "merged",
        staging,
        args.base_url,
        require_no_orphans=require_no_orphans,
    )
    dedup, dedup_stats = build_dedup_config(merged_suite, options, require_no_orphans=require_no_orphans)
    segment_mapping = load_segment_name_mapping(Path.cwd())
    dedup = apply_segment_name_mapping(dedup, options, segment_mapping)
    options.final_payloads = {
        re.sub(
            r"^merged-segment-(\d+)",
            lambda m: segment_mapping.get(f"merged-segment-{m.group(1)}", m.group(0)),
            name,
        ): payload
        for name, payload in options.final_payloads.items()
    }
    dedup_stats = {
        re.sub(r"^merged-segment-(\d+)", lambda m: segment_mapping.get(f"merged-segment-{m.group(1)}", m.group(0)), name): stats
        for name, stats in dedup_stats.items()
    }
    validate_generated_config(staging, dedup, require_no_orphans=require_no_orphans)
    dedup = normalize_no_active_resolve(dedup, options.final_payloads)
    validate_generated_config(staging, dedup, require_no_orphans=require_no_orphans)
    final_rule_counts = referenced_rule_counts(dedup, staging)
    publish_dist = Path(tempfile.mkdtemp(prefix="mihomo-mrs-publish-", dir=args.dist.parent))
    final = publish_final_config(dedup, staging, publish_dist, args.base_url)
    validate_generated_config(publish_dist, final, require_no_orphans=require_no_orphans)
    export_egern(dedup, staging, publish_dist, args.base_url)
    export_loon(dedup, staging, publish_dist, args.base_url)
    # The existing source-only development mode remains source-only unless a
    # Sing-box binary is explicitly supplied.  Production builds install both
    # binaries and therefore always publish the additional exporter.
    if args.sing_box and (args.mihomo or not args.allow_no_mihomo):
        try:
            from converter.exporters.singbox import export_singbox, export_singbox_dns
        except ImportError:
            from converter.exporters.singbox import export_singbox, export_singbox_dns
        export_singbox(dedup, options.final_payloads, publish_dist, args.base_url, args.sing_box, segment_names=segment_mapping)
        if args.mihomo and not args.allow_no_mihomo:
            export_singbox_dns(dedup, options.final_payloads, publish_dist, args.base_url, args.sing_box)
    if args.mihomo and not args.allow_no_mihomo:
        export_dns(dedup, staging, publish_dist, args.base_url, args.mihomo, options.final_payloads)
    write_yaml_atomic(publish_dist / "generated" / "mihomo-rules.yaml", final)
    old_dist = args.dist.with_name(f".{args.dist.name}.previous")
    if old_dist.exists():
        shutil.rmtree(old_dist)
    if args.dist.exists():
        os.replace(args.dist, old_dist)
    os.replace(publish_dist, args.dist)
    write_managed_manifest(args.dist, FINAL_SUITE, args.base_url, final["rule-providers"])
    shutil.rmtree(old_dist, ignore_errors=True)
    shutil.rmtree(staging, ignore_errors=True)
    print(f"wrote {args.dist / 'generated/mihomo-rules.yaml'}")
    print()
    print_dedup_report(dedup, dedup_stats)
    print()
    print("========== MRS Suite Summary ==========")
    print_suite_stats("Merged + dedup", FINAL_SUITE, final, args.dist, final_rule_counts)
    print("=======================================")

    if args.complete_config:
        refreshed = refresh_complete_config(
            complete_config,
            final,
            previous_manifest,
            args.base_url,
        )
        complete_output = args.complete_output or args.complete_config
        write_yaml_mapping_atomic(complete_output, refreshed)
        print(f"wrote refreshed complete config {complete_output}")


if __name__ == "__main__":
    main()
