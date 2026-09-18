"""Provider fetch, parse and normalization boundary."""

from .pipeline import *  # shared artifacts and rule semantics
from . import pipeline as _pipeline

def process_provider(
    name: str,
    provider: dict[str, Any],
    options: BuildOptions,
) -> ProviderResult:
    validate_provider_name(name)
    extra_fields = sorted(set(provider) - ALLOWED_PROVIDER_FIELDS)
    if "path-in-bundle" in provider:
        raise SystemExit(f"{name}: path-in-bundle is unsupported")
    if extra_fields:
        raise SystemExit(f"{name}: unsupported provider fields: {', '.join(extra_fields)}")

    url = provider.get("url")
    behavior = provider.get("behavior")
    if provider.get("type") != "http" or not isinstance(url, str):
        raise SystemExit(f"{name}: only http providers with url are supported")
    validate_http_url(name, url)
    if behavior not in {"classical", "domain", "ipcidr"}:
        raise SystemExit(f"{name}: unsupported behavior {behavior!r}")
    fmt = provider.get("format", "yaml")
    if fmt not in {"yaml", "text", "mrs"}:
        raise SystemExit(f"{name}: unsupported format {fmt!r}")

    generated: dict[str, dict[str, Any]] = {}
    generated_names: list[str] = []
    source_payloads: dict[str, list[str]] = {}

    if fmt == "mrs":
        if behavior == "classical":
            raise SystemExit(f"{name}: format mrs with classical behavior is unsupported")
        path = provider.get("path")
        if not isinstance(path, str):
            raise SystemExit(f"{name}: provider path must be a string")
        reserve_path(path, options.used_paths)
        passthrough = {
            key: value
            for key, value in provider.items()
            if key in PASSTHROUGH_PROVIDER_FIELDS
        }
        generated[name] = passthrough
        generated_names.append(name)
        options.used_names.add(name)
        empty_counter: Counter[str] = Counter()
        return ProviderResult(name, generated_names, generated, empty_counter, empty_counter, source_payloads)

    headers = provider.get("header")
    if headers is not None and not isinstance(headers, dict):
        raise SystemExit(f"{name}: provider header must be a mapping")
    remote_text = _pipeline.fetch_text(url, headers, options.memory_cache)
    remote_rules = payload_from_remote(name, remote_text, fmt, allow_integer_items=behavior == "ipcidr")
    if not remote_rules:
        raise SystemExit(f"{name}: provider contains no rules")
    parsed = [parse_rule(rule) for rule in remote_rules]
    original_counter = Counter(remote_rules)

    rebuilt: Counter[str] = Counter()

    if behavior == "domain":
        source_values = [rule.raw for rule in parsed]
        source_path = options.dist / "source" / "domain" / f"{name}.yaml"
        mrs_path = options.dist / "domain" / f"{name}.mrs"
        write_yaml_payload(source_path, source_values)
        if options.mihomo:
            convert_source_to_mrs(options.mihomo, "domain", source_path, mrs_path)
            fmt_out = "mrs"
            url_out = public_url(options.base_url, "dist/domain", f"{name}.mrs")
            path_out = f"./ruleset/{name}.mrs"
        else:
            fmt_out = "yaml"
            url_out = public_url(options.base_url, "dist/source/domain", f"{name}.yaml")
            path_out = f"./ruleset/{name}.yaml"
        generated[name] = make_provider(
            "domain",
            fmt_out,
            url_out,
            path_out,
            provider,
        )
        reserve_path(path_out, options.used_paths)
        generated_names.append(name)
        options.used_names.add(name)
        rebuilt.update(rule.raw for rule in parsed)
        source_payloads[name] = source_values

    elif behavior == "ipcidr":
        valid_rules: list[str] = []
        invalid_rules: list[str] = []
        for rule in parsed:
            if parse_ip_network(rule.raw) is None:
                invalid_rules.append(rule.raw)
            else:
                valid_rules.append(rule.raw)
        asn_values: list[str] = []
        if invalid_rules:
            metadata_counts = re.findall(r"(?im)^\s*#\s*IP-ASN\s*:\s*(\d+)\s*$", remote_text)
            candidates = [value for value in invalid_rules if re.fullmatch(r"\d+", value)]
            if (
                len(metadata_counts) != 1
                or len(candidates) != len(invalid_rules)
                or len(candidates) != int(metadata_counts[0])
            ):
                raise SystemExit(f"{name}: invalid ipcidr payload entries cannot be safely classified: {invalid_rules}")
            asn_values = candidates

        source_values = valid_rules
        if not source_values and not asn_values:
            raise SystemExit(f"{name}: provider produced no valid ipcidr or metadata-backed ASN rules")
        if source_values:
            source_path = options.dist / "source" / "ipcidr" / f"{name}.yaml"
            mrs_path = options.dist / "ipcidr" / f"{name}.mrs"
            write_yaml_payload(source_path, source_values)
            if options.mihomo:
                convert_source_to_mrs(options.mihomo, "ipcidr", source_path, mrs_path)
                fmt_out = "mrs"
                url_out = public_url(options.base_url, "dist/ipcidr", f"{name}.mrs")
                path_out = f"./ruleset/{name}.mrs"
            else:
                fmt_out = "yaml"
                url_out = public_url(options.base_url, "dist/source/ipcidr", f"{name}.yaml")
                path_out = f"./ruleset/{name}.yaml"
            generated[name] = make_provider("ipcidr", fmt_out, url_out, path_out, provider)
            reserve_path(path_out, options.used_paths)
            generated_names.append(name)
            options.used_names.add(name)
            source_payloads[name] = source_values
        if asn_values:
            segment = egern_segment_name(name)
            part = 1
            asn_name = format_provider_name(ProviderIdentity(segment, Behavior.CLASSICAL, part))
            while asn_name in options.used_names:
                part += 1
                asn_name = format_provider_name(ProviderIdentity(segment, Behavior.CLASSICAL, part))
            options.used_names.add(asn_name)
            classical_path = options.dist / "classical" / f"{asn_name}.yaml"
            write_yaml_payload(classical_path, [f"IP-ASN,{value}" for value in asn_values])
            path_out = f"./ruleset/{asn_name}.yaml"
            generated[asn_name] = make_generated_provider(
                "classical", "yaml", public_url(options.base_url, "dist/classical", f"{asn_name}.yaml"), path_out, provider, options.used_paths
            )
            generated_names.append(asn_name)
        if not generated_names:
            raise SystemExit(f"{name}: provider produced no generated providers")
        rebuilt.update(rule.raw for rule in parsed)

    else:
        domain_values: list[str] = []
        domain_originals: list[str] = []
        ip_values: list[str] = []
        ip_originals: list[str] = []
        fallback: list[str] = []

        for rule in parsed:
            domain_value = source_domain_value(rule)
            ip_value = source_ip_value(rule)
            if domain_value is not None:
                validate_source_domain_value(rule, domain_value)
                domain_values.append(domain_value)
                domain_originals.append(rule.raw)
            elif ip_value is not None:
                ip_values.append(ip_value)
                ip_originals.append(rule.raw)
            else:
                fallback.append(rule.raw)

        if domain_values:
            generated_name = reserve_provider_name(name, "domain", options.used_names)
            source_path = options.dist / "source" / "domain" / f"{name}.yaml"
            mrs_path = options.dist / "domain" / f"{name}.mrs"
            write_yaml_payload(source_path, domain_values)
            if options.mihomo:
                convert_source_to_mrs(options.mihomo, "domain", source_path, mrs_path)
                fmt_out = "mrs"
                url_out = public_url(options.base_url, "dist/domain", f"{name}.mrs")
                path_out = f"./ruleset/{generated_name}.mrs"
            else:
                fmt_out = "yaml"
                url_out = public_url(options.base_url, "dist/source/domain", f"{name}.yaml")
                path_out = f"./ruleset/{generated_name}.yaml"
            generated[generated_name] = make_generated_provider(
                "domain",
                fmt_out,
                url_out,
                path_out,
                provider,
                options.used_paths,
            )
            generated_names.append(generated_name)
            rebuilt.update(domain_originals)
            source_payloads[generated_name] = domain_values

        if ip_values:
            generated_name = reserve_provider_name(name, "ip", options.used_names)
            source_path = options.dist / "source" / "ipcidr" / f"{name}.yaml"
            mrs_path = options.dist / "ipcidr" / f"{name}.mrs"
            write_yaml_payload(source_path, ip_values)
            if options.mihomo:
                convert_source_to_mrs(options.mihomo, "ipcidr", source_path, mrs_path)
                fmt_out = "mrs"
                url_out = public_url(options.base_url, "dist/ipcidr", f"{name}.mrs")
                path_out = f"./ruleset/{generated_name}.mrs"
            else:
                fmt_out = "yaml"
                url_out = public_url(options.base_url, "dist/source/ipcidr", f"{name}.yaml")
                path_out = f"./ruleset/{generated_name}.yaml"
            generated[generated_name] = make_generated_provider(
                "ipcidr",
                fmt_out,
                url_out,
                path_out,
                provider,
                options.used_paths,
            )
            generated_names.append(generated_name)
            rebuilt.update(ip_originals)
            source_payloads[generated_name] = ip_values

        if fallback:
            generated_name = reserve_provider_name(name, "classical", options.used_names)
            classical_path = options.dist / "classical" / f"{name}.yaml"
            write_yaml_payload(classical_path, fallback)
            path_out = f"./ruleset/{generated_name}.yaml"
            generated[generated_name] = make_generated_provider(
                "classical",
                "yaml",
                public_url(options.base_url, "dist/classical", f"{name}.yaml"),
                path_out,
                provider,
                options.used_paths,
            )
            generated_names.append(generated_name)
            rebuilt.update(fallback)

    if not generated_names:
        raise SystemExit(f"{name}: provider produced no generated providers")

    validate_rule_counts(name, original_counter, rebuilt)

    return ProviderResult(name, generated_names, generated, original_counter, rebuilt, source_payloads)

