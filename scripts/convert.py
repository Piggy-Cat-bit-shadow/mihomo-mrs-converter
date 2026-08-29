#!/usr/bin/env python3
import argparse
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

try:
    import certifi
except ImportError:  # pragma: no cover - optional runtime fallback
    certifi = None


DOMAIN_RULES = {"DOMAIN", "DOMAIN-SUFFIX"}
IPCIDR_RULES = {"IP-CIDR", "IP-CIDR6"}


@dataclass(frozen=True)
class RuleLine:
    raw: str
    kind: str
    parts: tuple[str, ...]


@dataclass
class ProviderResult:
    original_name: str
    generated_names: list[str]
    providers: dict[str, dict[str, Any]]
    original_rules: Counter[str]
    rebuilt_rules: Counter[str]


@dataclass
class BuildOptions:
    dist: Path
    base_url: str
    mihomo: str | None
    used_names: set[str]
    used_paths: set[str]
    memory_cache: dict[str, str]


ALLOWED_PROVIDER_FIELDS = {
    "type",
    "behavior",
    "format",
    "url",
    "path",
    "interval",
    "proxy",
    "size-limit",
    "header",
}
PASSTHROUGH_PROVIDER_FIELDS = {
    "type",
    "behavior",
    "format",
    "url",
    "path",
    "interval",
    "proxy",
    "size-limit",
}


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must be a YAML mapping")
    allowed = {"rule-providers", "rules"}
    extra = sorted(set(data) - allowed)
    if extra:
        raise SystemExit(
            f"{path} contains unsupported top-level keys: {', '.join(extra)}"
        )
    return data


def validate_provider_name(name: str) -> None:
    if "\x00" in name or "/" in name or "\\" in name or ".." in name:
        raise SystemExit(f"{name}: provider name contains unsupported path content")


def validate_http_url(name: str, url: str) -> None:
    scheme = urlparse(url).scheme.lower()
    if scheme not in {"http", "https"}:
        raise SystemExit(f"{name}: unsupported provider URL scheme {scheme!r}")


def fetch_text(url: str, headers: dict[str, Any] | None, memory_cache: dict[str, str]) -> str:
    if url in memory_cache:
        return memory_cache[url]
    request_headers = {"User-Agent": "mihomo-mrs-converter"}
    if headers:
        for key, value in headers.items():
            if isinstance(key, str) and isinstance(value, str):
                request_headers[key] = value
            else:
                raise SystemExit("provider header keys and values must be strings")
    request = urllib.request.Request(url, headers=request_headers)
    context = (
        ssl.create_default_context(cafile=certifi.where())
        if certifi is not None
        else ssl.create_default_context()
    )
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=60, context=context) as response:
                body = response.read().decode("utf-8-sig")
            break
        except Exception as exc:  # pragma: no cover - network timing dependent
            last_error = exc
            if attempt == 2:
                raise
            time.sleep(2 * (attempt + 1))
    else:  # pragma: no cover
        raise last_error
    memory_cache[url] = body
    return body


def strict_yaml_rule_list(name: str, value: Any) -> list[str]:
    if not isinstance(value, list):
        raise SystemExit(f"{name}: YAML provider payload must be a list")
    rules: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise SystemExit(f"{name}: YAML provider payload items must be strings")
        stripped = item.strip()
        if stripped:
            rules.append(stripped)
    return rules


def payload_from_yaml(name: str, text: str) -> list[str]:
    parsed = yaml.safe_load(text)
    if isinstance(parsed, dict):
        for key in ("payload", "rules"):
            if key in parsed:
                return strict_yaml_rule_list(name, parsed[key])
        raise SystemExit(f"{name}: YAML provider must contain payload or rules")
    if isinstance(parsed, list):
        return strict_yaml_rule_list(name, parsed)
    raise SystemExit(f"{name}: YAML provider must be a mapping or list")


def payload_from_text(text: str) -> list[str]:
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def payload_from_remote(name: str, text: str, fmt: str) -> list[str]:
    if fmt == "yaml":
        return payload_from_yaml(name, text)
    if fmt == "text":
        return payload_from_text(text)
    raise SystemExit(f"{name}: unsupported source format {fmt!r}")


def parse_rule(raw: str) -> RuleLine:
    parts = tuple(part.strip() for part in raw.split(","))
    kind = parts[0].upper() if parts else ""
    return RuleLine(raw=raw, kind=kind, parts=parts)


def normalize(rule: str) -> str:
    return ",".join(part.strip() for part in rule.split(","))


def source_domain_value(rule: RuleLine) -> str | None:
    if len(rule.parts) < 2:
        return None
    value = rule.parts[1]
    if rule.kind == "DOMAIN":
        return value
    if rule.kind == "DOMAIN-SUFFIX":
        return f"+.{value.lstrip('.')}"
    return None


def validate_source_domain_value(rule: RuleLine, converted: str) -> None:
    value = rule.parts[1]
    if rule.kind == "DOMAIN":
        expected = value
    elif rule.kind == "DOMAIN-SUFFIX":
        expected = f"+.{value.lstrip('.')}"
    else:
        return
    if converted != expected:
        raise SystemExit(
            f"{rule.raw}: domain conversion mismatch; got={converted!r} expected={expected!r}"
        )


def source_ip_value(rule: RuleLine) -> str | None:
    if len(rule.parts) != 2:
        return None
    return rule.parts[1] if rule.kind in IPCIDR_RULES else None


def write_yaml_payload(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump({"payload": rules}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def write_text_payload(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rules) + "\n", encoding="utf-8")


def convert_source_to_mrs(mihomo: str, behavior: str, source: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            mihomo,
            "convert-ruleset",
            behavior,
            "yaml",
            str(source),
            str(output),
        ],
        check=True,
    )


def public_url(base_url: str, *parts: str) -> str:
    return "/".join([base_url.rstrip("/"), *[part.strip("/") for part in parts]])


def make_provider(
    behavior: str,
    fmt: str,
    url: str,
    path: str,
    source_provider: dict[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "http",
        "behavior": behavior,
        "format": fmt,
        "url": url,
        "path": path,
    }
    for key in ("interval", "proxy", "size-limit"):
        if key in source_provider:
            result[key] = source_provider[key]
    return result


def reserve_provider_name(name: str, suffix: str, used_names: set[str]) -> str:
    candidate = f"{name}-{suffix}"
    if candidate not in used_names:
        used_names.add(candidate)
        return candidate
    candidate = f"{name}-mrs-{suffix}"
    if candidate not in used_names:
        used_names.add(candidate)
        return candidate
    index = 2
    while True:
        candidate = f"{name}-mrs{index}-{suffix}"
        if candidate not in used_names:
            used_names.add(candidate)
            return candidate
        index += 1


def reserve_path(path: str, used_paths: set[str]) -> None:
    if path in used_paths:
        raise SystemExit(f"generated provider path collision: {path}")
    used_paths.add(path)


def generated_artifact_path(dist: Path, provider: dict[str, Any]) -> Path | None:
    url = provider.get("url")
    if not isinstance(url, str):
        return None
    marker = "/dist/"
    if marker not in url:
        return None
    relative = url.split(marker, 1)[1]
    return dist / relative


def make_generated_provider(
    behavior: str,
    fmt: str,
    url: str,
    path: str,
    source_provider: dict[str, Any],
    used_paths: set[str],
) -> dict[str, Any]:
    reserve_path(path, used_paths)
    return make_provider(behavior, fmt, url, path, source_provider)


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
        return ProviderResult(name, generated_names, generated, empty_counter, empty_counter)

    headers = provider.get("header")
    if headers is not None and not isinstance(headers, dict):
        raise SystemExit(f"{name}: provider header must be a mapping")
    remote_rules = payload_from_remote(
        name,
        fetch_text(url, headers, options.memory_cache),
        fmt,
    )
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

    elif behavior == "ipcidr":
        source_values = [rule.raw for rule in parsed]
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
        generated[name] = make_provider(
            "ipcidr",
            fmt_out,
            url_out,
            path_out,
            provider,
        )
        reserve_path(path_out, options.used_paths)
        generated_names.append(name)
        options.used_names.add(name)
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

    return ProviderResult(name, generated_names, generated, original_counter, rebuilt)


def rewrite_rules(
    rules: list[Any],
    replacements: dict[str, list[str]],
    provider_behaviors: dict[str, str],
) -> list[Any]:
    rewritten: list[Any] = []
    for item in rules:
        if not isinstance(item, str):
            rewritten.append(item)
            continue
        parts = [part.strip() for part in item.split(",")]
        if len(parts) >= 3 and parts[0].upper() == "RULE-SET" and parts[1] in replacements:
            for replacement in replacements[parts[1]]:
                inherited = ["RULE-SET", replacement, *parts[2:]]
                # no-resolve is meaningful for ipcidr providers; keep it only there.
                if provider_behaviors.get(replacement) != "ipcidr":
                    inherited = [part for part in inherited if part != "no-resolve"]
                rewritten.append(",".join(inherited))
        else:
            rewritten.append(item)
    return rewritten


def contains_ruleset(value: Any) -> bool:
    if isinstance(value, str):
        return "RULE-SET" in value.upper()
    if isinstance(value, list):
        return any(contains_ruleset(item) for item in value)
    if isinstance(value, dict):
        return any(contains_ruleset(item) for item in value.values())
    return False


def validate_top_level_rulesets(rules: list[Any], provider_names: set[str]) -> None:
    for item in rules:
        if not isinstance(item, str):
            if contains_ruleset(item):
                raise SystemExit("nested RULE-SET rewriting is not supported")
            continue
        parts = [part.strip() for part in item.split(",")]
        if parts and parts[0].upper() == "RULE-SET":
            if len(parts) < 2 or parts[1] not in provider_names:
                raise SystemExit(f"RULE-SET references missing provider: {parts[1] if len(parts) > 1 else ''}")
        elif "RULE-SET" in item.upper():
            raise SystemExit("nested RULE-SET rewriting is not supported")


def validate_generated_rulesets(rules: list[Any], provider_names: set[str]) -> None:
    validate_top_level_rulesets(rules, provider_names)


def validate_generated_artifacts(dist: Path, providers: dict[str, dict[str, Any]]) -> None:
    for name, provider in providers.items():
        artifact = generated_artifact_path(dist, provider)
        if artifact is not None and not artifact.exists():
            raise SystemExit(f"{name}: generated URL artifact does not exist: {artifact}")


def validate_rule_counts(name: str, original: Counter[str], rebuilt: Counter[str]) -> None:
    missing = original - rebuilt
    unexpected = rebuilt - original
    if missing or unexpected:
        raise SystemExit(
            f"{name}: verification failed; missing={len(missing)} unexpected={len(unexpected)}"
        )


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
    args = parser.parse_args()

    if not args.mihomo and not args.allow_no_mihomo:
        raise SystemExit("mihomo binary not found; install it or pass --allow-no-mihomo for source-only output")

    data = load_yaml(args.input)
    providers = data.get("rule-providers") or {}
    rules = data.get("rules") or []
    if not isinstance(providers, dict) or not isinstance(rules, list):
        raise SystemExit("input must contain rule-providers mapping and rules list")
    validate_top_level_rulesets(rules, set(providers))

    args.dist.mkdir(parents=True, exist_ok=True)
    clean_targets = [
        args.dist / "classical",
        args.dist / "source",
        args.dist / "generated",
        args.dist / "domain",
        args.dist / "ipcidr",
    ]
    for target in clean_targets:
        if target.exists():
            shutil.rmtree(target)

    generated_providers: dict[str, dict[str, Any]] = {}
    provider_behaviors: dict[str, str] = {}
    replacements: dict[str, list[str]] = {}
    options = BuildOptions(
        dist=args.dist,
        base_url=args.base_url,
        mihomo=args.mihomo,
        used_names=set(providers),
        used_paths=set(),
        memory_cache={},
    )

    for name, provider in providers.items():
        if not isinstance(provider, dict):
            raise SystemExit(f"{name}: provider must be a mapping")
        result = process_provider(
            name=name,
            provider=provider,
            options=options,
        )
        overlap = set(generated_providers) & set(result.providers)
        if overlap:
            raise SystemExit(f"generated provider name collision: {', '.join(sorted(overlap))}")
        generated_providers.update(result.providers)
        for generated_name, generated_provider in result.providers.items():
            provider_behaviors[generated_name] = generated_provider["behavior"]
        replacements[name] = result.generated_names
        print(f"{name}: ok ({len(result.original_rules)} rules -> {', '.join(result.generated_names)})")

    rewritten_rules = rewrite_rules(rules, replacements, provider_behaviors)
    validate_generated_rulesets(rewritten_rules, set(generated_providers))
    validate_generated_artifacts(args.dist, generated_providers)
    generated = {
        "rule-providers": generated_providers,
        "rules": rewritten_rules,
    }
    output = args.dist / "generated" / "mihomo-rules.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        yaml.safe_dump(generated, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    print(f"wrote {output}")


if __name__ == "__main__":
    main()
