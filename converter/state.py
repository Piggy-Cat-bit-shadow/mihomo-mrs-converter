"""Managed ownership state and complete-config refresh helpers."""

from .core import (
    Any,
    MANAGED_STATE_FILENAME,
    Path,
    build_managed_manifest,
    copy_provider_artifacts_to_suite,
    copy_tree_contents,
    hashlib,
    json,
    provider_fingerprint,
    rewrite_provider_for_suite,
    validate_generated_config,
    write_yaml_atomic,
    yaml
)  # shared artifacts and validation primitives

def provider_fingerprint(provider: dict[str, Any]) -> str:
    payload = json.dumps(
        provider,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_managed_manifest(
    suite: str,
    base_url: str,
    providers: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "version": 1,
        "suite": suite,
        "base_url": base_url.rstrip("/"),
        "providers": {
            name: {
                "name": name,
                "url": provider.get("url"),
                "path": provider.get("path"),
                "behavior": provider.get("behavior"),
                "format": provider.get("format"),
                "fingerprint": provider_fingerprint(provider),
            }
            for name, provider in providers.items()
        },
    }


def managed_manifest_path(dist: Path, suite: str) -> Path:
    return dist.parent / ".state" / MANAGED_STATE_FILENAME


def read_managed_manifest(dist: Path, suite: str) -> dict[str, Any] | None:
    path = managed_manifest_path(dist, suite)
    if not path.exists():
        return None
    manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise SystemExit(f"{path}: managed state must be a YAML mapping")
    providers = manifest.get("providers")
    if not isinstance(providers, dict):
        raise SystemExit(f"{path}: managed state missing providers mapping")
    return manifest


def write_managed_manifest(
    dist: Path,
    suite: str,
    base_url: str,
    providers: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    manifest = build_managed_manifest(suite, base_url, providers)
    path = managed_manifest_path(dist, suite)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_yaml_atomic(path, manifest)
    return manifest


def materialize_suite_config(
    config: dict[str, Any],
    suite: str,
    dist: Path,
    base_url: str,
    copy_all_base_outputs: bool = False,
    require_no_orphans: bool = False,
) -> dict[str, Any]:
    suite_root = dist / suite
    if copy_all_base_outputs:
        for folder in ("domain", "ipcidr", "classical", "source"):
            copy_tree_contents(dist / folder, suite_root / folder)
    else:
        for name, provider in config["rule-providers"].items():
            copy_provider_artifacts_to_suite(name, provider, suite, dist)

    suite_config = {
        **{key: value for key, value in config.items() if key not in {"rule-providers", "rules"}},
        "rule-providers": {
            name: rewrite_provider_for_suite(name, provider, suite, base_url)
            for name, provider in config["rule-providers"].items()
        },
        "rules": config["rules"],
    }
    output = suite_root / "generated" / "mihomo-rules.yaml"
    validate_generated_config(dist, suite_config, require_no_orphans=require_no_orphans)
    write_yaml_atomic(output, suite_config)
    return suite_config


