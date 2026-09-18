"""Artifact paths, payload serialization and atomic publication primitives."""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

import yaml


def write_yaml_payload(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"payload": rules}, allow_unicode=True, sort_keys=False), encoding="utf-8")


def read_yaml_payload(path: Path) -> list[str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    values = data.get("payload") if isinstance(data, dict) else data
    if not isinstance(values, list):
        raise ValueError(f"{path}: expected YAML payload list")
    return [str(item) for item in values]


def write_yaml_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        yaml.safe_dump(data, handle, allow_unicode=True, sort_keys=False)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def write_text_atomic(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(data)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def write_text_payload(path: Path, rules: list[str]) -> None:
    write_text_atomic(path, "\n".join(rules) + "\n")


def copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def copy_tree_contents(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    for path in source.rglob("*"):
        if path.is_file():
            copy_file(path, destination / path.relative_to(source))


def public_url(base_url: str, *parts: str) -> str:
    return "/".join([base_url.rstrip("/"), *[part.strip("/") for part in parts]])


def dist_relative_from_url(url: str) -> Path | None:
    return Path(url.split("/dist/", 1)[1]) if "/dist/" in url else None


def generated_artifact_path(dist: Path, provider: dict[str, Any]) -> Path | None:
    relative = dist_relative_from_url(str(provider.get("url", "")))
    return dist / relative if relative is not None else None


def validate_http_url(name: str, url: str) -> None:
    if urlparse(url).scheme.lower() not in {"http", "https"}:
        raise SystemExit(f"{name}: unsupported provider URL scheme")


def convert_source_to_mrs(mihomo: str, behavior: str, source: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([mihomo, "convert-ruleset", behavior, "yaml", str(source), str(output)], check=True, capture_output=True, text=True)
