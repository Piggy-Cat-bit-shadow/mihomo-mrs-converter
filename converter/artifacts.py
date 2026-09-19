"""Artifact paths, payload serialization and atomic publication primitives."""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from .timing import observe_external


def write_yaml_payload(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"payload": rules}, allow_unicode=True, sort_keys=False), encoding="utf-8")


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


def public_url(base_url: str, *parts: str) -> str:
    return "/".join([base_url.rstrip("/"), *[part.strip("/") for part in parts]])


def dist_relative_from_url(url: str) -> Path | None:
    if "/dist/" not in url:
        return None
    relative = Path(url.split("/dist/", 1)[1])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"artifact URL escapes dist: {url}")
    return relative


def generated_artifact_path(dist: Path, provider: dict[str, Any]) -> Path | None:
    relative = dist_relative_from_url(str(provider.get("url", "")))
    if relative is None:
        return None
    candidate = (dist / relative).resolve()
    if not candidate.is_relative_to(dist.resolve()):
        raise ValueError(f"artifact path escapes dist: {candidate}")
    return candidate


def convert_source_to_mrs(mihomo: str, behavior: str, source: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    observe_external(
        "mihomo",
        f"convert-ruleset {behavior} {source.name}",
        subprocess.run,
        [mihomo, "convert-ruleset", behavior, "yaml", str(source), str(output)],
        check=True,
        capture_output=True,
        text=True,
    )
