"""Artifact paths, payload serialization and atomic publication primitives."""

import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable

from .timing import BuildTiming, activate, current_timing, observe_external
from .yamlio import dump_yaml


def _replace_with_temp(path: Path, write: Any) -> None:
    """Write through a sibling temporary file and atomically replace ``path``.

    The temporary file is removed if writing fails, so a serialization or disk
    error cannot leave scratch files next to published artifacts or state.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False, newline="\n") as handle:
            temporary = Path(handle.name)
            write(handle)
        os.replace(temporary, path)
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def write_yaml_payload(path: Path, rules: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_yaml({"payload": rules}), encoding="utf-8", newline="\n")


def write_yaml_atomic(path: Path, data: dict[str, Any]) -> None:
    _replace_with_temp(path, lambda handle: dump_yaml(data, handle))


def write_text_atomic(path: Path, data: str) -> None:
    _replace_with_temp(path, lambda handle: handle.write(data))


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


def convert_sources_to_mrs(mihomo: str, jobs: Iterable[tuple[str, Path, Path]]) -> None:
    """Compile independent payloads in parallel; each artifact has its own file."""
    items = list(jobs)
    if not items:
        return
    timing = current_timing()

    def compile_one(item: tuple[str, Path, Path]) -> BuildTiming:
        behavior, source, output = item
        worker_timing = BuildTiming()
        with activate(worker_timing):
            convert_source_to_mrs(mihomo, behavior, source, output)
        return worker_timing

    workers = max(1, min(8, os.cpu_count() or 1, len(items)))
    if workers == 1:
        worker_timings = [compile_one(item) for item in items]
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="mrs") as pool:
            worker_timings = list(pool.map(compile_one, items))
    if timing is not None:
        for worker_timing in worker_timings:
            timing.merge(worker_timing)
