"""Unified artifact and segment identifier validation and filesystem containment."""
from __future__ import annotations

import re
from pathlib import Path


# Safe identifier: alphanumeric, dots, _, dashes.
# Explicitly rejects: empty, '.', '..', '/', '\', control characters, whitespace.
ARTIFACT_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def is_valid_artifact_id(name: str) -> bool:
    if not isinstance(name, str) or not name:
        return False
    if name in {".", ".."}:
        return False
    if "\x00" in name or "/" in name or "\\" in name:
        return False
    return bool(ARTIFACT_ID_RE.fullmatch(name))


def validate_artifact_id(name: str, context: str = "artifact identifier") -> str:
    """Validate that name is a safe artifact / segment / group identifier.

    Raises SystemExit on violation to maintain converter CLI error convention.
    """
    if not isinstance(name, str) or not name.strip():
        raise SystemExit(f"{context}: must be a non-empty string")
    if name in {".", ".."}:
        raise SystemExit(f"{context}: dangerous path reference is not allowed: {name!r}")
    if "/" in name or "\\" in name or "\x00" in name:
        raise SystemExit(f"{context}: path separator or control character not allowed: {name!r}")
    if not ARTIFACT_ID_RE.fullmatch(name):
        raise SystemExit(f"{context}: contains unsupported characters: {name!r}")
    return name


def ensure_path_within(target: Path, expected_root: Path, context: str = "output path") -> Path:
    """Verify that target resolves strictly within expected_root to prevent path escape."""
    resolved_root = expected_root.resolve()
    resolved_target = target.resolve()
    if not resolved_target.is_relative_to(resolved_root):
        raise SystemExit(f"{context} escapes root directory: {target} (outside {expected_root})")
    return resolved_target
