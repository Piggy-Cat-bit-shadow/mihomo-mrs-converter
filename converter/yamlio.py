"""Strict YAML loading and a libyaml-backed dumping path.

Provider payloads and generated artifacts are large enough that PyYAML's
pure-Python scanner dominates the build, so loading and dumping use the
libyaml bindings when the installed wheel provides them.  Two behaviours are
kept byte-stable regardless of the backend:

* duplicate mapping keys are rejected for repository-owned configuration;
* strings containing non-BMP characters (for example emoji policy names) are
  emitted by the pure-Python dumper, which keeps them unquoted while libyaml
  would escape them.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_BaseLoader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
_BaseDumper = getattr(yaml, "CSafeDumper", yaml.SafeDumper)


class DuplicateKeyError(ValueError):
    """Raised by the unique-key constructor; carries the offending key position."""

    def __init__(self, key: Any, line: int, column: int) -> None:
        super().__init__(key)
        self.key = key
        self.line = line
        self.column = column


class UniqueKeyLoader(_BaseLoader):  # type: ignore[misc, valid-type]
    """Safe loader that rejects duplicate mapping keys at any depth."""


def _construct_mapping(loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            mark = key_node.start_mark
            raise DuplicateKeyError(key, mark.line + 1, mark.column + 1)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def load_yaml(text: str) -> Any:
    """Load untrusted YAML (provider payloads) with the fastest available parser."""
    return yaml.load(text, Loader=_BaseLoader)


def load_yaml_unique(path: Path) -> Any:
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except DuplicateKeyError as exc:
        raise SystemExit(f"{path}:{exc.line}:{exc.column}: duplicate YAML key: {exc.key!r}") from exc
    except yaml.YAMLError as exc:
        raise SystemExit(f"{path}: invalid YAML: {exc}") from exc


def _pure_python_required(value: Any) -> bool:
    """Return True when libyaml would serialize a string differently."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if not item.isascii() and max(item) > "\uffff":
                return True
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return False


def dump_yaml(data: Any, stream: Any = None, sort_keys: bool = False) -> Any:
    dumper = yaml.SafeDumper if _pure_python_required(data) else _BaseDumper
    return yaml.dump(data, stream, Dumper=dumper, allow_unicode=True, sort_keys=sort_keys)
