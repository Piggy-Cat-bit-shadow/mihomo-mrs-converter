"""Low-overhead wall-clock timing for the build pipeline."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any, Callable, Iterator


@dataclass
class ExternalTiming:
    calls: int = 0
    seconds: float = 0.0
    slowest_seconds: float = 0.0
    slowest_label: str = ""


@dataclass
class BuildTiming:
    phases: dict[str, float] = field(default_factory=dict)
    skipped: set[str] = field(default_factory=set)
    external: dict[str, ExternalTiming] = field(default_factory=dict)

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        started = perf_counter()
        try:
            yield
        finally:
            self.phases[name] = self.phases.get(name, 0.0) + (perf_counter() - started)

    def mark_skipped(self, name: str) -> None:
        self.phases[name] = 0.0
        self.skipped.add(name)

    def observe_external(self, kind: str, label: str, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        started = perf_counter()
        try:
            return func(*args, **kwargs)
        finally:
            elapsed = perf_counter() - started
            stats = self.external.setdefault(kind, ExternalTiming())
            stats.calls += 1
            stats.seconds += elapsed
            if elapsed > stats.slowest_seconds:
                stats.slowest_seconds = elapsed
                stats.slowest_label = label


_ACTIVE_TIMING: ContextVar[BuildTiming | None] = ContextVar("active_build_timing", default=None)


@contextmanager
def activate(timing: BuildTiming) -> Iterator[None]:
    token = _ACTIVE_TIMING.set(timing)
    try:
        yield
    finally:
        _ACTIVE_TIMING.reset(token)


def current_timing() -> BuildTiming | None:
    return _ACTIVE_TIMING.get()


def observe_external(kind: str, label: str, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    timing = _ACTIVE_TIMING.get()
    if timing is None:
        return func(*args, **kwargs)
    return timing.observe_external(kind, label, func, *args, **kwargs)
