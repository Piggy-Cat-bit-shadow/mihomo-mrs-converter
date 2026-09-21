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
    notes: dict[str, str] = field(default_factory=dict)

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

    def merge(self, other: "BuildTiming") -> None:
        for label, value in other.phases.items():
            self.phases[label] = self.phases.get(label, 0.0) + value
        self.skipped.update(other.skipped)
        self.notes.update(other.notes)
        for kind, source in other.external.items():
            target = self.external.setdefault(kind, ExternalTiming())
            target.calls += source.calls
            target.seconds += source.seconds
            if source.slowest_seconds > target.slowest_seconds:
                target.slowest_seconds = source.slowest_seconds
                target.slowest_label = source.slowest_label

    def print_report(self) -> None:
        print("========== Build Timing ==========")
        for label in ("provider prefetch", "provider processing", "optimize config", "materialize Mihomo", "validate final config", "Egern export", "Loon export", "Sing-box route export", "Sing-box DNS export", "DNS export", "parallel exporter wall-clock", "audit", "total build"):
            suffix = " / skipped" if label in self.skipped else ""
            print(f"{label + ':':<28}{self.phases.get(label, 0.0):>8.2f}s{suffix}")
        for label, value in sorted(self.notes.items()):
            print(f"{label + ':':<28}{value}")
        for kind, stats in sorted(self.external.items()):
            print(f"external {kind} calls:       {stats.calls} calls, {stats.seconds:.2f}s")
        print("==================================")

    def to_markdown_summary(self) -> str:
        lines: list[str] = [
            "### ⏱️ Build Performance Summary\n",
            "| Phase | Duration | Status |",
            "| :--- | :--- | :--- |",
        ]
        for label in (
            "provider prefetch",
            "provider processing",
            "optimize config",
            "materialize Mihomo",
            "validate final config",
            "Egern export",
            "Loon export",
            "Sing-box route export",
            "Sing-box DNS export",
            "DNS export",
            "parallel exporter wall-clock",
            "audit",
            "total build",
        ):
            if label in self.phases or label in self.skipped:
                duration = f"{self.phases.get(label, 0.0):.2f}s"
                status = "Skipped" if label in self.skipped else "Completed"
                lines.append(f"| {label} | `{duration}` | {status} |")

        if self.notes:
            lines.append("\n#### 📦 Build Notes & Metrics\n")
            lines.append("| Metric | Value |")
            lines.append("| :--- | :--- |")
            for label, value in sorted(self.notes.items()):
                lines.append(f"| {label} | `{value}` |")

        if self.external:
            lines.append("\n#### ⚙️ External Binaries\n")
            lines.append("| Binary | Calls | Total Time | Slowest Call |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for kind, stats in sorted(self.external.items()):
                slowest = f"{stats.slowest_seconds:.2f}s ({stats.slowest_label})" if stats.slowest_label else f"{stats.slowest_seconds:.2f}s"
                lines.append(f"| `{kind}` | {stats.calls} | `{stats.seconds:.2f}s` | `{slowest}` |")

        lines.append("")
        return "\n".join(lines)

    def write_step_summary(self) -> None:
        import os
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            try:
                with open(summary_path, "a", encoding="utf-8") as f:
                    f.write(self.to_markdown_summary() + "\n")
            except Exception as exc:
                print(f"Warning: failed to write GITHUB_STEP_SUMMARY: {exc}")



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
