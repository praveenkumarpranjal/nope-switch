"""Lightweight, thread-safe Prometheus / OpenTelemetry metrics registry for nope-core."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any, TypeVar

T = TypeVar("T", bound="Metric")


class Metric:
    def __init__(self, name: str, help_text: str, label_names: list[str]) -> None:
        self.name = name
        self.help_text = help_text
        self.label_names = tuple(label_names)
        self._lock = threading.Lock()

    def _label_key(self, labels: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
        if not self.label_names:
            return ()
        labels = labels or {}
        return tuple((k, str(labels.get(k, ""))) for k in self.label_names)

    def _format_labels(self, key: tuple[tuple[str, str], ...]) -> str:
        if not key:
            return ""
        items = [f'{k}="{v}"' for k, v in key]
        return "{" + ",".join(items) + "}"

    def reset(self) -> None:
        pass

    def collect(self) -> list[str]:
        return []


class Counter(Metric):
    def __init__(self, name: str, help_text: str, label_names: list[str] | None = None) -> None:
        super().__init__(name, help_text, label_names or [])
        self._values: dict[tuple[tuple[str, str], ...], float] = {}

    def reset(self) -> None:
        with self._lock:
            self._values.clear()

    def inc(self, amount: float = 1.0, labels: dict[str, str] | None = None) -> None:
        key = self._label_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def collect(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} counter"]
        with self._lock:
            if not self._values and not self.label_names:
                lines.append(f"{self.name} 0")
            for key, val in sorted(self._values.items()):
                lbls = self._format_labels(key)
                lines.append(f"{self.name}{lbls} {val}")
        return lines


class Gauge(Metric):
    def __init__(self, name: str, help_text: str, label_names: list[str] | None = None) -> None:
        super().__init__(name, help_text, label_names or [])
        self._values: dict[tuple[tuple[str, str], ...], float] = {}

    def reset(self) -> None:
        with self._lock:
            self._values.clear()

    def set(self, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._label_key(labels)
        with self._lock:
            self._values[key] = value

    def inc(self, amount: float = 1.0, labels: dict[str, str] | None = None) -> None:
        key = self._label_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def dec(self, amount: float = 1.0, labels: dict[str, str] | None = None) -> None:
        key = self._label_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) - amount

    def collect(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} gauge"]
        with self._lock:
            if not self._values and not self.label_names:
                lines.append(f"{self.name} 0")
            for key, val in sorted(self._values.items()):
                lbls = self._format_labels(key)
                lines.append(f"{self.name}{lbls} {val}")
        return lines


class Histogram(Metric):
    DEFAULT_BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)

    def __init__(
        self,
        name: str,
        help_text: str,
        label_names: list[str] | None = None,
        buckets: tuple[float, ...] | None = None,
    ) -> None:
        super().__init__(name, help_text, label_names or [])
        self.buckets = buckets or self.DEFAULT_BUCKETS
        self._counts: dict[tuple[tuple[str, str], ...], int] = {}
        self._sums: dict[tuple[tuple[str, str], ...], float] = {}
        self._bucket_counts: dict[tuple[tuple[str, str], ...], dict[float, int]] = {}

    def observe(self, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._label_key(labels)
        with self._lock:
            self._counts[key] = self._counts.get(key, 0) + 1
            self._sums[key] = self._sums.get(key, 0.0) + value
            if key not in self._bucket_counts:
                self._bucket_counts[key] = {b: 0 for b in self.buckets}
            for b in self.buckets:
                if value <= b:
                    self._bucket_counts[key][b] += 1

    def time(self, labels: dict[str, str] | None = None) -> _Timer:
        return _Timer(self, labels)

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()
            self._sums.clear()
            self._bucket_counts.clear()

    def collect(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} histogram"]
        with self._lock:
            for key, count in sorted(self._counts.items()):
                base_dict = dict(key)
                # Buckets
                cum = 0
                for b in self.buckets:
                    cum = self._bucket_counts[key][b]
                    lbls = self._format_labels(tuple(sorted({**base_dict, "le": str(b)}.items())))
                    lines.append(f"{self.name}_bucket{lbls} {cum}")
                inf_lbls = self._format_labels(tuple(sorted({**base_dict, "le": "+Inf"}.items())))
                lines.append(f"{self.name}_bucket{inf_lbls} {count}")
                sum_lbls = self._format_labels(key)
                lines.append(f"{self.name}_sum{sum_lbls} {self._sums[key]}")
                lines.append(f"{self.name}_count{sum_lbls} {count}")
        return lines


class _Timer:
    def __init__(self, histogram: Histogram, labels: dict[str, str] | None) -> None:
        self.histogram = histogram
        self.labels = labels
        self.start = 0.0

    def __enter__(self) -> _Timer:
        self.start = time.perf_counter()
        return self

    def __exit__(self, *args: Any) -> None:
        duration = time.perf_counter() - self.start
        self.histogram.observe(duration, self.labels)


class MetricsRegistry:
    def __init__(self) -> None:
        self._metrics: list[Metric] = []
        self._collectors: list[Callable[[], None]] = []

    def register(self, metric: T) -> T:
        self._metrics.append(metric)
        return metric

    def add_collector(self, callback: Callable[[], None]) -> None:
        self._collectors.append(callback)

    def reset(self) -> None:
        for metric in self._metrics:
            metric.reset()

    def generate_prometheus(self) -> str:
        for cb in self._collectors:
            try:
                cb()
            except Exception:
                pass
        output: list[str] = []
        for metric in self._metrics:
            output.extend(metric.collect())
        return "\n".join(output) + "\n"


REGISTRY = MetricsRegistry()

# Built-in Core Metrics
NOPE_REQUEST_DURATION = REGISTRY.register(
    Histogram("nope_request_duration_seconds", "HTTP request duration in seconds", ["method", "endpoint"])
)
NOPE_VALIDATION_DURATION = REGISTRY.register(
    Histogram("nope_validation_duration_seconds", "Rule Lab validation duration in seconds", ["status"])
)
NOPE_SCARS_TOTAL = REGISTRY.register(
    Gauge("nope_scars_total", "Total scars count in ledger by status", ["status", "organization_id"])
)
NOPE_CI_FAILURES_TOTAL = REGISTRY.register(
    Counter("nope_ci_failures_total", "Total CI failures observed", ["scar_number", "repository"])
)
NOPE_EXCEPTIONS_TOTAL = REGISTRY.register(
    Gauge("nope_exceptions_total", "Total exceptions count by status", ["status", "organization_id"])
)
NOPE_ACTIVE_RULES_TOTAL = REGISTRY.register(
    Gauge("nope_active_rules_total", "Total active rules compiled", ["organization_id"])
)

