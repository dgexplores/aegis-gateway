"""Tiny Prometheus text-format metrics registry (no client dependency)."""

import time
from collections import defaultdict


class Metrics:
    def __init__(self) -> None:
        self._counters: dict[str, float] = defaultdict(float)
        self._start = time.time()

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        label_str = "".join(f'{k}="{v}",' for k, v in sorted(labels.items()))
        key = f"{name}{{{label_str}}}"
        self._counters[key] += value

    def render(self) -> str:
        lines = [
            "# HELP aegis_uptime_seconds gateway uptime",
            "# TYPE aegis_uptime_seconds gauge",
            f"aegis_uptime_seconds {time.time() - self._start:.0f}",
        ]
        # One `# TYPE` line per metric NAME, not per labelled series. Emitting it
        # once per series produced duplicate TYPE lines for the same metric, which
        # the Prometheus text parser rejects — scrapes (and promtool) would fail.
        names = sorted({key.split("{", 1)[0] for key in self._counters})
        for name in names:
            lines.append(f"# TYPE {name} counter")
        for key, val in sorted(self._counters.items()):
            lines.append(f"{key} {val}")
        return "\n".join(lines) + "\n"


metrics = Metrics()
