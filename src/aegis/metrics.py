"""Tiny Prometheus text-format metrics registry (no client dependency)."""

import time
from collections import defaultdict


def _parse_key(key: str) -> tuple[str, dict[str, str]]:
    """Split a counter key back into (metric name, labels).

    `inc` builds keys as `name{k="v",k2="v2",}`. The admin Overview needs to
    aggregate per tenant, which means reading the labels back off — so the
    format has exactly one reader and one writer, here.
    """
    name, _, rest = key.partition("{")
    labels: dict[str, str] = {}
    for pair in rest.rstrip("}").split(","):
        if not pair:
            continue
        k, _, v = pair.partition("=")
        labels[k] = v.strip('"')
    return name, labels


class Metrics:
    def __init__(self) -> None:
        self._counters: dict[str, float] = defaultdict(float)
        self._start = time.time()

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        label_str = "".join(f'{k}="{v}",' for k, v in sorted(labels.items()))
        key = f"{name}{{{label_str}}}"
        self._counters[key] += value

    def uptime_seconds(self) -> float:
        return time.time() - self._start

    def clear(self) -> None:
        """Test hook: drop every counter.

        `metrics` is a module-level singleton, so a test that makes real requests
        leaves its counts behind for every later test. That is not hypothetical:
        the admin Overview tests assert exact per-tenant totals, so one stray
        `/v1/chat` in an unrelated file turns into a failure somewhere else
        entirely. The boot timestamp is left alone — uptime is not a counter, and
        resetting it would make `counters_since` meaningless.
        """
        self._counters.clear()

    def total(self, name: str, **match: str) -> float:
        """Sum every series of `name` whose labels contain `match`.

        Used for the admin Overview's fleet totals. Counters are in-process and
        per-pod, so these are cumulative-since-boot figures, not a time series —
        the API returns the boot time alongside them so a view can say so
        rather than implying 24h of history it does not have.
        """
        total = 0.0
        for key, value in self._counters.items():
            metric, labels = _parse_key(key)
            if metric == name and all(labels.get(k) == v for k, v in match.items()):
                total += value
        return total

    def tenant_totals(self) -> dict[str, dict[str, float]]:
        """Per-tenant requests, blocks and cost, from the labelled counters."""
        out: dict[str, dict[str, float]] = {}

        def slot(tenant: str) -> dict[str, float]:
            return out.setdefault(
                tenant,
                {
                    "requests": 0.0,
                    "blocked": 0.0,
                    "soft_blocked": 0.0,
                    "cost_usd": 0.0,
                    "rate_limited": 0.0,
                    "tokens": 0.0,
                },
            )

        for key, value in self._counters.items():
            metric, labels = _parse_key(key)
            tenant = labels.get("tenant")
            if not tenant:
                continue
            row = slot(tenant)
            if metric == "aegis_requests_total":
                row["requests"] += value
            elif metric == "aegis_injection_blocked_total":
                row["blocked"] += value
            elif metric == "aegis_injection_softblocked_total":
                row["soft_blocked"] += value
            elif metric == "aegis_rate_limited_total":
                row["rate_limited"] += value
            elif metric == "aegis_cost_usd_total":
                row["cost_usd"] += value
            elif metric == "aegis_tokens_total":
                row["tokens"] += value
        return out

    def render(self, tenant: str | None = None) -> str:
        """Render Prometheus text format, optionally scoped to one tenant.

        `tenant=None` renders everything (admin scrapes, global dashboards).
        A tenant id renders only untagged global lines (uptime, TYPE headers
        for visible series) plus that tenant's own `tenant="<id>"` series —
        so a non-admin scrape token can never observe another tenant's usage.
        """
        lines = [
            "# HELP aegis_uptime_seconds gateway uptime",
            "# TYPE aegis_uptime_seconds gauge",
            f"aegis_uptime_seconds {time.time() - self._start:.0f}",
        ]
        # One `# TYPE` line per metric NAME, not per labelled series. Emitting it
        # once per series produced duplicate TYPE lines for the same metric, which
        # the Prometheus text parser rejects — scrapes (and promtool) would fail.
        items = sorted(self._counters.items())
        if tenant is not None:
            marker = f'tenant="{tenant}"'
            items = [(k, v) for k, v in items if marker in k]
        names = sorted({key.split("{", 1)[0] for key, _ in items})
        for name in names:
            lines.append(f"# TYPE {name} counter")
        for key, val in items:
            lines.append(f"{key} {val}")
        return "\n".join(lines) + "\n"


metrics = Metrics()
