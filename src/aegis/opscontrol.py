"""Operator control plane: pause, kill, allow and breaker overrides.

Counters, breaker state and the RAG index are per-process. That is fine for
observability and wrong for a decision an operator makes in an incident: if an
operator pauses a noisy tenant, every other pod must honour it immediately, and
it must still be paused after a restart. So the decisions here live in Redis
when one is configured — production already requires it — and fall back to a
per-process set in development, where the difference is invisible because there
is one process.

What an operator can do, and what they deliberately cannot:

* **pause a tenant** — refuse its traffic at the edge, keep its documents,
  history and budget untouched. Reversible.
* **kill switch** — refuse everything for everyone. For an active incident.
* **allow** — waive the *soft* band for a tenant, so its known-noisy callers
  stop being refused. The hard band is not waivable: an allowlist entry can
  never be a way to switch off injection detection, which is the one guarantee
  this product exists to make.
* **breaker override** — force a provider's circuit open or closed by hand
  instead of waiting for the automatic threshold.

Every mutation is the operator's own action, so the caller audits it into the
same signed chain as everything else: "who paused what, when" has to be
provable too.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

NS = "aegis:ctl"

#: A control plane that cannot be reached must not take the gateway down with it,
#: so every Redis failure degrades to the local view. It is logged rather than
#: swallowed, because "the pause did not take effect" is otherwise invisible —
#: and the local view is per-process, so in a multi-pod deployment it is wrong.
log = logging.getLogger("aegis.opscontrol")

#: Sentinel for a breaker key when the operator hands control back to the
#: automatic threshold logic.
AUTO = "auto"

#: Published demo break-glass secret. Like the demo admin password this is only
#: ever for a local demo, and the production guard refuses to ship it — a known
#: secret in front of the control that halts every tenant is worse than no
#: break-glass at all, which is why an unset secret only warns.
DEMO_BREAKGLASS_PASSWORD = "aegis-demo-glass-2026"  # noqa: S105 — demo secret, checked by prod_guard


class OpsControl:
    """Shared operator decisions, backed by Redis when available.

    Every read degrades to the local view if Redis is unreachable, the same way
    the rate limiter does: an unreachable control plane must not take the
    gateway down with it. Writes are best-effort too, so a Redis outage cannot
    turn an operator's Pause click into a 500.
    """

    def __init__(self, redis_client: Any = None) -> None:
        self.redis = redis_client
        self._lock = threading.Lock()
        self._paused: set[str] = set()
        self._allowed: set[str] = set()
        self._kill = False
        self._breakers: dict[str, str] = {}

    # ----------------------------------------------------------------- reads

    def killed(self) -> bool:
        if self.redis is not None:
            try:
                return self.redis.get(self._key("kill")) == b"1"
            except Exception as exc:  # noqa: BLE001 — degrade, do not fail the request
                log.warning("control plane read failed, using the local view: %s", exc)
        with self._lock:
            return self._kill

    def is_paused(self, tenant: str) -> bool:
        if self.redis is not None:
            try:
                return bool(self.redis.sismember(self._key("paused"), tenant))
            except Exception as exc:  # noqa: BLE001 — degrade, do not fail the request
                log.warning("control plane read failed, using the local view: %s", exc)
        with self._lock:
            return tenant in self._paused

    def is_allowed(self, tenant: str) -> bool:
        """True when this tenant's soft-band refusals are waived by an operator."""
        if self.redis is not None:
            try:
                return bool(self.redis.sismember(self._key("allowed"), tenant))
            except Exception as exc:  # noqa: BLE001 — degrade, do not fail the request
                log.warning("control plane read failed, using the local view: %s", exc)
        with self._lock:
            return tenant in self._allowed

    def breaker_override(self, name: str) -> str | None:
        """``"open"``, ``"closed"``, or ``None`` meaning automatic."""
        state = self._read(self._key("breaker", name))
        if state is None and self.redis is None:
            state = self._local_breaker(name)
        return None if state is None or state == AUTO else state

    # ---------------------------------------------------------------- writes

    def pause(self, tenant: str) -> None:
        self._sadd("paused", tenant)
        with self._lock:
            self._paused.add(tenant)

    def resume(self, tenant: str) -> None:
        self._srem("paused", tenant)
        with self._lock:
            self._paused.discard(tenant)

    def allow(self, tenant: str) -> None:
        self._sadd("allowed", tenant)
        with self._lock:
            self._allowed.add(tenant)

    def deny(self, tenant: str) -> bool:
        """Revoke the soft-band waiver. Returns True if one was in force."""
        had = self.is_allowed(tenant)
        self._srem("allowed", tenant)
        with self._lock:
            self._allowed.discard(tenant)
        return had

    def set_kill(self, on: bool) -> None:
        self._set(self._key("kill"), "1" if on else "0")
        with self._lock:
            self._kill = on

    def set_breaker(self, name: str, state: str) -> None:
        """``state`` is ``"open"``, ``"closed"``, or :data:`AUTO`."""
        if state not in ("open", "closed", AUTO):
            raise ValueError(f"unknown breaker state {state!r}")
        self._set(self._key("breaker", name), state)
        with self._lock:
            if state == AUTO:
                self._breakers.pop(name, None)
            else:
                self._breakers[name] = state

    def clear(self) -> None:
        """Test hook: drop the local view and every Redis key we own."""
        with self._lock:
            self._paused.clear()
            self._allowed.clear()
            self._breakers.clear()
            self._kill = False
        if self.redis is not None:
            try:
                for key in self.redis.scan_iter(f"{NS}:*"):
                    self.redis.delete(key)
            except Exception as exc:  # noqa: BLE001 — a test must not fail on a stub client
                log.debug("control plane clear failed: %s", exc)

    # ----------------------------------------------------------------- state

    def snapshot(self) -> dict[str, Any]:
        """The whole control plane, for the admin UI."""
        return {
            "killed": self.killed(),
            "paused_tenants": self._members("paused", self._paused),
            "allowed_tenants": self._members("allowed", self._allowed),
            "breaker_overrides": self._breaker_state(),
            # The admin UI says so out loud, because a per-process control plane
            # in a multi-pod deployment is a lie waiting to be believed.
            "shared": self.redis is not None,
        }

    # ------------------------------------------------------------- internals

    @staticmethod
    def _key(*parts: str) -> str:
        return ":".join((NS, *parts))

    def _local_breaker(self, name: str) -> str | None:
        with self._lock:
            return self._breakers.get(name)

    def _read(self, key: str) -> str | None:
        if self.redis is None:
            return None
        try:
            raw = self.redis.get(key)
        except Exception:  # noqa: BLE001 — degrade to the local view
            return None
        if raw is None:
            return None
        return raw.decode() if isinstance(raw, bytes) else str(raw)

    def _members(self, name: str, local: set[str]) -> list[str]:
        if self.redis is not None:
            try:
                found = self.redis.smembers(self._key(name)) or set()
                return sorted(m.decode() if isinstance(m, bytes) else str(m) for m in found)
            except Exception as exc:  # noqa: BLE001 — degrade, do not fail the request
                log.warning("control plane read failed, using the local view: %s", exc)
        with self._lock:
            return sorted(local)

    def _breaker_state(self) -> dict[str, str]:
        if self.redis is not None:
            try:
                prefix = self._key("breaker") + ":"
                out: dict[str, str] = {}
                for key in self.redis.scan_iter(f"{prefix}*"):
                    raw_key = key.decode() if isinstance(key, bytes) else str(key)
                    value = self._read(raw_key)
                    if value is not None and value != AUTO:
                        out[raw_key[len(prefix) :]] = value
                return out
            except Exception as exc:  # noqa: BLE001 — degrade, do not fail the request
                log.warning("control plane read failed, using the local view: %s", exc)
        with self._lock:
            return {k: v for k, v in self._breakers.items() if v != AUTO}

    def _set(self, key: str, value: str) -> None:
        if self.redis is None:
            return
        try:
            self.redis.set(key, value)
        except Exception as exc:  # noqa: BLE001 — an operator click must not 500
            log.error("control plane write failed, the decision is local only: %s", exc)

    def _sadd(self, name: str, member: str) -> None:
        if self.redis is None:
            return
        try:
            self.redis.sadd(self._key(name), member)
        except Exception as exc:  # noqa: BLE001 — an operator click must not 500
            log.error("control plane write failed, the decision is local only: %s", exc)

    def _srem(self, name: str, member: str) -> None:
        if self.redis is None:
            return
        try:
            self.redis.srem(self._key(name), member)
        except Exception as exc:  # noqa: BLE001 — an operator click must not 500
            log.error("control plane write failed, the decision is local only: %s", exc)
