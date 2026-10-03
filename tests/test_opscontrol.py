"""The control plane's own contract.

These are the rules the rest of the gateway leans on, so they are pinned here
rather than only through the admin endpoints: a decision that degrades to a
per-process view must degrade *visibly*, the hard band must stay unwaivable, and
an unreachable Redis must not take the gateway down or swallow an operator click.
"""

import pytest

from aegis.opscontrol import AUTO, OpsControl


class FakeRedis:
    """Just enough of the sync redis surface that OpsControl touches."""

    def __init__(self, *, fail: bool = False) -> None:
        self.strings: dict[str, str] = {}
        self.sets: dict[str, set[str]] = {}
        self.fail = fail
        self.writes = 0

    def _check(self):
        if self.fail:
            raise ConnectionError("redis down")

    @staticmethod
    def _s(v):
        return v.decode() if isinstance(v, bytes) else str(v)

    def get(self, key):
        self._check()
        v = self.strings.get(key)
        return v.encode() if isinstance(v, str) else v

    def set(self, key, value):
        self._check()
        self.writes += 1
        self.strings[key] = self._s(value)

    def sadd(self, key, member):
        self._check()
        self.writes += 1
        self.sets.setdefault(key, set()).add(self._s(member))

    def srem(self, key, member):
        self._check()
        self.writes += 1
        self.sets.setdefault(key, set()).discard(self._s(member))

    def smembers(self, key):
        self._check()
        return {m.encode() for m in self.sets.get(key, set())}

    def sismember(self, key, member):
        self._check()
        return self._s(member) in self.sets.get(key, set())

    def scan_iter(self, pattern):
        self._check()
        prefix = pattern.rstrip("*")
        keys = [k for k in (*self.strings, *self.sets) if k.startswith(prefix)]
        return [k.encode() for k in keys]

    def delete(self, key):
        self._check()
        self.strings.pop(self._s(key), None)
        self.sets.pop(self._s(key), None)


def test_local_only_defaults_to_allow_everything():
    """A fresh gateway must not refuse anyone. These are all opt-in."""
    ctl = OpsControl()
    assert ctl.killed() is False
    assert ctl.is_paused("acme") is False
    assert ctl.is_allowed("acme") is False
    assert ctl.breaker_override("echo-economy") is None
    assert ctl.snapshot()["shared"] is False


def test_pause_resume_round_trip():
    ctl = OpsControl()
    ctl.pause("acme")
    assert ctl.is_paused("acme") and not ctl.is_paused("other")
    ctl.resume("acme")
    assert not ctl.is_paused("acme")


def test_allow_deny_round_trip_reports_whether_it_did_anything():
    ctl = OpsControl()
    ctl.allow("acme")
    assert ctl.deny("acme") is True, "revoking a live waiver should say so"
    assert ctl.deny("acme") is False, "revoking nothing should not claim it did"
    assert not ctl.is_allowed("acme")


def test_kill_switch_toggles():
    ctl = OpsControl()
    ctl.set_kill(True)
    assert ctl.killed()
    ctl.set_kill(False)
    assert not ctl.killed()


def test_breaker_override_accepts_auto_as_handover():
    ctl = OpsControl()
    ctl.set_breaker("echo-economy", "open")
    assert ctl.breaker_override("echo-economy") == "open"
    ctl.set_breaker("echo-economy", AUTO)
    assert ctl.breaker_override("echo-economy") is None


def test_breaker_rejects_a_state_it_cannot_honour():
    with pytest.raises(ValueError, match="unknown breaker state"):
        OpsControl().set_breaker("echo-economy", "ajar")


def test_decisions_are_shared_across_instances_through_redis():
    """The whole point: one pod pauses, every pod honours it."""
    shared = FakeRedis()
    pod_a, pod_b = OpsControl(shared), OpsControl(shared)
    pod_a.pause("acme")
    pod_a.allow("acme")
    pod_a.set_kill(True)
    pod_a.set_breaker("echo-economy", "open")

    assert pod_b.is_paused("acme")
    assert pod_b.is_allowed("acme")
    assert pod_b.killed()
    assert pod_b.breaker_override("echo-economy") == "open"
    assert pod_b.snapshot()["shared"] is True

    pod_b.resume("acme")
    assert not pod_a.is_paused("acme"), "the decision must travel back too"


def test_redis_outage_degrades_to_the_local_view_instead_of_raising():
    """An unreachable control plane must not take the gateway down with it."""
    broken = FakeRedis(fail=True)
    ctl = OpsControl(broken)
    # These are the calls on the request path. None of them may raise.
    assert ctl.killed() is False
    assert ctl.is_paused("acme") is False
    assert ctl.is_allowed("acme") is False
    assert ctl.breaker_override("echo-economy") is None
    assert ctl.snapshot()["paused_tenants"] == []


def test_redis_outage_does_not_turn_an_operator_click_into_a_500():
    ctl = OpsControl(FakeRedis(fail=True))
    ctl.pause("acme")  # must not raise
    ctl.allow("acme")
    ctl.set_kill(True)
    ctl.set_breaker("echo-economy", "open")
    ctl.clear()


def test_snapshot_reports_the_whole_plane():
    ctl = OpsControl()
    ctl.pause("acme")
    ctl.allow("other")
    ctl.set_breaker("echo-premium", "closed")
    assert ctl.snapshot() == {
        "killed": False,
        "paused_tenants": ["acme"],
        "allowed_tenants": ["other"],
        "breaker_overrides": {"echo-premium": "closed"},
        "shared": False,
    }


def test_clear_resets_local_and_redis_so_tests_cannot_leak_into_each_other():
    shared = FakeRedis()
    ctl = OpsControl(shared)
    ctl.pause("acme")
    ctl.allow("acme")
    ctl.set_kill(True)
    ctl.set_breaker("echo-economy", "open")

    ctl.clear()

    snap = ctl.snapshot()
    assert snap == {
        "killed": False,
        "paused_tenants": [],
        "allowed_tenants": [],
        "breaker_overrides": {},
        "shared": True,
    }
    assert not shared.strings and not shared.sets


def test_redis_stays_authoritative_so_a_stale_local_value_cannot_resurrect_an_override():
    """A breaker handed back to `auto` is deleted in Redis. If the local view
    still remembered "open", falling back to it would silently keep the
    provider fenced off after the operator said to let it through."""
    shared = FakeRedis()
    ctl = OpsControl(shared)
    ctl.set_breaker("echo-economy", "open")
    assert ctl.breaker_override("echo-economy") == "open"

    ctl.set_breaker("echo-economy", AUTO)
    # The local entry is gone, so prove the point with one left behind on purpose.
    with ctl._lock:  # noqa: SLF001 — reaching in to simulate a stale process view
        ctl._breakers["echo-economy"] = "open"

    assert ctl.breaker_override("echo-economy") is None


def test_keys_are_namespaced_so_they_cannot_collide_with_audit_or_cache():
    shared = FakeRedis()
    ctl = OpsControl(shared)
    ctl.pause("acme")
    ctl.set_kill(True)
    assert all(k.startswith("aegis:ctl:") for k in (*shared.strings, *shared.sets))
