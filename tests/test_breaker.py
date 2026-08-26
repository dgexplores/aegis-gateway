import pytest

from aegis.breaker import BreakerOpen, CircuitBreaker


def test_opens_after_threshold():
    b = CircuitBreaker("prov", failure_threshold=3, recovery_seconds=60)
    for _ in range(2):
        b.record_failure()
        b.before_call()  # still closed
    b.record_failure()
    with pytest.raises(BreakerOpen):
        b.before_call()
    assert b.state.value == "open"


def test_half_open_then_close_on_successes():
    import time
    b = CircuitBreaker("prov", failure_threshold=1, recovery_seconds=0)
    b.record_failure()
    time.sleep(0.01)
    b.before_call()  # enters half-open
    assert b.state.value == "half_open"
    b.record_success()
    b.record_success()
    assert b.state.value == "closed"


def test_failure_in_half_open_reopens():
    import time
    b = CircuitBreaker("prov", failure_threshold=1, recovery_seconds=0)
    b.record_failure()
    time.sleep(0.01)
    b.before_call()
    b.record_failure()
    assert b.state.value == "open"
