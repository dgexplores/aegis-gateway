
from aegis.ratelimit import SlidingWindowLimiter


def test_allows_under_limit():
    limiter = SlidingWindowLimiter(limit_per_min=3)
    assert limiter.check("t").allowed
    assert limiter.check("t").allowed
    assert limiter.check("t").remaining == 0


def test_blocks_over_limit():
    limiter = SlidingWindowLimiter(limit_per_min=2)
    limiter.check("t")
    limiter.check("t")
    result = limiter.check("t")
    assert not result.allowed
    assert result.retry_after >= 1


def test_keys_are_isolated():
    limiter = SlidingWindowLimiter(limit_per_min=1)
    assert limiter.check("tenant-a").allowed
    assert limiter.check("tenant-b").allowed
    assert not limiter.check("tenant-a").allowed


def test_window_slides():
    import time as _time
    limiter = SlidingWindowLimiter(limit_per_min=1)
    limiter.check("t")
    assert not limiter.check("t").allowed
    # simulate window passage by backdating the single entry
    limiter._windows["t"][0] -= 61.0
    _time.sleep(0)
    assert limiter.check("t").allowed
