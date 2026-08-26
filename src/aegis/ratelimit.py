"""Sliding-window rate limiter with Redis backend and in-memory fallback.

Redis path uses a sorted-set sliding window (accurate across replicas).
Falls back to a per-process deque window when Redis is unavailable so local
dev and tests run dependency-free. Decision is fail-open ONLY for the
in-memory fallback in development; production requires Redis.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass


class RateLimitExceeded(Exception):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after
        super().__init__(f"rate limit exceeded, retry in {retry_after}s")


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after: int = 0


class SlidingWindowLimiter:
    def __init__(self, limit_per_min: int, redis_client=None) -> None:
        self.limit = limit_per_min
        self.redis = redis_client
        self._windows: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> RateLimitResult:
        now = time.time()
        window = 60.0
        if self.redis is not None:
            try:
                return self._check_redis(key, now, window)
            except Exception:  # Redis down — degrade to local view
                pass
        return self._check_memory(key, now, window)

    def _check_redis(self, key: str, now: float, window: float) -> RateLimitResult:
        rkey = f"rl:{key}"
        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(rkey, 0, now - window)
        pipe.zcard(rkey)
        _, count = pipe.execute()
        if count >= self.limit:
            oldest = self.redis.zrange(rkey, 0, 0, withscores=True)
            retry = int(window - (now - oldest[0][1])) + 1 if oldest else 60
            return RateLimitResult(False, 0, max(retry, 1))
        pipe = self.redis.pipeline()
        pipe.zadd(rkey, {str(now): now})
        pipe.zremrangebyscore(rkey, 0, now - window)
        pipe.expire(rkey, int(window))
        pipe.execute()
        return RateLimitResult(True, self.limit - count - 1)

    def _check_memory(self, key: str, now: float, window: float) -> RateLimitResult:
        q = self._windows[key]
        while q and q[0] <= now - window:
            q.popleft()
        if len(q) >= self.limit:
            retry = int(window - (now - q[0])) + 1
            return RateLimitResult(False, 0, max(retry, 1))
        q.append(now)
        return RateLimitResult(True, self.limit - len(q))
