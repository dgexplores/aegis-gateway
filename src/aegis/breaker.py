"""Per-provider circuit breaker (CLOSED -> OPEN -> HALF_OPEN -> CLOSED).

Prevents cascade failure when an upstream LLM provider degrades. Trips after
`failure_threshold` consecutive failures; stays OPEN for `recovery_seconds`,
then admits probe requests in HALF_OPEN."""

import time
from enum import Enum


class State(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class BreakerOpen(Exception):
    pass


class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 5, recovery_seconds: float = 15.0) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_seconds = recovery_seconds
        self.state = State.CLOSED
        self.failures = 0
        self.opened_at = 0.0
        self.successes = 0

    def before_call(self) -> None:
        if self.state == State.OPEN:
            if time.time() - self.opened_at >= self.recovery_seconds:
                self.state = State.HALF_OPEN
                self.successes = 0
            else:
                raise BreakerOpen(f"provider '{self.name}' circuit open")

    def record_success(self) -> None:
        self.failures = 0
        if self.state == State.HALF_OPEN:
            self.successes += 1
            if self.successes >= 2:
                self.state = State.CLOSED
        elif self.state == State.CLOSED:
            return

    def record_failure(self) -> None:
        self.failures += 1
        if self.state == State.HALF_OPEN or self.failures >= self.failure_threshold:
            self.state = State.OPEN
            self.opened_at = time.time()

    def snapshot(self) -> dict:
        return {
            "provider": self.name,
            "state": self.state.value,
            "consecutive_failures": self.failures,
        }
