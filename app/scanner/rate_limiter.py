import time
import threading
import logging

logger = logging.getLogger(__name__)


class TokenBucketRateLimiter:
    """Token-bucket rate limiter for GitHub API (10 req/min for code search)."""

    def __init__(self, tokens_per_minute: int = 10):
        self.capacity = tokens_per_minute
        self.tokens = float(tokens_per_minute)
        self.refill_rate = tokens_per_minute / 60.0  # tokens per second
        self.last_refill = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def acquire(self, timeout: float = 120.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(1.0, remaining))

    def adapt_from_headers(self, remaining: int, reset_timestamp: int):
        """Adapt rate based on GitHub X-RateLimit-* headers."""
        with self._lock:
            now = time.time()
            seconds_until_reset = max(1, reset_timestamp - int(now))
            if remaining <= 2:
                logger.warning(
                    "GitHub rate limit nearly exhausted (%d left), sleeping %ds",
                    remaining,
                    seconds_until_reset,
                )
                self.tokens = 0.0
                time.sleep(seconds_until_reset)
                self.tokens = float(self.capacity)
                self.last_refill = time.monotonic()
            elif remaining < 5:
                self.tokens = min(self.tokens, 1.0)
