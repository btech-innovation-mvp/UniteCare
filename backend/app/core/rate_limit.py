"""In-memory authentication rate limiter.

Architecture Constraints and Limitations:
- Process-Local Scope: The InMemoryRateLimiter stores timestamps strictly in Python process memory.
  It is NOT shared across multiple Uvicorn worker processes, containers, or distributed replicas.
- Multi-Worker / Replica Deployments: In a production multi-worker or Kubernetes deployment,
  requests from a client routed to different worker processes will maintain independent buckets.
  A shared external rate limiter (such as Redis-backed sliding window or an API Gateway/reverse proxy)
  is required for horizontal multi-replica production environments.
- Thread Safety: Uses threading.Lock to synchronize concurrent requests within the single process.
"""

import threading
import time
from collections import defaultdict

from fastapi import HTTPException, Request, status


class InMemoryRateLimiter:
    """Thread-safe sliding-window rate limiter using in-memory timestamps."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str, max_requests: int, window_seconds: int = 60) -> tuple[bool, int]:
        """Check if request is allowed under sliding window limit.

        Args:
            key: Unique bucket identifier (e.g. 'login:127.0.0.1').
            max_requests: Maximum allowed requests within window.
            window_seconds: Window duration in seconds.

        Returns:
            Tuple of (is_allowed: bool, retry_after_seconds: int).
        """
        now = time.monotonic()
        cutoff = now - window_seconds

        with self._lock:
            # Purge timestamps outside the window
            timestamps = self._requests[key]
            valid_timestamps = [t for t in timestamps if t > cutoff]

            if len(valid_timestamps) >= max_requests:
                # Calculate remaining time until oldest request falls out
                oldest = valid_timestamps[0]
                retry_after = max(1, int(oldest + window_seconds - now))
                self._requests[key] = valid_timestamps
                return False, retry_after

            valid_timestamps.append(now)
            self._requests[key] = valid_timestamps
            return True, 0

    def reset(self) -> None:
        """Clear all rate limit buckets (useful for test resets)."""
        with self._lock:
            self._requests.clear()


# Global in-memory rate limiter instance
limiter = InMemoryRateLimiter()


def enforce_rate_limit(
    request: Request, action: str, max_requests: int, window_seconds: int = 60
) -> None:
    """FastAPI utility to enforce rate limits per client IP."""
    client_ip = request.client.host if request.client else "unknown"
    bucket_key = f"{action}:{client_ip}"

    allowed, retry_after = limiter.check(
        bucket_key, max_requests=max_requests, window_seconds=window_seconds
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many {action} attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
