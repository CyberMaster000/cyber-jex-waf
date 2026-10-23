"""Small fixed-window rate limiter with an optional Redis backend.

Redis is used when it is reachable (the docker-compose stack provides it).
If Redis is unavailable the limiter degrades to an in-process counter so the
gateway keeps working instead of failing open or crashing.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

from loguru import logger


class RateLimiter:
    def __init__(
        self,
        limit: int = 100,
        window_seconds: int = 60,
        redis_url: Optional[str] = None,
    ) -> None:
        self.limit = max(1, int(limit))
        self.window = max(1, int(window_seconds))
        self._redis = None
        self._redis_failed = False
        self._local: dict[str, tuple[int, int]] = {}
        self._lock = asyncio.Lock()

        if redis_url:
            try:
                import redis.asyncio as redis_async

                self._redis = redis_async.from_url(
                    redis_url, decode_responses=True, socket_timeout=0.25
                )
            except Exception as exc:  # pragma: no cover - optional dependency
                logger.warning("Redis rate limiter unavailable: {}", exc)
                self._redis = None

    async def allow(self, identity: str) -> tuple[bool, int]:
        """Return (allowed, remaining)."""
        window_id = int(time.time()) // self.window
        if self._redis is not None and not self._redis_failed:
            try:
                key = f"waf:rl:{identity}:{window_id}"
                async with self._redis.pipeline(transaction=True) as pipe:
                    pipe.incr(key)
                    pipe.expire(key, self.window + 1)
                    count, _ = await pipe.execute()
                return int(count) <= self.limit, max(0, self.limit - int(count))
            except Exception as exc:
                logger.warning("Redis rate limit check failed, using local fallback: {}", exc)
                self._redis_failed = True

        async with self._lock:
            count, stored_window = self._local.get(identity, (0, window_id))
            if stored_window != window_id:
                count = 0
            count += 1
            self._local[identity] = (count, window_id)
            if len(self._local) > 10_000:
                self._local = {
                    k: v for k, v in self._local.items() if v[1] == window_id
                }
            return count <= self.limit, max(0, self.limit - count)

    async def close(self) -> None:
        if self._redis is not None:
            try:
                await self._redis.aclose()
            except Exception:
                pass
