"""Tiny thread-safe TTL cache for transformer scores.

Transformer inference dominates request latency on CPU.  Repeated or
automated requests (scanners, demos, health probes) often carry identical
payloads, so caching the score avoids re-running the encoder while still
recording every event and recomputing the allow/block decision.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import OrderedDict
from typing import Optional


class ScoreCache:
    def __init__(self, max_entries: int = 2048, ttl_seconds: int = 300) -> None:
        self.max_entries = int(max_entries)
        self.ttl = int(ttl_seconds)
        self._data: "OrderedDict[str, tuple[float, float, str]]" = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def key(raw_request: str) -> str:
        return hashlib.sha256(raw_request.encode("utf-8", errors="replace")).hexdigest()

    def get(self, key: str) -> Optional[tuple[float, str]]:
        now = time.time()
        with self._lock:
            item = self._data.get(key)
            if item is None:
                self.misses += 1
                return None
            score, expires, version = item
            if expires < now:
                self._data.pop(key, None)
                self.misses += 1
                return None
            self._data.move_to_end(key)
            self.hits += 1
            return score, version

    def set(self, key: str, score: float, version: str) -> None:
        now = time.time()
        with self._lock:
            self._data[key] = (score, now + self.ttl, version)
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "entries": len(self._data),
                "hits": self.hits,
                "misses": self.misses,
            }


score_cache = ScoreCache(
    max_entries=int(os.environ.get("WAF_SCORE_CACHE_SIZE", "2048")),
    ttl_seconds=int(os.environ.get("WAF_SCORE_CACHE_TTL", "300")),
)
