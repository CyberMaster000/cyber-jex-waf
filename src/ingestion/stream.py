import asyncio
from typing import AsyncGenerator, Optional

from loguru import logger

from src.preprocessing.parser import ParsedRequest, parse_http_request
from src.preprocessing.normalizer import normalize_request


class StreamIngester:
    def __init__(self):
        self._queue: asyncio.Queue[ParsedRequest] = asyncio.Queue(maxsize=1000)
        self._running = False

    async def push(self, method: str, url: str, headers: Optional[dict[str, str]] = None, body: str = ""):
        parsed = parse_http_request(method=method, url=url, headers=headers, body=body)
        normalized = normalize_request(parsed)
        try:
            self._queue.put_nowait(normalized)
        except asyncio.QueueFull:
            logger.warning("Stream ingestion queue is full, dropping request")

    async def stream(self) -> AsyncGenerator[ParsedRequest, None]:
        self._running = True
        while self._running:
            try:
                req = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield req
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
        self._running = False

    def stop(self):
        self._running = False
