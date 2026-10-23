"""Inline WAF enforcement gateway.

The gateway sits in the request path, asks the detection service for a
decision, returns HTTP 403 for threats, and only then streams clean traffic to
the protected backend.  It also enforces request-size limits, per-client rate
limits (Redis-backed when configured), request IDs and Prometheus metrics.
"""

from __future__ import annotations

import json
import os
import time
from typing import Iterable
from urllib.parse import parse_qsl

import httpx
from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.background import BackgroundTask
from starlette.responses import StreamingResponse

from src.utils.config import get_settings
from src.utils.ipfilter import ip_decision
from src.utils.logger import setup_logger
from src.utils.metrics import (
    BLOCKED,
    LATENCY,
    RATE_LIMITED,
    REQUESTS,
    metrics_auth,
    metrics_response,
)
from src.utils.ratelimit import RateLimiter
from src.utils.request_context import get_request_id, sanitize_request_id, set_request_id

setup_logger()
settings = get_settings()

DETECTION_URL = os.environ.get("WAF_DETECTION_URL", "http://waf-api:8000").rstrip("/")
BACKEND_URL = os.environ.get("WAF_BACKEND_URL", "http://sample-app-1:5001").rstrip("/")
API_KEY = os.environ.get("WAF_API_KEY", "waf-key-dev-001")
RATE_LIMIT = int(os.environ.get("WAF_RATE_LIMIT", "100"))
RATE_WINDOW = int(os.environ.get("WAF_RATE_WINDOW", "60"))
REDIS_URL = os.environ.get("WAF_REDIS_URL", "")
MAX_BODY_BYTES = int(
    os.environ.get("WAF_MAX_BODY_BYTES", getattr(settings.security, "max_body_bytes", 1_048_576))
)
MAX_PATH_LENGTH = int(
    os.environ.get("WAF_MAX_PATH_LENGTH", getattr(settings.security, "max_path_length", 4096))
)
MAX_HEADER_COUNT = int(
    os.environ.get("WAF_MAX_HEADER_COUNT", getattr(settings.security, "max_header_count", 100))
)
MAX_HEADER_BYTES = int(
    os.environ.get("WAF_MAX_HEADER_BYTES", getattr(settings.security, "max_header_bytes", 32768))
)


def _load_routes() -> dict[str, str]:
    """Path-prefix -> backend URL map, longest prefix wins."""
    raw = os.environ.get("WAF_BACKEND_ROUTES", "").strip()
    routes: dict[str, str] = {}
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                routes = {str(k): str(v).rstrip("/") for k, v in parsed.items()}
        except Exception as exc:
            logger.error("Invalid WAF_BACKEND_ROUTES JSON: {}", exc)
    return routes


BACKEND_ROUTES = _load_routes()

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}

app = FastAPI(title="Sentinel WAF Gateway", version="1.0.0")
limiter = RateLimiter(RATE_LIMIT, RATE_WINDOW, REDIS_URL or None)
client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=5.0), follow_redirects=False)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


def _forward_headers(headers: Iterable[tuple[str, str]], request_id: str) -> dict[str, str]:
    forwarded = {k: v for k, v in headers if k.lower() not in HOP_BY_HOP}
    forwarded["x-request-id"] = request_id
    return forwarded


def _response_headers(headers: Iterable[tuple[str, str]]) -> dict[str, str]:
    blocked = HOP_BY_HOP | {"content-type"}
    safe = {k: v for k, v in headers if k.lower() not in blocked}
    safe.setdefault("X-Content-Type-Options", "nosniff")
    safe.setdefault("X-Frame-Options", "DENY")
    safe.setdefault("Referrer-Policy", "no-referrer")
    return safe


def _backend_for(path: str) -> str:
    for prefix in sorted(BACKEND_ROUTES, key=len, reverse=True):
        if path.startswith(prefix):
            return BACKEND_ROUTES[prefix]
    return BACKEND_URL


def _error(status: int, detail: str, request_id: str, extra: dict | None = None) -> JSONResponse:
    body = {"detail": detail, "request_id": request_id}
    if extra:
        body.update(extra)
    return JSONResponse(
        status_code=status, content=body, headers={"X-Request-ID": request_id}
    )


@app.get("/health/live", include_in_schema=False)
async def liveness() -> dict[str, str]:
    return {"status": "alive", "service": "waf-gateway"}


@app.get("/health/ready", include_in_schema=False)
async def readiness() -> Response:
    try:
        response = await client.get(f"{DETECTION_URL}/health/live", timeout=3.0)
        response.raise_for_status()
    except Exception as exc:
        logger.error("Gateway readiness failed: {}", exc)
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    return JSONResponse(content={"status": "ready", "service": "waf-gateway"})


@app.get("/metrics", include_in_schema=False)
async def metrics(token: str = Depends(metrics_auth)):
    return metrics_response()


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def proxy(path: str, request: Request) -> Response:
    request_id = sanitize_request_id(request.headers.get("x-request-id"))
    set_request_id(request_id)
    start = time.time()

    if request.url.path == "/health":
        return JSONResponse(content={"status": "healthy", "service": "waf-gateway"})
    if len(request.url.path) > MAX_PATH_LENGTH:
        return _error(414, "Request path too long", request_id)
    if len(request.headers) > MAX_HEADER_COUNT:
        return _error(431, "Too many request headers", request_id)
    if sum(len(k) + len(v) for k, v in request.headers.items()) > MAX_HEADER_BYTES:
        return _error(431, "Request headers too large", request_id)

    # Reject ambiguous request framing (request-smuggling defence in depth;
    # nginx normally rejects this before it reaches the gateway).
    if request.headers.get("content-length") and request.headers.get("transfer-encoding"):
        return _error(400, "Ambiguous request framing", request_id)

    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_BODY_BYTES:
        return _error(413, f"Request body exceeds {MAX_BODY_BYTES} bytes", request_id)

    client_ip = _client_ip(request)
    ip_state = ip_decision(client_ip)
    if ip_state in {"blocklisted", "not_allowlisted"}:
        REQUESTS.labels("gateway", request.method, "blocked").inc()
        BLOCKED.labels("gateway", "ip_filter").inc()
        logger.warning("IP FILTERED | ip={} state={}", client_ip, ip_state)
        return _error(403, "Client address denied", request_id, {"reason": f"ip_filter:{ip_state}"})
    allowed, _remaining = await limiter.allow(client_ip)
    if not allowed:
        RATE_LIMITED.inc()
        logger.warning("RATE LIMITED | ip={} path={}", client_ip, request.url.path)
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded", "retry_after_seconds": RATE_WINDOW},
            headers={"Retry-After": str(RATE_WINDOW), "X-Request-ID": request_id},
        )

    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_BYTES:
        return _error(413, f"Request body exceeds {MAX_BODY_BYTES} bytes", request_id)

    body_text = raw_body.decode("utf-8", errors="replace")
    base_path = "/" + path
    query = request.url.query
    query_params = dict(parse_qsl(query, keep_blank_values=True))

    headers = {k.lower(): v for k, v in request.headers.items()}
    headers["x-real-ip"] = client_ip
    headers.pop("host", None)

    detect_payload = {
        "method": request.method,
        "path": base_path,
        "headers": headers,
        "body": body_text,
        "query_params": query_params,
    }

    try:
        check = await client.post(
            f"{DETECTION_URL}/check",
            json=detect_payload,
            headers={"X-API-Key": API_KEY, "X-Request-ID": request_id},
            timeout=30.0,
        )
    except Exception as exc:
        logger.error("Detection API unavailable, failing closed: {}", exc)
        REQUESTS.labels("gateway", request.method, "error").inc()
        return _error(503, "WAF detection service unavailable", request_id)

    if check.status_code == 403:
        try:
            detail = check.json()
        except Exception:
            detail = {"decision": "BLOCKED", "reason": "hard_rule"}
        detail["decision"] = "BLOCKED"
        detail["request_id"] = request_id
        reason = str(detail.get("reason", "unknown"))
        logger.warning(
            "BLOCKED | ip={} {} {} | reason={}",
            client_ip,
            request.method,
            request.url.path,
            reason,
        )
        REQUESTS.labels("gateway", request.method, "blocked").inc()
        BLOCKED.labels("gateway", reason.split(":", 1)[0]).inc()
        LATENCY.labels("gateway").observe(time.time() - start)
        return JSONResponse(status_code=403, content=detail)

    if check.status_code not in (200, 204):
        logger.error("Unexpected detection status {}: {}", check.status_code, check.text[:200])
        REQUESTS.labels("gateway", request.method, "error").inc()
        return _error(503, "WAF detection error", request_id)

    backend = _backend_for(base_path)
    target = f"{backend}{base_path}"
    if query:
        target = f"{target}?{query}"

    upstream_request = client.build_request(
        request.method,
        target,
        headers=_forward_headers(request.headers.items(), request_id),
        content=raw_body,
        timeout=30.0,
    )
    try:
        upstream = await client.send(upstream_request, stream=True)
    except httpx.HTTPError as exc:
        logger.error("Backend unreachable for {} {}: {}", request.method, base_path, exc)
        REQUESTS.labels("gateway", request.method, "error").inc()
        return _error(502, "Backend unavailable", request_id)

    REQUESTS.labels("gateway", request.method, "allowed").inc()
    LATENCY.labels("gateway").observe(time.time() - start)
    response = StreamingResponse(
        upstream.aiter_raw(),
        status_code=upstream.status_code,
        headers=_response_headers(upstream.headers.items()),
        media_type=upstream.headers.get("content-type"),
        background=BackgroundTask(upstream.aclose),
    )
    response.headers["X-Request-ID"] = request_id
    return response
