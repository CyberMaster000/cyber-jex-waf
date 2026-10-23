"""Prometheus metrics shared by the detection API and enforcement gateway."""

from __future__ import annotations

import os
import secrets

from fastapi import Header, HTTPException
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.responses import Response

REQUESTS = Counter(
    "waf_requests_total",
    "Requests evaluated by the WAF",
    ["service", "method", "decision"],
)
LATENCY = Histogram(
    "waf_request_duration_seconds",
    "WAF request processing latency",
    ["service"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
SCORE = Histogram(
    "waf_model_score",
    "Distribution of model decision scores",
    ["service"],
    buckets=(-10, -5, -2, -1, 0, 1, 3, 5, 8, 10, 15),
)
BLOCKED = Counter(
    "waf_blocked_total",
    "Requests blocked by rule or model",
    ["service", "reason_class"],
)
RATE_LIMITED = Counter(
    "waf_rate_limited_total",
    "Requests rejected by the gateway rate limiter",
)
CACHE = Counter(
    "waf_score_cache_total",
    "Score cache results",
    ["result"],
)
MODEL_LOADED = Gauge(
    "waf_model_loaded",
    "1 when the detection model is loaded and ready",
)


async def metrics_auth(x_metrics_token: str = Header(default="")) -> None:
    expected = os.environ.get("WAF_METRICS_TOKEN", "")
    if expected and not secrets.compare_digest(x_metrics_token, expected):
        raise HTTPException(status_code=401, detail="Invalid metrics token")


def metrics_response() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
