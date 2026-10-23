import json
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

import torch
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from loguru import logger
from pydantic import BaseModel

from src.models.transformer import TransformerAutoencoder, ModernBertWAFDetector, SecureBertClassifier, load_waf_model
from src.preprocessing.attack_rules import canonicalize, detect_attack_rules, is_structurally_benign
from src.preprocessing.normalizer import normalize_request
from src.preprocessing.parser import parse_http_request
from src.preprocessing.tokenizer import Tokenizer
from src.storage.db import DetectionEvent, Database, get_db
from src.utils.audit import audit, fingerprint_secret
from src.utils.cache import score_cache
from src.utils.config import get_settings
from src.utils.logger import setup_logger
from src.utils.metrics import (
    BLOCKED,
    CACHE,
    LATENCY,
    MODEL_LOADED,
    REQUESTS,
    SCORE,
    metrics_auth,
    metrics_response,
)
from src.utils.redaction import redact_body, redact_headers, redact_query
from src.utils.request_context import get_request_id, sanitize_request_id, set_request_id

setup_logger()

app = FastAPI(title="WAF Detection API", version="1.0.0")
settings = get_settings()


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    request_id = sanitize_request_id(request.headers.get("x-request-id"))
    set_request_id(request_id)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response

_model: Optional[Union[TransformerAutoencoder, ModernBertWAFDetector, SecureBertClassifier]] = None
_tokenizer: Optional[Tokenizer] = None
_calibration_mtime: Optional[float] = None


def _apply_calibration(force: bool = False) -> None:
    global _calibration_mtime
    path = Path(settings.model.calibration_file)
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.exists():
        return
    mtime = path.stat().st_mtime
    if not force and mtime == _calibration_mtime:
        return
    try:
        data = json.loads(path.read_text())
        threshold = float(data["threshold"])
        settings.model.threshold = threshold
        _calibration_mtime = mtime
        logger.info("Applied calibrated detection threshold {}", threshold)
    except Exception as exc:
        logger.warning("Could not read calibration file {}: {}", path, exc)


def get_model():
    global _model
    if _model is None:
        _model = load_waf_model()
        _model.eval()
        _apply_calibration(force=True)
    else:
        if isinstance(_model, SecureBertClassifier):
            _model.reload_if_changed()
        _apply_calibration()
    return _model


def get_tokenizer() -> Tokenizer:
    global _tokenizer
    if _tokenizer is None:
        _tokenizer = Tokenizer()
    return _tokenizer


@app.on_event("startup")
async def _warmup() -> None:
    # Load the transformer before the first user request so the first request
    # does not pay the cold-start cost (and gateway timeouts do not trigger).
    try:
        get_model()
        MODEL_LOADED.set(1)
        logger.info("WAF model warmed up (threshold={})", settings.model.threshold)
    except Exception as exc:  # pragma: no cover - startup best effort
        MODEL_LOADED.set(0)
        logger.exception("Model warmup failed: {}", exc)


async def verify_api_key(x_api_key: str = Header(default="")):
    if settings.detection_api.api_keys and x_api_key not in settings.detection_api.api_keys:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


async def verify_admin_key(x_api_key: str = Header(default="")):
    admin_keys = getattr(settings.detection_api, "admin_api_keys", []) or getattr(
        settings.update_api, "api_keys", []
    )
    if admin_keys and x_api_key not in admin_keys:
        raise HTTPException(status_code=401, detail="Invalid admin API key")
    return x_api_key


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.headers.get("x-real-ip") or (
        request.client.host if request.client else "unknown"
    )


_dashboard_security = HTTPBasic(auto_error=False)


def verify_dashboard(
    credentials: Optional[HTTPBasicCredentials] = Depends(_dashboard_security),
) -> str:
    if not getattr(settings.detection_api, "require_dashboard_auth", True):
        return "anonymous"
    expected_user = getattr(settings.detection_api, "dashboard_username", "sentinel")
    expected_password = getattr(settings.detection_api, "dashboard_password", "change-me")
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Dashboard authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )
    user_ok = secrets.compare_digest(credentials.username, expected_user)
    pass_ok = secrets.compare_digest(credentials.password, expected_password)
    if not (user_ok and pass_ok):
        raise HTTPException(
            status_code=401,
            detail="Invalid dashboard credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


class DetectRequest(BaseModel):
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = {}
    body: str = ""
    query_params: dict[str, str] = {}


class BatchDetectRequest(BaseModel):
    requests: list[DetectRequest]


class ThresholdUpdate(BaseModel):
    threshold: float


def _build_url(req: DetectRequest) -> str:
    url = req.path
    if req.query_params:
        qs = "&".join(f"{k}={v}" for k, v in req.query_params.items())
        url = f"{url}?{qs}"
    return url


def _score_request(model, tokenizer: Tokenizer, req: DetectRequest, url: str) -> tuple[float, str]:
    if isinstance(model, (ModernBertWAFDetector, SecureBertClassifier)):
        hdr_str = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
        raw_req = f"{req.method} {url} HTTP/1.1\n{hdr_str}\n\n{req.body}".strip()
        cache_key = score_cache.key(f"{model.version}|{raw_req}")
        cached = score_cache.get(cache_key)
        if cached is not None:
            CACHE.labels("hit").inc()
            return cached[0], model.version
        CACHE.labels("miss").inc()

        anomaly_score, _ = model.score_request(raw_req)

        # Percent-encoded payloads are also scored in their decoded form.
        canon_url = canonicalize(url)
        canon_body = canonicalize(req.body)
        if canon_url != url or canon_body != req.body:
            canon_req = f"{req.method} {canon_url} HTTP/1.1\n{hdr_str}\n\n{canon_body}".strip()
            canon_score, _ = model.score_request(canon_req)
            anomaly_score = max(anomaly_score, canon_score)

        score_cache.set(cache_key, anomaly_score, model.version)
        return anomaly_score, model.version

    parsed = parse_http_request(
        method=req.method,
        url=url,
        headers=req.headers,
        body=req.body,
    )
    normalized = normalize_request(parsed)
    input_tensor = tokenizer.encode_request(normalized)
    input_tensor = torch.tensor([input_tensor], dtype=torch.long)

    model.eval()
    with torch.inference_mode():
        logits, latent = model(input_tensor)
        scores = model.compute_anomaly_score(logits, input_tensor)
        anomaly_score = scores.item()
    return anomaly_score, "v1.0"


def _enforce_request_limits(req: DetectRequest) -> None:
    limits = settings.security
    body_size = len(req.body.encode("utf-8", errors="replace"))
    if body_size > limits.max_body_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Request body exceeds {limits.max_body_bytes} bytes",
        )
    if len(req.path) > limits.max_path_length:
        raise HTTPException(status_code=414, detail="Request path too long")
    if len(req.headers) > limits.max_header_count:
        raise HTTPException(status_code=431, detail="Too many request headers")
    header_bytes = sum(len(k) + len(v) for k, v in req.headers.items())
    if header_bytes > limits.max_header_bytes:
        raise HTTPException(status_code=431, detail="Request headers too large")


def _decide(req: DetectRequest, url: str, anomaly_score: float) -> tuple[bool, str, list[str]]:
    """Combine deterministic exploit rules with the ML score.

    Blocking policy (defense in depth):
      1. A high-confidence exploit signature always blocks.
      2. A model score above the threshold blocks, unless the request is a
         well-formed benign request (JSON, XML/SOAP, multipart, form, simple
         query) AND the score is within the suppression ceiling.
      3. Everything else is allowed.
    """
    rules = detect_attack_rules(req.method, url, req.headers, req.body)
    threshold = settings.model.threshold
    max_suppression = getattr(settings.model, "suppression_max_score", 9.5)
    suppression_enabled = getattr(settings.model, "benign_suppression", True)

    if rules:
        return True, "hard_rule:" + ",".join(rules), rules

    if anomaly_score <= threshold:
        return False, "model:clean", []

    if suppression_enabled and anomaly_score <= max_suppression:
        benign_reason = is_structurally_benign(req.method, url, req.headers, req.body)
        if benign_reason:
            return False, f"benign_suppressed:{benign_reason}", []

    return True, "model:anomaly", []


def _run_detection(req: DetectRequest, db: Database, model, tokenizer: Tokenizer) -> dict:
    _enforce_request_limits(req)
    start = time.time()
    url = _build_url(req)

    anomaly_score, model_version = _score_request(model, tokenizer, req, url)
    is_anomaly, reason, rules = _decide(req, url, anomaly_score)

    latency_ms = (time.time() - start) * 1000

    event_headers = req.headers
    event_query = req.query_params
    event_body = req.body[:1000]
    if getattr(settings.storage, "redact_sensitive", True):
        content_type = req.headers.get("content-type", "")
        event_headers = redact_headers(event_headers)
        event_query = redact_query(event_query)
        event_body = redact_body(event_body, content_type)[:1000]

    event = DetectionEvent(
        request_id=get_request_id(),
        method=req.method,
        path=req.path,
        query_params=event_query,
        headers=event_headers,
        body=event_body,
        source_ip=req.headers.get("x-real-ip", req.headers.get("x-forwarded-for", "")),
        user_agent=req.headers.get("user-agent", ""),
        anomaly_score=round(anomaly_score, 6),
        is_anomaly=is_anomaly,
        latency_ms=round(latency_ms, 2),
        model_version=model_version,
    )

    request_id = db.store_event(event)

    decision = "blocked" if is_anomaly else "allowed"
    REQUESTS.labels("detection", req.method, decision).inc()
    LATENCY.labels("detection").observe(latency_ms / 1000.0)
    SCORE.labels("detection").observe(anomaly_score)
    if is_anomaly:
        BLOCKED.labels("detection", reason.split(":", 1)[0]).inc()

    if is_anomaly:
        logger.warning(
            "THREAT BLOCKED | {} {} | score={:.4f} | reason={} | latency={:.1f}ms | id={}",
            req.method, req.path, anomaly_score, reason, latency_ms, request_id,
        )

    return {
        "request_id": request_id,
        "is_anomaly": is_anomaly,
        "decision": "BLOCKED" if is_anomaly else "ALLOWED",
        "reason": reason,
        "matched_rules": rules,
        "anomaly_score": round(anomaly_score, 6),
        "threshold": settings.model.threshold,
        "latency_ms": round(latency_ms, 2),
        "model_version": model_version,
    }


@app.post("/detect")
async def detect(req: DetectRequest, api_key: str = Depends(verify_api_key), db: Database = Depends(get_db)):
    model = get_model()
    tokenizer = get_tokenizer()
    return _run_detection(req, db, model, tokenizer)


@app.post("/check", status_code=204)
async def check(
    req: DetectRequest,
    api_key: str = Depends(verify_api_key),
    db: Database = Depends(get_db),
):
    """Enforcement endpoint: 204 when allowed, 403 when blocked."""
    model = get_model()
    tokenizer = get_tokenizer()
    result = _run_detection(req, db, model, tokenizer)
    if result["decision"] == "BLOCKED":
        return JSONResponse(status_code=403, content=result)
    return Response(status_code=204)


@app.post("/detect/batch")
async def detect_batch(batch: BatchDetectRequest, api_key: str = Depends(verify_api_key), db: Database = Depends(get_db)):
    model = get_model()
    tokenizer = get_tokenizer()
    results = [_run_detection(req, db, model, tokenizer) for req in batch.requests]
    flagged = sum(1 for r in results if r["is_anomaly"])
    return {
        "total": len(results),
        "flagged": flagged,
        "results": results,
    }


@app.get("/logs")
async def get_logs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    anomalies_only: bool = Query(False),
    method: Optional[str] = Query(None),
    path_contains: Optional[str] = Query(None),
    api_key: str = Depends(verify_api_key),
    db: Database = Depends(get_db),
):
    events = db.get_events(limit=limit, offset=offset, anomalies_only=anomalies_only, method=method, path_contains=path_contains)
    return {"total": len(events), "events": events}


@app.post("/replay/{request_id}")
async def replay(request_id: str, api_key: str = Depends(verify_api_key), db: Database = Depends(get_db)):
    event = db.get_event_by_id(request_id)
    if not event:
        raise HTTPException(status_code=404, detail="Request not found")

    req = DetectRequest(
        method=event["method"],
        path=event["path"],
        headers=event.get("headers", {}),
        body=event.get("body", ""),
    )

    model = get_model()
    tokenizer = get_tokenizer()
    result = _run_detection(req, db, model, tokenizer)

    return {
        "original": event,
        "replay_result": result,
    }


@app.get("/stats")
async def get_stats(api_key: str = Depends(verify_api_key), db: Database = Depends(get_db)):
    return db.get_stats()


@app.post("/threshold")
async def update_threshold(
    body: ThresholdUpdate,
    request: Request,
    api_key: str = Depends(verify_admin_key),
):
    previous = settings.model.threshold
    settings.model.threshold = body.threshold
    logger.info("Anomaly threshold updated to {}", body.threshold)
    audit(
        "threshold.update",
        actor=f"key:{fingerprint_secret(api_key)}",
        request_id=get_request_id(),
        source_ip=_client_ip(request),
        details={"previous": previous, "new": body.threshold},
    )
    return {"threshold": body.threshold, "status": "updated"}


@app.post("/clear")
async def clear_history(
    request: Request,
    api_key: str = Depends(verify_admin_key),
    db: Database = Depends(get_db),
):
    deleted_count = db.clear_events()
    audit(
        "history.clear",
        actor=f"key:{fingerprint_secret(api_key)}",
        request_id=get_request_id(),
        source_ip=_client_ip(request),
        details={"deleted": deleted_count},
    )
    return {"status": "cleared", "deleted_count": deleted_count}


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/history")


@app.get("/history", response_class=HTMLResponse)
async def history_page(_user: str = Depends(verify_dashboard)):
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel WAF — Security Operations Console</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #0B0D11;
            --bg-surface: #13161C;
            --bg-surface-elevated: #1A1E26;
            --bg-hover: #222733;
            --border-subtle: #202530;
            --border-strong: #2D3444;
            --text-primary: #F3F4F6;
            --text-secondary: #9CA3AF;
            --text-muted: #6B7280;
            --danger-text: #F87171;
            --danger-bg: rgba(239, 68, 68, 0.12);
            --danger-border: rgba(239, 68, 68, 0.28);
            --success-text: #34D399;
            --success-bg: rgba(16, 185, 129, 0.12);
            --success-border: rgba(16, 185, 129, 0.28);
            --warning-text: #FBBF24;
            --warning-bg: rgba(245, 158, 11, 0.12);
            --accent-brand: #E5E7EB;
            --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: var(--font-sans);
            background-color: var(--bg-base);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }

        /* Top Header */
        header {
            background: var(--bg-surface);
            border-bottom: 1px solid var(--border-subtle);
            padding: 14px 28px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .brand-section {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .brand-logo {
            width: 32px;
            height: 32px;
            background: var(--bg-surface-elevated);
            border: 1px solid var(--border-strong);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .brand-logo svg {
            width: 18px;
            height: 18px;
            fill: #E5E7EB;
        }
        .brand-title {
            font-size: 15px;
            font-weight: 700;
            color: var(--text-primary);
            letter-spacing: -0.01em;
        }
        .brand-subtitle {
            font-size: 12px;
            color: var(--text-secondary);
            font-weight: 500;
        }
        .header-badges {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 5px 12px;
            background: var(--bg-surface-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            font-size: 12px;
            font-weight: 500;
            color: var(--text-secondary);
        }
        .status-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background-color: var(--success-text);
            box-shadow: 0 0 6px rgba(52, 211, 153, 0.6);
        }

        /* Container */
        .app-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px 28px;
        }

        /* Metrics KPI */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 20px;
        }
        .metric-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            padding: 18px 20px;
        }
        .metric-label {
            font-size: 12px;
            color: var(--text-secondary);
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .metric-value {
            font-size: 26px;
            font-weight: 700;
            color: var(--text-primary);
            letter-spacing: -0.02em;
        }
        .metric-sub {
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 4px;
        }

        /* Charts Section */
        .charts-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 16px;
            margin-bottom: 20px;
        }
        .chart-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            padding: 18px 20px;
        }
        .chart-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 14px;
        }
        .chart-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-primary);
        }
        .chart-legend {
            display: flex;
            align-items: center;
            gap: 14px;
            font-size: 11px;
            color: var(--text-secondary);
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .legend-dot {
            width: 8px;
            height: 8px;
            border-radius: 2px;
        }
        .canvas-container {
            width: 100%;
            height: 180px;
            position: relative;
        }
        canvas {
            width: 100%;
            height: 100%;
            display: block;
        }

        /* Controls Panel */
        .controls-panel {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            padding: 14px 18px;
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
            flex-wrap: wrap;
        }
        .filter-group {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }
        .search-box {
            position: relative;
            min-width: 280px;
        }
        .search-box input {
            width: 100%;
            background: var(--bg-surface-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            padding: 8px 12px 8px 34px;
            color: var(--text-primary);
            font-size: 13px;
            outline: none;
            transition: border-color 0.15s;
        }
        .search-box input:focus {
            border-color: var(--border-strong);
            background: var(--bg-surface);
        }
        .search-icon {
            position: absolute;
            left: 10px;
            top: 50%;
            transform: translateY(-50%);
            width: 14px;
            height: 14px;
            fill: var(--text-muted);
        }
        select, .btn-secondary {
            background: var(--bg-surface-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            padding: 8px 12px;
            color: var(--text-primary);
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            outline: none;
            transition: all 0.15s;
        }
        select:hover, .btn-secondary:hover {
            background: var(--bg-hover);
            border-color: var(--border-strong);
        }

        /* Table */
        .table-wrapper {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            overflow: hidden;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 13px;
        }
        thead {
            background: var(--bg-surface-elevated);
            border-bottom: 1px solid var(--border-subtle);
        }
        th {
            padding: 12px 18px;
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        tbody tr {
            border-bottom: 1px solid var(--border-subtle);
            cursor: pointer;
            transition: background 0.12s;
        }
        tbody tr:hover {
            background: var(--bg-hover);
        }
        tbody tr:last-child {
            border-bottom: none;
        }
        td {
            padding: 12px 18px;
            color: var(--text-primary);
        }

        /* Badges */
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            font-family: var(--font-mono);
            letter-spacing: 0.02em;
        }
        .badge-method-get { background: rgba(148, 163, 184, 0.12); color: #CBD5E1; border: 1px solid rgba(148, 163, 184, 0.25); }
        .badge-method-post { background: rgba(168, 85, 247, 0.12); color: #C084FC; border: 1px solid rgba(168, 85, 247, 0.25); }
        .badge-method-put { background: rgba(245, 158, 11, 0.12); color: #FCD34D; border: 1px solid rgba(245, 158, 11, 0.25); }
        .badge-method-delete { background: rgba(244, 63, 94, 0.12); color: #FDA4AF; border: 1px solid rgba(244, 63, 94, 0.25); }

        .badge-threat {
            background: var(--danger-bg);
            color: var(--danger-text);
            border: 1px solid var(--danger-border);
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
        }
        .badge-clean {
            background: var(--success-bg);
            color: var(--success-text);
            border: 1px solid var(--success-border);
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
        }

        .path-code {
            font-family: var(--font-mono);
            font-size: 12px;
            color: #E5E7EB;
            max-width: 440px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            display: inline-block;
        }
        .score-cell {
            font-family: var(--font-mono);
            font-weight: 600;
            font-size: 12px;
        }
        .score-high { color: var(--danger-text); }
        .score-normal { color: var(--text-secondary); }
        .latency-cell {
            color: var(--text-muted);
            font-size: 12px;
            font-family: var(--font-mono);
        }

        /* Floating Tooltip */
        .chart-tooltip {
            position: absolute;
            display: none;
            background: #181C26;
            border: 1px solid #2D3444;
            border-radius: 6px;
            padding: 8px 12px;
            font-size: 11px;
            color: #F3F4F6;
            pointer-events: none;
            z-index: 50;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.5);
            min-width: 140px;
        }
        .tooltip-title { font-weight: 600; margin-bottom: 4px; color: #9CA3AF; }
        .tooltip-row { display: flex; justify-content: space-between; gap: 8px; margin-bottom: 2px; }
        .tooltip-badge { font-weight: 600; font-family: var(--font-mono); }

        /* Detail Drawer */
        .detail-drawer {
            display: none;
            position: fixed;
            top: 0;
            right: 0;
            width: 480px;
            height: 100vh;
            background: var(--bg-surface);
            border-left: 1px solid var(--border-strong);
            box-shadow: -10px 0 30px rgba(0, 0, 0, 0.6);
            z-index: 200;
            padding: 24px;
            overflow-y: auto;
        }
        .detail-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-subtle);
        }
        .detail-title {
            font-size: 15px;
            font-weight: 700;
        }
        .close-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 20px;
            cursor: pointer;
        }
        .close-btn:hover { color: var(--text-primary); }
        .detail-section {
            margin-bottom: 16px;
        }
        .detail-section-title {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 6px;
            font-weight: 600;
        }
        .code-block {
            background: var(--bg-base);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            padding: 10px 12px;
            font-family: var(--font-mono);
            font-size: 11px;
            color: #CBD5E1;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 200px;
            overflow-y: auto;
        }
        .empty-state {
            padding: 48px;
            text-align: center;
            color: var(--text-muted);
            font-size: 13px;
        }
    </style>
</head>
<body>

    <header>
        <div class="brand-section">
            <div class="brand-logo">
                <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
            </div>
            <div>
                <div class="brand-title">Sentinel WAF Console</div>
                <div class="brand-subtitle">Transformer Anomaly Detection & Threat Interceptor</div>
            </div>
        </div>
        <div class="header-badges">
            <div class="status-pill">
                <span class="status-dot"></span>
                <span>ModernBERT (161.7k)</span>
            </div>
            <div class="status-pill">
                <span>Threshold: <strong style="color: var(--text-primary);">1.25</strong></span>
            </div>
        </div>
    </header>

    <div class="app-container">
        <!-- Metrics -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Total Inspected</div>
                <div class="metric-value" id="statTotal">-</div>
                <div class="metric-sub">Live HTTP requests processed</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Threats Blocked</div>
                <div class="metric-value" style="color: var(--danger-text);" id="statAnomalies">-</div>
                <div class="metric-sub" id="statThreatRate">0% block rate</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Clean Traffic</div>
                <div class="metric-value" style="color: var(--success-text);" id="statBenign">-</div>
                <div class="metric-sub">Verified normal traffic</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Mean Loss Index</div>
                <div class="metric-value" id="statAvgScore">-</div>
                <div class="metric-sub">Transformer sequence loss</div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="charts-grid">
            <div class="chart-card">
                <div class="chart-header">
                    <div class="chart-title">Traffic Activity & Threat Stream <span style="font-size: 11px; color: var(--text-muted); font-weight: normal; margin-left: 6px;">(Hover or click points to inspect)</span></div>
                    <div class="chart-legend">
                        <div class="legend-item"><span class="legend-dot" style="background: #94A3B8;"></span> Total Stream</div>
                        <div class="legend-item"><span class="legend-dot" style="background: #F87171;"></span> Threat Anomaly</div>
                    </div>
                </div>
                <div class="canvas-container">
                    <canvas id="timelineChart"></canvas>
                    <div id="timelineTooltip" class="chart-tooltip"></div>
                </div>
            </div>
            <div class="chart-card">
                <div class="chart-header">
                    <div class="chart-title">Method Distribution <span style="font-size: 11px; color: var(--text-muted); font-weight: normal; margin-left: 6px;">(Click slice to filter)</span></div>
                    <div class="chart-legend">
                        <span id="methodSummaryText" style="font-size: 11px; color: var(--text-muted);">Active Stream</span>
                    </div>
                </div>
                <div class="canvas-container">
                    <canvas id="methodChart"></canvas>
                    <div id="methodTooltip" class="chart-tooltip"></div>
                </div>
            </div>
        </div>

        <!-- Controls -->
        <div class="controls-panel">
            <div class="filter-group">
                <div class="search-box">
                    <svg class="search-icon" viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
                    <input type="text" id="pathFilter" placeholder="Search by URI, endpoint, or payload..." oninput="debounceLoad()">
                </div>
                <select id="anomalyFilter" onchange="loadData()">
                    <option value="false">All Traffic</option>
                    <option value="true">Threats Only (Blocked)</option>
                </select>
                <select id="methodFilter" onchange="loadData()">
                    <option value="">All Methods</option>
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                </select>
            </div>
            <div class="filter-group">
                <input type="password" id="apiKey" value="waf-key-dev-001" style="display: none;">
                <button class="btn-secondary" onclick="loadData()">Refresh Stream</button>
                <button class="btn-secondary" style="color: var(--danger-text); border-color: rgba(239, 68, 68, 0.3);" onclick="clearHistory()">Clear History</button>
            </div>
        </div>

        <!-- Table -->
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th style="width: 130px;">Time</th>
                        <th style="width: 80px;">Method</th>
                        <th>Path / Payload</th>
                        <th style="width: 120px;">Threat Score</th>
                        <th style="width: 110px;">Decision</th>
                        <th style="width: 90px;">Latency</th>
                        <th style="width: 90px;">ID</th>
                    </tr>
                </thead>
                <tbody id="eventsTableBody">
                    <tr><td colspan="7" class="empty-state">Loading real-time events...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Detail Drawer -->
    <div class="detail-drawer" id="detailDrawer">
        <div class="detail-header">
            <div class="detail-title">Request Diagnostics</div>
            <button class="close-btn" onclick="closeDrawer()">&times;</button>
        </div>
        <div class="detail-section">
            <div class="detail-section-title">Decision</div>
            <div id="drawerDecision" style="margin-bottom: 6px;"></div>
            <div id="drawerScore" style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary);"></div>
        </div>
        <div class="detail-section">
            <div class="detail-section-title">Target Endpoint</div>
            <div id="drawerEndpoint" class="code-block" style="padding: 8px;"></div>
        </div>
        <div class="detail-section">
            <div class="detail-section-title">Query Parameters</div>
            <div id="drawerQuery" class="code-block"></div>
        </div>
        <div class="detail-section">
            <div class="detail-section-title">Headers</div>
            <div id="drawerHeaders" class="code-block"></div>
        </div>
        <div class="detail-section">
            <div class="detail-section-title">Payload Body</div>
            <div id="drawerBody" class="code-block"></div>
        </div>
        <div class="detail-section">
            <div class="detail-section-title">Session Info</div>
            <div id="drawerDiag" style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);"></div>
        </div>
    </div>

    <script>
        let currentEvents = [];
        let debounceTimer;
        let timelinePoints = [];
        let activeHoverIndex = null;
        let methodSlices = [];
        let activeMethodHover = null;

        function debounceLoad() {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(loadData, 250);
        }

        async function fetchStats() {
            try {
                const res = await fetch('/stats', {
                    headers: { 'X-API-Key': document.getElementById('apiKey').value }
                });
                if (!res.ok) return;
                const data = await res.json();

                document.getElementById('statTotal').innerText = Number(data.total_requests || 0).toLocaleString();
                document.getElementById('statAnomalies').innerText = Number(data.anomalies || 0).toLocaleString();
                document.getElementById('statBenign').innerText = Number(data.benign || 0).toLocaleString();
                document.getElementById('statAvgScore').innerText = Number(data.avg_score || 0).toFixed(4);

                const total = data.total_requests || 1;
                const rate = ((data.anomalies / total) * 100).toFixed(1);
                document.getElementById('statThreatRate').innerText = `${rate}% threat ratio`;

                renderMethodChart(data.method_distribution || {});
            } catch (err) {
                console.error('Stats error:', err);
            }
        }

        async function loadData() {
            await fetchStats();
            const anomalyFilter = document.getElementById('anomalyFilter').value;
            const methodFilter = document.getElementById('methodFilter').value;
            const pathFilter = document.getElementById('pathFilter').value;

            const params = new URLSearchParams({
                limit: 100,
                anomalies_only: anomalyFilter
            });
            if (methodFilter) params.append('method', methodFilter);
            if (pathFilter) params.append('path_contains', pathFilter);

            try {
                const res = await fetch('/logs?' + params.toString(), {
                    headers: { 'X-API-Key': document.getElementById('apiKey').value }
                });
                if (!res.ok) return;
                const data = await res.json();
                currentEvents = data.events || [];
                renderTable(currentEvents);
                updateTimelineChart(currentEvents);
            } catch (err) {
                console.error('Logs error:', err);
            }
        }

        function renderTable(events) {
            const tbody = document.getElementById('eventsTableBody');
            if (!events || events.length === 0) {
                tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No matching traffic recorded.</td></tr>`;
                return;
            }

            tbody.innerHTML = events.map((e, idx) => {
                const methodClass = `badge-method-${(e.method || 'get').toLowerCase()}`;
                const isBlocked = e.is_anomaly;
                const statusBadge = isBlocked
                    ? `<span class="badge badge-threat">🚫 BLOCKED</span>`
                    : `<span class="badge badge-clean">✅ ALLOWED</span>`;

                const scoreClass = isBlocked ? 'score-high' : 'score-normal';
                const timeStr = e.timestamp ? new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '-';

                let fullPath = e.path;
                if (e.query_params && Object.keys(e.query_params).length > 0) {
                    const qs = Object.entries(e.query_params).map(([k,v]) => `${k}=${v}`).join('&');
                    fullPath += `?${qs}`;
                }

                return `
                <tr onclick="openDrawer(${idx})">
                    <td style="color: var(--text-secondary); font-family: var(--font-mono); font-size: 12px;">${timeStr}</td>
                    <td><span class="badge ${methodClass}">${e.method}</span></td>
                    <td><span class="path-code" title="${escapeHtml(fullPath)}">${escapeHtml(fullPath)}</span></td>
                    <td class="score-cell ${scoreClass}">${Number(e.anomaly_score || 0).toFixed(4)}</td>
                    <td>${statusBadge}</td>
                    <td class="latency-cell">${Number(e.latency_ms || 0).toFixed(1)}ms</td>
                    <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${(e.request_id || '').substring(0, 8)}</td>
                </tr>
                `;
            }).join('');
        }

        function openDrawer(index) {
            const e = currentEvents[index];
            if (!e) return;

            document.getElementById('drawerDecision').innerHTML = e.is_anomaly
                ? `<span class="badge badge-threat" style="font-size: 12px;">🚫 THREAT INTERCEPTED & BLOCKED</span>`
                : `<span class="badge badge-clean" style="font-size: 12px;">✅ VERIFIED BENIGN TRAFFIC</span>`;

            document.getElementById('drawerScore').innerHTML = `Anomaly Score: <strong>${e.anomaly_score}</strong> (Threshold: 1.25)`;
            document.getElementById('drawerEndpoint').innerText = `${e.method} ${e.path}`;
            document.getElementById('drawerQuery').innerText = JSON.stringify(e.query_params || {}, null, 2);
            document.getElementById('drawerHeaders').innerText = JSON.stringify(e.headers || {}, null, 2);
            document.getElementById('drawerBody').innerText = e.body || '(Empty Body)';
            document.getElementById('drawerDiag').innerText = `ID: ${e.request_id}\nSource: ${e.source_ip || '127.0.0.1'}\nLatency: ${e.latency_ms} ms`;

            document.getElementById('detailDrawer').style.display = 'block';
        }

        function closeDrawer() {
            document.getElementById('detailDrawer').style.display = 'none';
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        // --- Interactive Real-Time HTML5 Canvas Charts ---
        function updateTimelineChart(events) {
            const canvas = document.getElementById('timelineChart');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            const dpr = window.devicePixelRatio || 1;

            const rect = canvas.parentElement.getBoundingClientRect();
            canvas.width = rect.width * dpr;
            canvas.height = rect.height * dpr;
            ctx.scale(dpr, dpr);
            const w = rect.width;
            const h = rect.height;

            ctx.clearRect(0, 0, w, h);

            const recent = events.slice(0, 30).reverse();
            if (recent.length === 0) return;

            const padding = { top: 20, bottom: 25, left: 30, right: 20 };
            const chartW = w - padding.left - padding.right;
            const chartH = h - padding.top - padding.bottom;

            const stepX = chartW / Math.max(recent.length - 1, 1);

            // Grid lines
            ctx.strokeStyle = '#1E232E';
            ctx.lineWidth = 1;
            for (let i = 0; i <= 3; i++) {
                const y = padding.top + (chartH / 3) * i;
                ctx.beginPath();
                ctx.moveTo(padding.left, y);
                ctx.lineTo(w - padding.right, y);
                ctx.stroke();
            }

            // Calculate point coordinates
            timelinePoints = recent.map((e, idx) => {
                const x = padding.left + idx * stepX;
                const score = Math.min(Math.max(e.anomaly_score || 0, 0), 5);
                const y = padding.top + chartH - (score / 5) * chartH;
                return { x, y, event: e, originalIndex: events.indexOf(e) };
            });

            // Draw Total Traffic Gradient Area
            if (timelinePoints.length > 1) {
                ctx.beginPath();
                ctx.moveTo(timelinePoints[0].x, padding.top + chartH);
                timelinePoints.forEach(p => ctx.lineTo(p.x, p.y));
                ctx.lineTo(timelinePoints[timelinePoints.length - 1].x, padding.top + chartH);
                ctx.closePath();
                const grad = ctx.createLinearGradient(0, padding.top, 0, padding.top + chartH);
                grad.addColorStop(0, 'rgba(148, 163, 184, 0.15)');
                grad.addColorStop(1, 'rgba(148, 163, 184, 0.0)');
                ctx.fillStyle = grad;
                ctx.fill();
            }

            // Draw Line (Slate)
            ctx.beginPath();
            ctx.strokeStyle = '#94A3B8';
            ctx.lineWidth = 2;
            timelinePoints.forEach((p, idx) => {
                if (idx === 0) ctx.moveTo(p.x, p.y);
                else ctx.lineTo(p.x, p.y);
            });
            ctx.stroke();

            // Draw Threshold Line (Subtle Amber Dashed)
            const threshY = padding.top + chartH - (1.25 / 5) * chartH;
            ctx.beginPath();
            ctx.setLineDash([4, 4]);
            ctx.strokeStyle = 'rgba(245, 158, 11, 0.4)';
            ctx.lineWidth = 1;
            ctx.moveTo(padding.left, threshY);
            ctx.lineTo(w - padding.right, threshY);
            ctx.stroke();
            ctx.setLineDash([]);

            // Draw Nodes
            timelinePoints.forEach((p, idx) => {
                const isBlocked = p.event.is_anomaly;
                ctx.fillStyle = isBlocked ? '#F87171' : '#34D399';
                ctx.beginPath();
                ctx.arc(p.x, p.y, isBlocked ? 4.5 : 3.5, 0, Math.PI * 2);
                ctx.fill();

                if (idx === activeHoverIndex) {
                    ctx.strokeStyle = '#FFFFFF';
                    ctx.lineWidth = 2;
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, 6.5, 0, Math.PI * 2);
                    ctx.stroke();
                }
            });

            // Draw Tracking Crosshair on Active Hover
            if (activeHoverIndex !== null && timelinePoints[activeHoverIndex]) {
                const activeP = timelinePoints[activeHoverIndex];
                ctx.strokeStyle = 'rgba(255, 255, 255, 0.25)';
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(activeP.x, padding.top);
                ctx.lineTo(activeP.x, padding.top + chartH);
                ctx.stroke();
            }
        }

        // Timeline Pointer Events (Mouse & Touch)
        const timelineCanvas = document.getElementById('timelineChart');
        const timelineTooltip = document.getElementById('timelineTooltip');

        function handleTimelinePointer(e) {
            const rect = timelineCanvas.getBoundingClientRect();
            const clientX = e.touches ? e.touches[0].clientX : e.clientX;
            const clientY = e.touches ? e.touches[0].clientY : e.clientY;
            const mouseX = clientX - rect.left;
            const mouseY = clientY - rect.top;

            if (timelinePoints.length === 0) return;

            let closestDist = Infinity;
            let closestIdx = null;

            timelinePoints.forEach((p, idx) => {
                const dist = Math.abs(p.x - mouseX);
                if (dist < closestDist) {
                    closestDist = dist;
                    closestIdx = idx;
                }
            });

            if (closestIdx !== null && closestDist < 35) {
                activeHoverIndex = closestIdx;
                const p = timelinePoints[closestIdx];
                updateTimelineChart(currentEvents);

                const ev = p.event;
                timelineTooltip.style.display = 'block';
                timelineTooltip.style.left = `${Math.min(Math.max(p.x - 70, 10), rect.width - 160)}px`;
                timelineTooltip.style.top = `${Math.max(p.y - 75, 5)}px`;

                timelineTooltip.innerHTML = `
                    <div class="tooltip-title">${ev.method} ${escapeHtml(ev.path.substring(0, 24))}</div>
                    <div class="tooltip-row"><span>Score:</span> <span class="tooltip-badge" style="color: ${ev.is_anomaly ? 'var(--danger-text)' : 'var(--success-text)'};">${Number(ev.anomaly_score || 0).toFixed(4)}</span></div>
                    <div class="tooltip-row"><span>Action:</span> <span>${ev.is_anomaly ? '🚫 BLOCKED' : '✅ PASSED'}</span></div>
                    <div class="tooltip-row"><span>Latency:</span> <span>${Number(ev.latency_ms || 0).toFixed(1)}ms</span></div>
                `;
            } else {
                activeHoverIndex = null;
                timelineTooltip.style.display = 'none';
                updateTimelineChart(currentEvents);
            }
        }

        timelineCanvas.addEventListener('mousemove', handleTimelinePointer);
        timelineCanvas.addEventListener('touchmove', handleTimelinePointer);
        timelineCanvas.addEventListener('mouseleave', () => {
            activeHoverIndex = null;
            timelineTooltip.style.display = 'none';
            updateTimelineChart(currentEvents);
        });
        timelineCanvas.addEventListener('click', (e) => {
            if (activeHoverIndex !== null && timelinePoints[activeHoverIndex]) {
                const origIdx = timelinePoints[activeHoverIndex].originalIndex;
                openDrawer(origIdx);
            }
        });

        // Donut Chart
        const methodCanvas = document.getElementById('methodChart');
        const methodTooltip = document.getElementById('methodTooltip');

        function renderMethodChart(dist) {
            if (!methodCanvas) return;
            const ctx = methodCanvas.getContext('2d');
            const dpr = window.devicePixelRatio || 1;
            const rect = methodCanvas.parentElement.getBoundingClientRect();
            methodCanvas.width = rect.width * dpr;
            methodCanvas.height = rect.height * dpr;
            ctx.scale(dpr, dpr);
            const w = rect.width;
            const h = rect.height;

            ctx.clearRect(0, 0, w, h);

            const keys = Object.keys(dist);
            if (keys.length === 0) return;

            const total = Object.values(dist).reduce((a, b) => a + b, 0);
            const colors = { 'GET': '#64748B', 'POST': '#A855F7', 'PUT': '#F59E0B', 'DELETE': '#F43F5E' };

            let startAngle = -Math.PI / 2;
            const cx = w / 2;
            const cy = h / 2 - 5;
            const radius = Math.min(cx, cy) - 15;
            const innerRadius = radius * 0.65;

            methodSlices = [];

            keys.forEach(k => {
                const val = dist[k];
                const sliceAngle = (val / total) * 2 * Math.PI;
                const isHovered = activeMethodHover === k;
                const currentRadius = isHovered ? radius + 4 : radius;

                ctx.beginPath();
                ctx.arc(cx, cy, currentRadius, startAngle, startAngle + sliceAngle);
                ctx.arc(cx, cy, innerRadius, startAngle + sliceAngle, startAngle, true);
                ctx.closePath();
                ctx.fillStyle = colors[k] || '#71717A';
                ctx.fill();

                methodSlices.push({
                    method: k,
                    count: val,
                    percentage: ((val / total) * 100).toFixed(1),
                    startAngle: startAngle,
                    endAngle: startAngle + sliceAngle,
                    cx, cy, radius, innerRadius
                });

                startAngle += sliceAngle;
            });

            // Center Text
            ctx.fillStyle = '#F3F4F6';
            ctx.font = '700 16px Inter, sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';

            if (activeMethodHover) {
                const hovered = methodSlices.find(s => s.method === activeMethodHover);
                ctx.fillText(`${hovered.method} ${hovered.count}`, cx, cy - 2);
                ctx.font = '500 10px Inter, sans-serif';
                ctx.fillStyle = '#9CA3AF';
                ctx.fillText(`${hovered.percentage}% OF TRAFFIC`, cx, cy + 14);
            } else {
                ctx.fillText(total.toString(), cx, cy - 2);
                ctx.font = '500 10px Inter, sans-serif';
                ctx.fillStyle = '#9CA3AF';
                ctx.fillText('REQUESTS', cx, cy + 14);
            }
        }

        function handleMethodPointer(e) {
            const rect = methodCanvas.getBoundingClientRect();
            const clientX = e.touches ? e.touches[0].clientX : e.clientX;
            const clientY = e.touches ? e.touches[0].clientY : e.clientY;
            const mouseX = clientX - rect.left;
            const mouseY = clientY - rect.top;

            const cx = rect.width / 2;
            const cy = rect.height / 2 - 5;
            const dx = mouseX - cx;
            const dy = mouseY - cy;
            const distFromCenter = Math.sqrt(dx * dx + dy * dy);

            let angle = Math.atan2(dy, dx);
            if (angle < -Math.PI / 2) angle += 2 * Math.PI;

            let hoveredSlice = null;
            methodSlices.forEach(s => {
                if (distFromCenter >= s.innerRadius && distFromCenter <= s.radius + 8) {
                    if (angle >= s.startAngle && angle <= s.endAngle) {
                        hoveredSlice = s;
                    }
                }
            });

            if (hoveredSlice) {
                activeMethodHover = hoveredSlice.method;
                methodCanvas.style.cursor = 'pointer';
                methodTooltip.style.display = 'block';
                methodTooltip.style.left = `${Math.min(Math.max(mouseX - 60, 5), rect.width - 130)}px`;
                methodTooltip.style.top = `${Math.max(mouseY - 50, 5)}px`;
                methodTooltip.innerHTML = `
                    <div class="tooltip-title">${hoveredSlice.method} Requests</div>
                    <div class="tooltip-row"><span>Count:</span> <span class="tooltip-badge">${hoveredSlice.count} (${hoveredSlice.percentage}%)</span></div>
                `;
            } else {
                activeMethodHover = null;
                methodCanvas.style.cursor = 'default';
                methodTooltip.style.display = 'none';
            }
            fetchStats();
        }

        methodCanvas.addEventListener('mousemove', handleMethodPointer);
        methodCanvas.addEventListener('touchmove', handleMethodPointer);
        methodCanvas.addEventListener('mouseleave', () => {
            activeMethodHover = null;
            methodTooltip.style.display = 'none';
            fetchStats();
        });
        methodCanvas.addEventListener('click', () => {
            if (activeMethodHover) {
                document.getElementById('methodFilter').value = activeMethodHover;
                loadData();
            }
        });

        async function clearHistory() {
            if (!confirm('Are you sure you want to clear all inspection history?')) return;
            try {
                const res = await fetch('/clear', {
                    method: 'POST',
                    headers: { 'X-API-Key': document.getElementById('apiKey').value }
                });
                if (res.ok) {
                    await loadData();
                }
            } catch (err) {
                console.error('Clear error:', err);
            }
        }

        // Initialize & Auto Poll
        loadData();
        setInterval(loadData, 3500);
        window.addEventListener('resize', () => {
            updateTimelineChart(currentEvents);
            fetchStats();
        });
    </script>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.get("/health/live", include_in_schema=False)
async def liveness():
    return {"status": "alive"}


@app.get("/health/ready")
async def readiness(db: Database = Depends(get_db)):
    try:
        db.get_stats()
        get_model()
    except Exception as exc:
        logger.error("Readiness check failed: {}", exc)
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    return {"status": "ready", "model_version": get_model().version}


@app.get("/version")
async def version():
    return {"name": settings.app.name, "version": settings.app.version}


@app.get("/metrics", include_in_schema=False)
async def metrics(token: str = Depends(metrics_auth)):
    return metrics_response()


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "detection-api"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.detection_api.host, port=settings.detection_api.port)
