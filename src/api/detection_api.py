import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import torch
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from loguru import logger
from pydantic import BaseModel

from src.models.transformer import TransformerAutoencoder
from src.preprocessing.normalizer import normalize_request
from src.preprocessing.parser import parse_http_request
from src.preprocessing.tokenizer import Tokenizer
from src.storage.db import DetectionEvent, Database, get_db
from src.utils.config import get_settings
from src.utils.logger import setup_logger

setup_logger()

app = FastAPI(title="WAF Detection API", version="1.0.0")
settings = get_settings()

_model: Optional[TransformerAutoencoder] = None
_tokenizer: Optional[Tokenizer] = None


def get_model() -> TransformerAutoencoder:
    global _model
    if _model is None:
        _model = TransformerAutoencoder.load()
        _model.eval()
    return _model


def get_tokenizer() -> Tokenizer:
    global _tokenizer
    if _tokenizer is None:
        _tokenizer = Tokenizer()
    return _tokenizer


async def verify_api_key(x_api_key: str = Header(default="")):
    if settings.detection_api.api_keys and x_api_key not in settings.detection_api.api_keys:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


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


def _run_detection(req: DetectRequest, db: Database, model: TransformerAutoencoder, tokenizer: Tokenizer) -> dict:
    start = time.time()

    url = req.path
    if req.query_params:
        qs = "&".join(f"{k}={v}" for k, v in req.query_params.items())
        url = f"{url}?{qs}"

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
    with torch.no_grad():
        logits, latent = model(input_tensor)
        scores = model.compute_anomaly_score(logits, input_tensor)
        anomaly_score = scores.item()

    latency_ms = (time.time() - start) * 1000
    is_anomaly = anomaly_score > settings.model.threshold

    event = DetectionEvent(
        method=req.method,
        path=req.path,
        query_params=req.query_params,
        headers=req.headers,
        body=req.body[:1000],
        source_ip=req.headers.get("x-real-ip", req.headers.get("x-forwarded-for", "")),
        user_agent=req.headers.get("user-agent", ""),
        anomaly_score=round(anomaly_score, 6),
        is_anomaly=is_anomaly,
        latency_ms=round(latency_ms, 2),
    )

    request_id = db.store_event(event)

    if is_anomaly:
        logger.warning(
            "ANOMALY DETECTED | {} {} | score={:.4f} | latency={:.1f}ms | id={}",
            req.method, req.path, anomaly_score, latency_ms, request_id,
        )

    return {
        "request_id": request_id,
        "is_anomaly": is_anomaly,
        "anomaly_score": round(anomaly_score, 6),
        "threshold": settings.model.threshold,
        "latency_ms": round(latency_ms, 2),
        "model_version": "v1.0",
    }


@app.post("/detect")
async def detect(req: DetectRequest, api_key: str = Depends(verify_api_key), db: Database = Depends(get_db)):
    model = get_model()
    tokenizer = get_tokenizer()
    return _run_detection(req, db, model, tokenizer)


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
async def update_threshold(body: ThresholdUpdate, api_key: str = Depends(verify_api_key)):
    settings.model.threshold = body.threshold
    logger.info("Anomaly threshold updated to {}", body.threshold)
    return {"threshold": body.threshold, "status": "updated"}


@app.get("/history", response_class=HTMLResponse)
async def history_page():
    html = """
<!DOCTYPE html>
<html>
<head>
    <title>WAF Detection History</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0f0f23; color: #e0e0e0; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #00d4ff; margin-bottom: 20px; text-align: center; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }
        .stat-card { background: #1a1a3e; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #2a2a5e; }
        .stat-card .value { font-size: 28px; font-weight: bold; color: #00d4ff; }
        .stat-card .label { font-size: 12px; color: #888; margin-top: 5px; }
        .controls { margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
        .controls input, .controls select, .controls button { padding: 8px 12px; border-radius: 6px; border: 1px solid #2a2a5e; background: #1a1a3e; color: #e0e0e0; }
        .controls button { background: #00d4ff; color: #000; border: none; cursor: pointer; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #2a2a5e; }
        th { background: #1a1a3e; color: #00d4ff; }
        tr:hover { background: #1a1a3e; }
        .anomaly { color: #ff4444; font-weight: bold; }
        .benign { color: #44ff44; }
        .api-key { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>WAF Detection History</h1>
        <div class="stats" id="stats"></div>
        <div class="controls">
            <input type="text" id="apiKey" placeholder="API Key" value="waf-key-dev-001">
            <select id="anomalyFilter"><option value="false">All</option><option value="true">Anomalies Only</option></select>
            <select id="methodFilter"><option value="">All Methods</option><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option></select>
            <input type="text" id="pathFilter" placeholder="Path contains...">
            <button onclick="loadData()">Search</button>
        </div>
        <table>
            <thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Score</th><th>Status</th><th>Latency</th><th>ID</th></tr></thead>
            <tbody id="events"></tbody>
        </table>
    </div>
    <script>
        async function loadStats() {
            const r = await fetch('/api/stats', { headers: {'X-API-Key': document.getElementById('apiKey').value} });
            const d = await r.json();
            document.getElementById('stats').innerHTML = `
                <div class="stat-card"><div class="value">${d.total_requests}</div><div class="label">Total Requests</div></div>
                <div class="stat-card"><div class="value">${d.anomalies}</div><div class="label">Anomalies</div></div>
                <div class="stat-card"><div class="value">${d.benign}</div><div class="label">Benign</div></div>
                <div class="stat-card"><div class="value">${d.avg_score}</div><div class="label">Avg Score</div></div>`;
        }
        async function loadData() {
            await loadStats();
            const q = new URLSearchParams({
                limit: 100,
                anomalies_only: document.getElementById('anomalyFilter').value,
                method: document.getElementById('methodFilter').value,
                path_contains: document.getElementById('pathFilter').value,
            });
            const r = await fetch('/api/logs?' + q, { headers: {'X-API-Key': document.getElementById('apiKey').value} });
            const d = await r.json();
            const tbody = document.getElementById('events');
            tbody.innerHTML = d.events.map(e => `<tr>
                <td>${e.timestamp ? new Date(e.timestamp).toLocaleString() : '-'}</td>
                <td>${e.method}</td><td>${e.path}</td>
                <td>${e.anomaly_score.toFixed(4)}</td>
                <td class="${e.is_anomaly ? 'anomaly' : 'benign'}">${e.is_anomaly ? 'ANOMALY' : 'OK'}</td>
                <td>${e.latency_ms.toFixed(1)}ms</td>
                <td style="font-size:10px">${e.request_id.substring(0, 8)}</td></tr>`).join('');
        }
        loadData();
        setInterval(loadData, 10000);
    </script>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "detection-api"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.detection_api.host, port=settings.detection_api.port)
