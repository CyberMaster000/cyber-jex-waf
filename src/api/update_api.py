from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from loguru import logger
from pydantic import BaseModel

from src.models.trainer import ModelTrainer
from src.storage.db import Database, get_db
from src.utils.config import get_settings
from src.utils.logger import setup_logger

setup_logger()

app = FastAPI(title="WAF Update API", version="1.0.0")
settings = get_settings()

_trainer: Optional[ModelTrainer] = None


def get_trainer() -> ModelTrainer:
    global _trainer
    if _trainer is None:
        _trainer = ModelTrainer()
    return _trainer


async def verify_admin_key(x_api_key: str = Header(default="")):
    if settings.update_api.api_keys and x_api_key not in settings.update_api.api_keys:
        raise HTTPException(status_code=401, detail="Invalid admin API key")
    return x_api_key


class RetrainRequest(BaseModel):
    epochs: Optional[int] = None
    batch_size: Optional[int] = None


class AddBenignDataRequest(BaseModel):
    requests: list[dict]


@app.post("/retrain")
async def retrain(
    body: RetrainRequest,
    api_key: str = Depends(verify_admin_key),
    db: Database = Depends(get_db),
):
    trainer = get_trainer()
    if trainer.is_training:
        raise HTTPException(status_code=409, detail="Training already in progress")

    samples = db.get_training_samples(label="benign")
    raw_requests = [s["raw_request"] for s in samples]

    if len(raw_requests) < 10:
        raise HTTPException(
            status_code=400,
            detail=f"Not enough training data. Need at least 10 samples, have {len(raw_requests)}. "
                   "Add benign data first via /add_benign_data.",
        )

    import asyncio

    async def run_training():
        trainer = get_trainer()
        trainer.train(
            raw_requests=raw_requests,
            epochs=body.epochs,
            batch_size=body.batch_size,
            incremental=True,
        )

    asyncio.create_task(run_training())
    logger.info("Background retraining started with {} samples", len(raw_requests))

    return {
        "status": "training_started",
        "samples": len(raw_requests),
        "epochs": body.epochs or settings.training.epochs,
    }


@app.get("/retrain/status")
async def retrain_status(api_key: str = Depends(verify_admin_key)):
    trainer = get_trainer()
    return trainer.progress


@app.post("/add_benign_data")
async def add_benign_data(
    body: AddBenignDataRequest,
    api_key: str = Depends(verify_admin_key),
    db: Database = Depends(get_db),
):
    import json
    added = 0
    for req in body.requests:
        try:
            raw = json.dumps(req) if isinstance(req, dict) else str(req)
            db.add_training_sample(raw_request=raw, label="benign")
            added += 1
        except Exception as e:
            logger.warning("Failed to add sample: {}", e)

    logger.info("Added {} benign training samples", added)
    return {"added": added, "total_submitted": len(body.requests)}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "update-api"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.update_api.host, port=settings.update_api.port)
