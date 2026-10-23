"""Incremental retraining for the SecureBERT classification head.

The transformer encoder stays frozen.  Only the small logistic-regression
head is updated, which is fast enough to run on CPU and can be hot-reloaded
by the detection API without restarting the service.

This is deliberately conservative: it continues from the current weights with
a small learning rate and balanced class weights, and writes the new weights
atomically.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Iterable

import numpy as np
import torch
from loguru import logger


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -40.0, 40.0)))


def _embed_texts(model, texts: list[str], batch_size: int = 8) -> np.ndarray:
    chunks: list[np.ndarray] = []
    for start in range(0, len(texts), batch_size):
        batch = texts[start : start + batch_size]
        with torch.inference_mode():
            pooled = model._embed(batch)
        chunks.append(pooled.cpu().numpy())
    return np.concatenate(chunks, axis=0)


def retrain_head(
    model,
    benign_texts: Iterable[str],
    attack_texts: Iterable[str],
    epochs: int = 40,
    learning_rate: float = 0.02,
    l2: float = 1e-3,
) -> dict:
    benign = [t for t in benign_texts if t and t.strip()]
    attacks = [t for t in attack_texts if t and t.strip()]
    if len(benign) < 5 or len(attacks) < 5:
        raise ValueError("Need at least 5 benign and 5 attack samples")

    texts = benign + attacks
    y = np.concatenate([np.zeros(len(benign)), np.ones(len(attacks))]).astype(np.float32)
    X = _embed_texts(model, texts)

    # Continue from the current head instead of starting from scratch.
    w = model.classifier_weight.detach().cpu().numpy().astype(np.float32).copy()
    b = model.classifier_bias.detach().cpu().numpy().astype(np.float32).copy()
    if w.ndim == 1:
        w = w.reshape(1, -1)

    # Balanced class weights so small attack sets are not drowned out.
    n = len(y)
    n_pos = max(1.0, float(y.sum()))
    n_neg = max(1.0, float(n - y.sum()))
    sample_w = np.where(y == 1, n / (2.0 * n_pos), n / (2.0 * n_neg)).astype(np.float32)

    def scores(X_in: np.ndarray) -> np.ndarray:
        return (X_in @ w.T).ravel() + float(b[0])

    before = scores(X)
    before_acc = float(((before > 0) == (y > 0.5)).mean())

    for _ in range(max(1, epochs)):
        pred = _sigmoid(scores(X))
        error = (pred - y) * sample_w
        grad_w = (error[:, None] * X).mean(axis=0, keepdims=True) + l2 * w
        grad_b = np.array([error.mean()], dtype=np.float32)
        w -= learning_rate * grad_w.astype(np.float32)
        b -= learning_rate * grad_b

    after = scores(X)
    after_acc = float(((after > 0) == (y > 0.5)).mean())

    weights_path = Path(model.model_dir) / "classifier_weights.npz"
    backup = weights_path.with_suffix(".npz.bak")
    if not backup.exists() and weights_path.exists():
        shutil.copy2(weights_path, backup)
    tmp_path = weights_path.with_name(weights_path.stem + ".tmp.npz")
    np.savez(tmp_path, coef=w, intercept=b)
    os.replace(tmp_path, weights_path)

    result = {
        "status": "completed",
        "benign_samples": len(benign),
        "attack_samples": len(attacks),
        "accuracy_before": round(before_acc, 4),
        "accuracy_after": round(after_acc, 4),
        "epochs": epochs,
        "weights_path": str(weights_path),
    }
    logger.info(
        "Classifier head retrained: {} benign + {} attacks | acc {:.3f} -> {:.3f}",
        len(benign),
        len(attacks),
        before_acc,
        after_acc,
    )
    return result
