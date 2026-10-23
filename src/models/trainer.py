import json
import time
from pathlib import Path
from typing import Optional

import torch
import torch.nn as nn
from loguru import logger
from torch.utils.data import DataLoader, Dataset, random_split

from src.models.transformer import TransformerAutoencoder
from src.preprocessing.tokenizer import Tokenizer, SPECIAL_TOKENS
from src.utils.config import get_settings
from src.utils.device import get_device, is_tpu, save_checkpoint

try:
    import torch_xla.core.xla_model as xm
except ImportError:
    xm = None


class RequestDataset(Dataset):
    def __init__(self, sequences: list[list[int]], max_len: int = 512):
        self.sequences = sequences
        self.max_len = max_len

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        seq = self.sequences[idx]
        if len(seq) < self.max_len:
            seq = seq + [SPECIAL_TOKENS["<PAD>"]] * (self.max_len - len(seq))
        else:
            seq = seq[: self.max_len]
        tensor = torch.tensor(seq, dtype=torch.long)
        return tensor, tensor


class ModelTrainer:
    def __init__(
        self,
        model: Optional[TransformerAutoencoder] = None,
        device: Optional[str] = None,
    ):
        settings = get_settings()
        if device is not None:
            self.device = get_device(device)
        else:
            self.device = get_device(settings.training.device)

        if model is None:
            self.model = TransformerAutoencoder(
                vocab_size=settings.model.vocab_size,
                embed_dim=settings.model.embed_dim,
                num_heads=settings.model.num_heads,
                num_layers=settings.model.num_layers,
                max_seq_len=settings.model.max_seq_len,
                dropout=settings.model.dropout,
            )
        else:
            self.model = model

        self.model.to(self.device)
        self.tokenizer = Tokenizer()
        self.threshold = settings.model.threshold
        self._training = False
        self._progress = {"status": "idle", "epoch": 0, "loss": 0.0, "val_loss": 0.0}

    @property
    def is_training(self) -> bool:
        return self._training

    @property
    def progress(self) -> dict:
        return self._progress

    def compute_optimal_threshold(self, losses: list[float], percentile: float = 95) -> float:
        import numpy as np
        arr = np.array(losses)
        return float(np.percentile(arr, percentile))

    def train(
        self,
        raw_requests: list[str],
        epochs: Optional[int] = None,
        batch_size: Optional[int] = None,
        incremental: bool = False,
    ):
        settings = get_settings()
        epochs = epochs or settings.training.epochs
        batch_size = batch_size or settings.training.batch_size

        self._training = True
        self._progress = {"status": "training", "epoch": 0, "loss": 0.0, "val_loss": 0.0}

        logger.info("Starting training with {} samples for {} epochs on {}", len(raw_requests), epochs, self.device)

        tokenizer = Tokenizer()
        sequences = []
        for req_str in raw_requests:
            try:
                req_data = json.loads(req_str) if req_str.startswith("{") else {"method": "GET", "path": req_str, "headers": {}, "body": ""}
                from src.preprocessing.parser import parse_http_request
                from src.preprocessing.normalizer import normalize_request

                parsed = parse_http_request(
                    method=req_data.get("method", "GET"),
                    url=req_data.get("path", "/"),
                    headers=req_data.get("headers", {}),
                    body=req_data.get("body", ""),
                )
                normalized = normalize_request(parsed)
                ids = tokenizer.encode_request(normalized)
                sequences.append(ids)
            except Exception as e:
                logger.warning("Failed to process training sample: {}", e)
                continue

        if len(sequences) < 10:
            logger.error("Not enough valid sequences for training (got {})", len(sequences))
            self._training = False
            self._progress = {"status": "error", "message": "insufficient data"}
            return

        dataset = RequestDataset(sequences, settings.model.max_seq_len)

        val_size = max(1, int(len(dataset) * settings.training.val_split))
        train_size = len(dataset) - val_size
        train_dataset, val_dataset = random_split(dataset, [train_size, val_size])

        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size)

        optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=settings.training.learning_rate,
            weight_decay=0.01,
        )
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
        loss_fn = nn.CrossEntropyLoss(ignore_index=SPECIAL_TOKENS["<PAD>"])

        best_val_loss = float("inf")
        patience_counter = 0
        all_train_losses = []

        for epoch in range(epochs):
            if not self._training:
                logger.info("Training interrupted")
                break

            self.model.train()
            epoch_loss = 0.0
            n_batches = 0

            for batch_src, batch_tgt in train_loader:
                batch_src = batch_src.to(self.device)
                batch_tgt = batch_tgt.to(self.device)

                optimizer.zero_grad()
                logits, _ = self.model(batch_src)
                loss = loss_fn(logits.view(-1, logits.size(-1)), batch_tgt.view(-1))
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)

                if is_tpu(self.device):
                    xm.optimizer_step(optimizer)
                    xm.mark_step()
                else:
                    optimizer.step()

                epoch_loss += loss.item()
                n_batches += 1

            scheduler.step()
            avg_train_loss = epoch_loss / max(n_batches, 1)
            all_train_losses.append(avg_train_loss)

            self.model.eval()
            val_loss = 0.0
            n_val = 0
            with torch.no_grad():
                for batch_src, batch_tgt in val_loader:
                    batch_src = batch_src.to(self.device)
                    batch_tgt = batch_tgt.to(self.device)
                    logits, _ = self.model(batch_src)
                    loss = loss_fn(logits.view(-1, logits.size(-1)), batch_tgt.view(-1))
                    val_loss += loss.item()
                    n_val += 1

            if is_tpu(self.device):
                xm.mark_step()

            avg_val_loss = val_loss / max(n_val, 1)

            logger.info(
                "Epoch {}/{} - train_loss: {:.4f} - val_loss: {:.4f}",
                epoch + 1,
                epochs,
                avg_train_loss,
                avg_val_loss,
            )

            self._progress = {
                "status": "training",
                "epoch": epoch + 1,
                "total_epochs": epochs,
                "loss": round(avg_train_loss, 4),
                "val_loss": round(avg_val_loss, 4),
            }

            if avg_val_loss < best_val_loss:
                best_val_loss = avg_val_loss
                patience_counter = 0
                self.model.save(metrics={"best_val_loss": best_val_loss, "epoch": epoch + 1}, device=self.device)
            else:
                patience_counter += 1
                if patience_counter >= settings.training.early_stopping_patience:
                    logger.info("Early stopping at epoch {}", epoch + 1)
                    break

        new_threshold = self.compute_optimal_threshold(all_train_losses)
        self.threshold = new_threshold

        self.model.save(metrics={
            "final_train_loss": all_train_losses[-1] if all_train_losses else 0,
            "best_val_loss": best_val_loss,
            "optimal_threshold": new_threshold,
            "total_samples": len(sequences),
        }, device=self.device)

        self._training = False
        self._progress = {
            "status": "completed",
            "epochs_run": len(all_train_losses),
            "final_loss": round(all_train_losses[-1], 4) if all_train_losses else 0,
            "best_val_loss": round(best_val_loss, 4),
            "optimal_threshold": round(new_threshold, 4),
            "total_samples": len(sequences),
        }
        logger.info("Training completed. Optimal threshold: {:.4f}", new_threshold)
