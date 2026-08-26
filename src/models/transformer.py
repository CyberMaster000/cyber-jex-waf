from pathlib import Path
from typing import Optional

import torch
import torch.nn as nn
from loguru import logger

from src.utils.config import get_settings


class PositionalEncoding(nn.Module):
    def __init__(self, embed_dim: int, max_len: int = 512, dropout: float = 0.1):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)
        pe = torch.zeros(max_len, embed_dim)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, embed_dim, 2).float() * (-torch.log(torch.tensor(10000.0)) / embed_dim))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x + self.pe[:, : x.size(1)]
        return self.dropout(x)


class TransformerAutoencoder(nn.Module):
    def __init__(
        self,
        vocab_size: int = 10000,
        embed_dim: int = 256,
        num_heads: int = 8,
        num_layers: int = 4,
        max_seq_len: int = 512,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.embed_dim = embed_dim
        self.max_seq_len = max_seq_len

        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_encoder = PositionalEncoding(embed_dim, max_seq_len, dropout)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=embed_dim * 4,
            dropout=dropout,
            activation="gelu",
            batch_first=True,
        )
        self.transformer_encoder = nn.TransformerEncoder(
            encoder_layer, num_layers=num_layers
        )

        self.decoder = nn.Sequential(
            nn.Linear(embed_dim, embed_dim * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim * 2, embed_dim),
            nn.GELU(),
        )

        self.output_projection = nn.Linear(embed_dim, vocab_size)

        self._init_weights()

    def _init_weights(self):
        for p in self.parameters():
            if p.dim() > 1:
                nn.init.xavier_uniform_(p)

    def forward(self, src: torch.Tensor, src_mask: Optional[torch.Tensor] = None) -> tuple[torch.Tensor, torch.Tensor]:
        pad_mask = (src == 0)
        embedded = self.embedding(src) * (self.embed_dim ** 0.5)
        encoded = self.pos_encoder(embedded)

        if src_mask is None:
            src_mask = nn.Transformer.generate_square_subsequent_mask(
                src.size(1), device=src.device
            ).bool()

        latent = self.transformer_encoder(
            encoded, src_key_padding_mask=pad_mask, mask=src_mask
        )
        reconstructed = self.decoder(latent)
        logits = self.output_projection(reconstructed)
        return logits, latent

    def compute_anomaly_score(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        loss_fn = nn.CrossEntropyLoss(reduction="none")
        pad_mask = targets != 0
        per_token_loss = loss_fn(
            logits.view(-1, logits.size(-1)), targets.view(-1)
        ).view_as(targets)
        per_token_loss = per_token_loss * pad_mask.float()
        seq_loss = per_token_loss.sum(dim=1) / pad_mask.float().sum(dim=1).clamp(min=1)
        return seq_loss

    @classmethod
    def load(cls, checkpoint_path: Optional[str] = None) -> "TransformerAutoencoder":
        settings = get_settings()
        path = Path(checkpoint_path or settings.model.checkpoint_dir) / "best_model.pt"
        if not path.exists():
            logger.warning("No checkpoint found at {}, creating fresh model", path)
            return cls(
                vocab_size=settings.model.vocab_size,
                embed_dim=settings.model.embed_dim,
                num_heads=settings.model.num_heads,
                num_layers=settings.model.num_layers,
                max_seq_len=settings.model.max_seq_len,
                dropout=settings.model.dropout,
            )

        checkpoint = torch.load(path, map_location="cpu", weights_only=False)
        config = checkpoint.get("config", {})
        model = cls(
            vocab_size=config.get("vocab_size", settings.model.vocab_size),
            embed_dim=config.get("embed_dim", settings.model.embed_dim),
            num_heads=config.get("num_heads", settings.model.num_heads),
            num_layers=config.get("num_layers", settings.model.num_layers),
            max_seq_len=config.get("max_seq_len", settings.model.max_seq_len),
            dropout=config.get("dropout", settings.model.dropout),
        )
        model.load_state_dict(checkpoint["model_state_dict"])
        logger.info("Loaded model checkpoint from {}", path)
        return model

    def save(self, checkpoint_path: Optional[str] = None, metrics: Optional[dict] = None):
        settings = get_settings()
        path = Path(checkpoint_path or settings.model.checkpoint_dir)
        path.mkdir(parents=True, exist_ok=True)

        checkpoint = {
            "model_state_dict": self.state_dict(),
            "config": {
                "vocab_size": settings.model.vocab_size,
                "embed_dim": settings.model.embed_dim,
                "num_heads": settings.model.num_heads,
                "num_layers": settings.model.num_layers,
                "max_seq_len": settings.model.max_seq_len,
                "dropout": settings.model.dropout,
            },
            "metrics": metrics or {},
        }
        torch.save(checkpoint, path / "best_model.pt")
        torch.save(checkpoint, path / "latest_model.pt")
        logger.info("Saved model checkpoint to {}", path)
