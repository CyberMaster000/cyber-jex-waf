from pathlib import Path
from typing import Optional, Union, Tuple
import torch
import torch.nn as nn
from loguru import logger

from src.utils.config import get_settings
from src.utils.device import is_tpu, save_checkpoint


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
    def load(cls, checkpoint_path: Optional[str] = None, device: Optional[torch.device] = None) -> "TransformerAutoencoder":
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

        if device is not None and is_tpu(device):
            import torch_xla.core.xla_model as xm
            model = model.to(device)
            xm.mark_step()
            logger.info("Loaded model checkpoint from {} to TPU", path)
        else:
            logger.info("Loaded model checkpoint from {}", path)

        return model

    def save(self, checkpoint_path: Optional[str] = None, metrics: Optional[dict] = None, device: Optional[torch.device] = None):
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
        save_checkpoint(checkpoint, path / "best_model.pt", device)
        save_checkpoint(checkpoint, path / "latest_model.pt", device)
        logger.info("Saved model checkpoint to {}", path)


class ModernBertWAFDetector(nn.Module):
    """
    Production WAF Transformer Detector using pre-trained ModernBERT (checkpoint-161700).
    Trained on 161,700 steps for deep contextual representation and anomaly/threat detection.
    """

    def __init__(self, checkpoint_path: Union[str, Path]):
        super().__init__()
        from transformers import AutoModelForMaskedLM, AutoTokenizer

        self.checkpoint_path = Path(checkpoint_path)
        logger.info("Initializing ModernBERT WAF Model from {}", self.checkpoint_path)
        self.tokenizer = AutoTokenizer.from_pretrained(str(self.checkpoint_path))
        self.model = AutoModelForMaskedLM.from_pretrained(str(self.checkpoint_path))
        self.model.eval()
        self.version = "ModernBERT-161700"

    def forward(self, input_ids: torch.Tensor, attention_mask: Optional[torch.Tensor] = None):
        return self.model(input_ids=input_ids, attention_mask=attention_mask)

    def compute_anomaly_score(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        loss_fn = nn.CrossEntropyLoss(reduction="none")
        pad_id = self.tokenizer.pad_token_id if self.tokenizer.pad_token_id is not None else 0
        pad_mask = (targets != pad_id) & (targets != 0)
        per_token_loss = loss_fn(
            logits.view(-1, logits.size(-1)), targets.view(-1)
        ).view_as(targets)
        per_token_loss = per_token_loss * pad_mask.float()
        seq_loss = per_token_loss.sum(dim=1) / pad_mask.float().sum(dim=1).clamp(min=1)
        return seq_loss

    def score_request(self, raw_http: str) -> tuple[float, torch.Tensor]:
        inputs = self.tokenizer(raw_http, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            input_ids = inputs["input_ids"]
            score = self.compute_anomaly_score(logits, input_ids).item()
        return score, logits


class SecureBertClassifier(nn.Module):
    """
    Production WAF detector: SecureBERT (ModernBERT) as frozen encoder + a
    trained logistic-regression classification head (benign vs malicious).
    The anomaly score is the signed decision value from the linear head,
    where positive => malicious.
    """

    def __init__(self, model_dir: Union[str, Path]):
        super().__init__()
        from transformers import AutoModelForMaskedLM, AutoTokenizer

        self.model_dir = Path(model_dir)
        logger.info("Initializing SecureBERT classifier from {}", self.model_dir)
        self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_dir))
        self.model = AutoModelForMaskedLM.from_pretrained(str(self.model_dir))
        self.model.eval()

        weights_path = self.model_dir / "classifier_weights.npz"
        if not weights_path.exists():
            raise FileNotFoundError(f"Missing classifier weights: {weights_path}")

        import numpy as np
        w = np.load(weights_path)
        self.register_buffer("classifier_bias", torch.tensor(w["intercept"], dtype=torch.float32))
        self.classifier_weight = torch.tensor(w["coef"], dtype=torch.float32)
        self.weights_path = weights_path
        self._weights_mtime = weights_path.stat().st_mtime
        self.version = "SecureBERT2.0-clf"

    def reload_if_changed(self) -> bool:
        """Hot-reload the classifier head when retraining writes new weights."""
        try:
            mtime = self.weights_path.stat().st_mtime
        except OSError:
            return False
        if mtime == self._weights_mtime:
            return False

        import numpy as np
        w = np.load(self.weights_path)
        weight = torch.tensor(w["coef"], dtype=torch.float32)
        bias = torch.tensor(w["intercept"], dtype=torch.float32)
        if weight.shape != self.classifier_weight.shape:
            logger.warning(
                "Ignoring incompatible retrained weights: {} vs {}",
                tuple(weight.shape),
                tuple(self.classifier_weight.shape),
            )
            return False
        self.classifier_weight = weight
        self.classifier_bias = bias
        self._weights_mtime = mtime
        logger.info("Reloaded retrained SecureBERT classifier head")
        return True

    @torch.no_grad()
    def _embed(self, texts: list[str]) -> torch.Tensor:
        inputs = self.tokenizer(
            texts, padding=True, truncation=True, max_length=256,
            return_tensors="pt",
        )
        outputs = self.model(**inputs, output_hidden_states=True)
        hidden = outputs.hidden_states[-1]
        mask = inputs["attention_mask"].unsqueeze(-1).float()
        pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
        return pooled

    def score_request(self, raw_http: str) -> tuple[float, torch.Tensor]:
        embed = self._embed([raw_http])
        logit = embed @ self.classifier_weight.t() + self.classifier_bias
        score = logit.item()
        return score, logit

    def forward(self, input_ids: torch.Tensor, attention_mask: Optional[torch.Tensor] = None):
        return self.model(input_ids=input_ids, attention_mask=attention_mask)


def load_waf_model(checkpoint_path: Optional[str] = None):
    """Factory function to load either SecureBERT classifier, ModernBERT, or TransformerAutoencoder."""
    settings = get_settings()

    # 1) Prefer the trained SecureBERT classifier (best accuracy)
    securebert_dir = Path(settings.model.securebert_path)
    if not securebert_dir.is_absolute():
        securebert_dir = Path.cwd() / securebert_dir
    if securebert_dir.exists() and (securebert_dir / "model.safetensors").exists():
        logger.info("Found SecureBERT classifier at {}", securebert_dir)
        return SecureBertClassifier(securebert_dir)

    # 2) Fallback to ModernBERT (raw MLM loss)
    modernbert_dir = Path(checkpoint_path or settings.model.modernbert_path)
    if not modernbert_dir.is_absolute():
        modernbert_dir = Path.cwd() / modernbert_dir

    if modernbert_dir.exists() and (modernbert_dir / "model.safetensors").exists():
        logger.info("Found ModernBERT checkpoint at {}", modernbert_dir)
        return ModernBertWAFDetector(modernbert_dir)

    alt_modernbert = Path(settings.model.checkpoint_dir) / "modernbert"
    if alt_modernbert.exists() and (alt_modernbert / "model.safetensors").exists():
        logger.info("Found ModernBERT checkpoint at {}", alt_modernbert)
        return ModernBertWAFDetector(alt_modernbert)

    logger.info("ModernBERT not found, falling back to TransformerAutoencoder")
    return TransformerAutoencoder.load(checkpoint_path)
