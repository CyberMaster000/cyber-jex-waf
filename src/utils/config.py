import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel


class AppConfig(BaseModel):
    name: str = "waf-project"
    version: str = "1.0.0"


class DetectionAPIConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    api_keys: list[str] = []


class UpdateAPIConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8001
    workers: int = 2
    api_keys: list[str] = []


class ModelConfig(BaseModel):
    vocab_size: int = 10000
    embed_dim: int = 256
    num_heads: int = 8
    num_layers: int = 4
    max_seq_len: int = 512
    dropout: float = 0.1
    threshold: float = 0.75
    checkpoint_dir: str = "models/checkpoints"


class TrainingConfig(BaseModel):
    batch_size: int = 32
    learning_rate: float = 0.0001
    epochs: int = 50
    early_stopping_patience: int = 5
    val_split: float = 0.1
    device: str = "auto"


class PreprocessingConfig(BaseModel):
    dynamic_patterns: list[str] = []
    replacement_tokens: dict[str, str] = {}


class StorageConfig(BaseModel):
    db_path: str = "data/detections.db"
    max_events: int = 100000


class RedisConfig(BaseModel):
    host: str = "redis"
    port: int = 6379
    db: int = 0
    rate_limit: dict[str, Any] = {"requests": 100, "window_seconds": 60}


class Settings(BaseModel):
    app: AppConfig = AppConfig()
    detection_api: DetectionAPIConfig = DetectionAPIConfig()
    update_api: UpdateAPIConfig = UpdateAPIConfig()
    model: ModelConfig = ModelConfig()
    training: TrainingConfig = TrainingConfig()
    preprocessing: PreprocessingConfig = PreprocessingConfig()
    storage: StorageConfig = StorageConfig()
    redis: RedisConfig = RedisConfig()


_settings: Optional[Settings] = None


def load_settings(config_path: Optional[str] = None) -> Settings:
    global _settings
    if _settings is not None:
        return _settings

    if config_path is None:
        config_path = os.environ.get(
            "WAF_CONFIG_PATH",
            str(Path(__file__).parent.parent.parent / "config.yaml"),
        )

    path = Path(config_path)
    if path.exists():
        with open(path) as f:
            raw = yaml.safe_load(f)
        _settings = Settings(**raw)
    else:
        _settings = Settings()

    return _settings


def get_settings() -> Settings:
    if _settings is None:
        return load_settings()
    return _settings
