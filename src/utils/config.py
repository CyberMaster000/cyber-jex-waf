import os
import re
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel


_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand_env(raw: str) -> str:
    """Expand ${VAR} and ${VAR:-default} without requiring extra packages."""

    def _replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        value = os.environ.get(name)
        if value is None or value == "":
            return default if default is not None else ""
        return value

    return _ENV_PATTERN.sub(_replace, raw)


class AppConfig(BaseModel):
    name: str = "waf-project"
    version: str = "1.0.0"


class DetectionAPIConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    api_keys: list[str] = []
    admin_api_keys: list[str] = []
    dashboard_username: str = "sentinel"
    dashboard_password: str = "change-me"
    require_dashboard_auth: bool = True


class UpdateAPIConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8001
    workers: int = 2
    api_keys: list[str] = []


class ModelConfig(BaseModel):
    type: str = "auto"
    securebert_path: str = "models/securebert_clf"
    modernbert_path: str = "models/checkpoints/modernbert"
    vocab_size: int = 50368
    embed_dim: int = 768
    num_heads: int = 12
    num_layers: int = 22
    max_seq_len: int = 512
    dropout: float = 0.1
    threshold: float = -1.0
    benign_suppression: bool = True
    suppression_max_score: float = 9.5
    checkpoint_dir: str = "models/checkpoints"
    calibration_file: str = "models/securebert_clf/calibration.json"


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
    redact_sensitive: bool = True


class SecurityConfig(BaseModel):
    max_body_bytes: int = 1_048_576
    max_path_length: int = 4096
    max_header_count: int = 100
    max_header_bytes: int = 32768


class RedisConfig(BaseModel):
    host: str = "redis"
    port: int = 6379
    db: int = 0
    enabled: bool = True
    rate_limit: dict[str, Any] = {"requests": 100, "window_seconds": 60}


class Settings(BaseModel):
    app: AppConfig = AppConfig()
    detection_api: DetectionAPIConfig = DetectionAPIConfig()
    update_api: UpdateAPIConfig = UpdateAPIConfig()
    model: ModelConfig = ModelConfig()
    training: TrainingConfig = TrainingConfig()
    preprocessing: PreprocessingConfig = PreprocessingConfig()
    storage: StorageConfig = StorageConfig()
    security: SecurityConfig = SecurityConfig()
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
        text = _expand_env(path.read_text())
        raw = yaml.safe_load(text) or {}
        _settings = Settings(**raw)
    else:
        _settings = Settings()

    return _settings


def get_settings() -> Settings:
    if _settings is None:
        return load_settings()
    return _settings
