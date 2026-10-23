import os
import sys
from pathlib import Path

from loguru import logger


def setup_logger(log_file: str | None = None, level: str | None = None):
    """Configure loguru for container-friendly JSON or human-readable logs."""
    level = (level or os.environ.get("WAF_LOG_LEVEL", "INFO")).upper()
    log_file = log_file or os.environ.get("WAF_LOG_FILE", "logs/waf.log")
    as_json = os.environ.get("WAF_LOG_JSON", "false").lower() in {"1", "true", "yes", "on"}

    logger.remove()
    logger.add(
        sys.stderr,
        level=level,
        serialize=as_json,
        backtrace=False,
        diagnose=False,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
        ),
    )
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            log_file,
            level=level,
            serialize=as_json,
            rotation="50 MB",
            retention=10,
            compression="gz",
            enqueue=True,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        )
    return logger
