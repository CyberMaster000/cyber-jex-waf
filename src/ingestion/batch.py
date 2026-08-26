from pathlib import Path
from typing import Optional

from loguru import logger

from src.preprocessing.parser import parse_access_log_line, ParsedRequest
from src.preprocessing.normalizer import normalize_request


def ingest_log_file(file_path: str, limit: Optional[int] = None) -> list[ParsedRequest]:
    path = Path(file_path)
    if not path.exists():
        logger.error("Log file not found: {}", file_path)
        return []

    requests = []
    count = 0
    with open(path) as f:
        for line in f:
            if limit and count >= limit:
                break
            parsed = parse_access_log_line(line)
            if parsed:
                normalized = normalize_request(parsed)
                requests.append(normalized)
                count += 1

    logger.info("Ingested {} requests from {}", len(requests), file_path)
    return requests
