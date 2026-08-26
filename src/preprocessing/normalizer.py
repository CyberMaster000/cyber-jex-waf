import re

from loguru import logger

from src.preprocessing.parser import ParsedRequest
from src.utils.config import get_settings

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_JWT_RE = re.compile(r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")
_NUMERIC_RE = re.compile(r"\b\d{10,}\b")
_TIMESTAMP_RE = re.compile(
    r"\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")


def normalize_value(text: str) -> str:
    text = _TIMESTAMP_RE.sub("<TS>", text)
    text = _UUID_RE.sub("<UUID>", text)
    text = _JWT_RE.sub("<TOKEN>", text)
    text = _EMAIL_RE.sub("<EMAIL>", text)
    text = _IP_RE.sub("<IP>", text)
    text = _NUMERIC_RE.sub("<NUM>", text)
    return text


def normalize_request(req: ParsedRequest) -> ParsedRequest:
    normalized_path = normalize_value(req.path)

    normalized_params: dict[str, list[str]] = {}
    for key, values in req.query_params.items():
        normalized_params[key] = [normalize_value(v) for v in values]

    normalized_headers = {}
    for k, v in req.headers.items():
        if k.lower() not in ("cookie", "authorization"):
            normalized_headers[k] = normalize_value(v)

    normalized_body = normalize_value(req.body) if req.body else ""

    logger.debug("Normalized request: {} {}", req.method, normalized_path)

    return ParsedRequest(
        method=req.method,
        path=normalized_path,
        query_params=normalized_params,
        headers=normalized_headers,
        body=normalized_body,
        raw=req.raw,
        source_ip=req.source_ip,
        user_agent=req.user_agent,
    )
