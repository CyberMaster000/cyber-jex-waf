"""Redaction helpers for data that is persisted or exported.

WAF logs are security-sensitive and often contain credentials, session
tokens, personal data and request bodies.  The detector needs the raw request
to score it, but the stored event does not.  These helpers keep the raw data
in memory only and sanitise everything written to SQLite / audit logs.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode

MASK = "[REDACTED]"

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-admin-key",
    "x-auth-token",
    "x-csrf-token",
}

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "sessionid",
    "csrf",
    "card",
    "card_number",
    "cvv",
    "cvc",
    "ssn",
    "private_key",
}

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_FORM_SECRET_RE = re.compile(
    r"(?i)(^|[&;])([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key)[A-Za-z0-9_.-]*)=([^&;]*)"
)
_XML_SECRET_RE = re.compile(
    r"(?is)(<(?:password|passwd|pwd|secret|token|api[_-]?key)[^>]*>)(.*?)(</(?:password|passwd|pwd|secret|token|api[_-]?key)>)"
)


def _mask_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (MASK if str(k).lower() in SENSITIVE_KEYS else _mask_value(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_value(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(text: str) -> str:
    """Mask common secret patterns inside free-form text."""
    if not text:
        return text
    text = _JWT_RE.sub(MASK, text)
    text = _BEARER_RE.sub(lambda m: f"{m.group(1)} {MASK}", text)
    text = _EMAIL_RE.sub(MASK, text)
    return text


def redact_headers(headers: dict[str, str] | None) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in (headers or {}).items():
        if key.lower() in SENSITIVE_HEADERS:
            safe[key] = MASK
        else:
            safe[key] = redact_text(value)
    return safe


def redact_query(query: dict[str, Any] | None) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in (query or {}).items():
        if str(key).lower() in SENSITIVE_KEYS:
            safe[key] = MASK
        elif isinstance(value, str):
            safe[key] = redact_text(value)
        else:
            safe[key] = value
    return safe


def redact_body(body: str, content_type: str = "") -> str:
    """Redact JSON, form, XML and free-form request bodies."""
    if not body:
        return body
    lowered = (content_type or "").lower()
    stripped = body.strip()

    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
            return json.dumps(_mask_value(parsed), ensure_ascii=False)
        except Exception:
            pass

    if "x-www-form-urlencoded" in lowered or ("=" in stripped and "&" in stripped and "<" not in stripped):
        pairs = parse_qsl(stripped, keep_blank_values=True)
        if pairs:
            safe_pairs = [
                (k, MASK if k.lower() in SENSITIVE_KEYS else redact_text(v))
                for k, v in pairs
            ]
            return urlencode(safe_pairs)

    if "xml" in lowered or stripped.startswith("<"):
        return _XML_SECRET_RE.sub(lambda m: m.group(1) + MASK + m.group(3), body)

    return redact_text(_FORM_SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}={MASK}", body))
