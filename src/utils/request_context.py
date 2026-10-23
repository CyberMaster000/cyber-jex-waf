"""Per-request correlation ID shared across API layers."""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar
from typing import Optional

_request_id: ContextVar[str] = ContextVar("waf_request_id", default="")
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def new_request_id() -> str:
    return uuid.uuid4().hex


def sanitize_request_id(value: Optional[str]) -> str:
    if value and _SAFE_ID.match(value):
        return value
    return new_request_id()


def set_request_id(value: str) -> None:
    _request_id.set(value)


def get_request_id() -> str:
    return _request_id.get()
