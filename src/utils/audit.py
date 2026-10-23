"""Append-only audit trail for privileged WAF operations."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from loguru import logger

_LOCK = threading.Lock()
_AUDIT_PATH = Path(os.environ.get("WAF_AUDIT_LOG", "logs/audit.jsonl"))


def fingerprint_secret(value: str) -> str:
    """Return a stable non-reversible identifier for an API key."""
    if not value:
        return "anonymous"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def audit(
    action: str,
    *,
    actor: str = "system",
    request_id: str = "",
    source_ip: str = "",
    details: Optional[dict[str, Any]] = None,
) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "actor": actor,
        "request_id": request_id,
        "source_ip": source_ip,
        "details": details or {},
    }
    try:
        _AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _LOCK:
            with _AUDIT_PATH.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except Exception as exc:  # pragma: no cover - audit must never break requests
        logger.warning("Failed to write audit entry: {}", exc)
    logger.bind(audit=True).info(
        "AUDIT {} by {} {}",
        action,
        actor,
        json.dumps(details or {}, ensure_ascii=True),
    )
