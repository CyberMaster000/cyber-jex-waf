import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from loguru import logger
from pydantic import BaseModel

from src.utils.config import get_settings


class DetectionEvent(BaseModel):
    request_id: str = ""
    timestamp: str = ""
    method: str = ""
    path: str = ""
    query_params: dict[str, Any] = {}
    headers: dict[str, str] = {}
    body: str = ""
    source_ip: str = ""
    user_agent: str = ""
    anomaly_score: float = 0.0
    is_anomaly: bool = False
    model_version: str = "v1.0"
    latency_ms: float = 0.0


class Database:
    def __init__(self, db_path: Optional[str] = None):
        settings = get_settings()
        self.db_path = db_path or settings.storage.db_path
        self.max_events = int(getattr(settings.storage, "max_events", 100000))
        self._writes_since_prune = 0
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    request_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    query_params TEXT DEFAULT '{}',
                    headers TEXT DEFAULT '{}',
                    body TEXT DEFAULT '',
                    source_ip TEXT DEFAULT '',
                    user_agent TEXT DEFAULT '',
                    anomaly_score REAL NOT NULL,
                    is_anomaly INTEGER NOT NULL DEFAULT 0,
                    model_version TEXT DEFAULT 'v1.0',
                    latency_ms REAL DEFAULT 0.0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON detections(timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_is_anomaly ON detections(is_anomaly)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS training_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    raw_request TEXT NOT NULL,
                    label TEXT DEFAULT 'benign',
                    added_at TEXT NOT NULL
                )
            """)
        logger.info("Database initialized at {}", self.db_path)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def store_event(self, event: DetectionEvent) -> str:
        if not event.request_id:
            event.request_id = str(uuid.uuid4())
        if not event.timestamp:
            event.timestamp = datetime.now(timezone.utc).isoformat()

        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO detections
                (request_id, timestamp, method, path, query_params, headers, body,
                 source_ip, user_agent, anomaly_score, is_anomaly, model_version, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.request_id,
                    event.timestamp,
                    event.method,
                    event.path,
                    json.dumps(event.query_params),
                    json.dumps(event.headers),
                    event.body,
                    event.source_ip,
                    event.user_agent,
                    event.anomaly_score,
                    int(event.is_anomaly),
                    event.model_version,
                    event.latency_ms,
                ),
            )
        self._writes_since_prune += 1
        if self._writes_since_prune >= 1000:
            self._writes_since_prune = 0
            try:
                self.prune_old_events(self.max_events)
            except Exception as exc:  # pragma: no cover - maintenance best effort
                logger.warning("Failed to prune old events: {}", exc)
        logger.debug("Stored detection event {}", event.request_id)
        return event.request_id

    def get_events(
        self,
        limit: int = 100,
        offset: int = 0,
        anomalies_only: bool = False,
        method: Optional[str] = None,
        path_contains: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM detections WHERE 1=1"
        params: list[Any] = []

        if anomalies_only:
            query += " AND is_anomaly = 1"
        if method:
            query += " AND method = ?"
            params.append(method.upper())
        if path_contains:
            query += " AND path LIKE ?"
            params.append(f"%{path_contains}%")

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
            events = []
            for row in rows:
                event = dict(row)
                for field in ("query_params", "headers"):
                    value = event.get(field)
                    if isinstance(value, str):
                        try:
                            event[field] = json.loads(value)
                        except Exception:
                            event[field] = {}
                event["is_anomaly"] = bool(event.get("is_anomaly"))
                events.append(event)
            return events

    def get_event_by_id(self, request_id: str) -> Optional[dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM detections WHERE request_id = ?", (request_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_stats(self) -> dict[str, Any]:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
            anomalies = conn.execute(
                "SELECT COUNT(*) FROM detections WHERE is_anomaly = 1"
            ).fetchone()[0]
            benign = total - anomalies
            avg_score = conn.execute(
                "SELECT COALESCE(AVG(anomaly_score), 0) FROM detections"
            ).fetchone()[0]
            methods = conn.execute(
                "SELECT method, COUNT(*) as cnt FROM detections GROUP BY method ORDER BY cnt DESC"
            ).fetchall()
            return {
                "total_requests": total,
                "anomalies": anomalies,
                "benign": benign,
                "avg_score": round(avg_score, 4),
                "method_distribution": {r["method"]: r["cnt"] for r in methods},
            }

    def add_training_sample(self, raw_request: str, label: str = "benign"):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO training_data (timestamp, raw_request, label, added_at) VALUES (?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    raw_request,
                    label,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def get_training_samples(self, label: str = "benign") -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM training_data WHERE label = ? ORDER BY added_at DESC",
                (label,),
            ).fetchall()
            return [dict(row) for row in rows]

    def prune_old_events(self, max_events: int = 100000):
        with self._conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
            if count > max_events:
                to_delete = count - max_events
                conn.execute(
                    """DELETE FROM detections WHERE request_id IN
                    (SELECT request_id FROM detections ORDER BY timestamp ASC LIMIT ?)""",
                    (to_delete,),
                )
                logger.info("Pruned {} old detection events", to_delete)

    def clear_events(self) -> int:
        with self._conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
            conn.execute("DELETE FROM detections")
            logger.info("Cleared all {} detection events from database", count)
            return count


db_instance: Optional[Database] = None


def get_db() -> Database:
    global db_instance
    if db_instance is None:
        db_instance = Database()
    return db_instance
