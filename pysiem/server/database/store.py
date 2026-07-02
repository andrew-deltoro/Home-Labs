"""
Alert storage backed by SQLite.

Every matched detection rule produces one alert row. This module owns the
schema, reads, and writes — nothing else touches the DB file directly.
"""

import json
import sqlite3
from datetime import datetime, timezone


# DDL run once on startup to create the table and index if missing.
_CREATE_TABLE = """
    CREATE TABLE IF NOT EXISTS alerts (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT    NOT NULL,
        rule_id   TEXT    NOT NULL,
        rule_name TEXT    NOT NULL,
        severity  TEXT    NOT NULL,
        source    TEXT    NOT NULL,
        event_id  INTEGER,
        hostname  TEXT,
        message   TEXT,
        raw_event TEXT    NOT NULL
    )
"""

# Index on timestamp so ORDER BY timestamp DESC scans the index, not the table.
_CREATE_INDEX = """
    CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (timestamp DESC)
"""


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    # Row objects behave like dicts — row["column"] instead of row[0].
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """Create the alerts table and index if they don't already exist."""
    with _connect(db_path) as conn:
        conn.execute(_CREATE_TABLE)
        conn.execute(_CREATE_INDEX)


def insert_alert(db_path: str, rule: dict, event: dict) -> int:
    """
    Persist one triggered alert. Returns the new row ID.

    rule  — matched YAML rule dict (must have id, name, severity, source)
    event — raw log event dict forwarded by the agent
    """
    sql = """
        INSERT INTO alerts
            (timestamp, rule_id, rule_name, severity, source,
             event_id, hostname, message, raw_event)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    values = (
        datetime.now(timezone.utc).isoformat(),
        rule["id"],
        rule["name"],
        rule["severity"],
        rule["source"],
        event.get("EventID"),
        event.get("hostname"),
        # Cap message at 500 chars — full payload is in raw_event.
        (event.get("Message") or "")[:500],
        json.dumps(event),
    )
    with _connect(db_path) as conn:
        cursor = conn.execute(sql, values)
        return cursor.lastrowid


def get_alerts(
    db_path: str,
    limit: int = 200,
    severity: str | None = None,
    rule_id: str | None = None,
) -> list[dict]:
    """
    Return recent alerts, newest first.

    severity — filter to one level: 'low' | 'medium' | 'high' | 'critical'
    rule_id  — filter to one rule by its id string
    limit    — max rows returned (dashboard default: 200)
    """
    clauses: list[str] = []
    params: list = []

    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if rule_id:
        clauses.append("rule_id = ?")
        params.append(rule_id)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()

    return [dict(row) for row in rows]


def get_counts_by_severity(db_path: str) -> dict[str, int]:
    """Return {severity: count} for all alerts — used by the dashboard summary bar."""
    sql = "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
    with _connect(db_path) as conn:
        rows = conn.execute(sql).fetchall()
    return {row["severity"]: row["count"] for row in rows}


def get_alert_count_since(db_path: str, since_iso: str) -> int:
    """Count alerts newer than an ISO timestamp — used for the live refresh indicator."""
    sql = "SELECT COUNT(*) FROM alerts WHERE timestamp > ?"
    with _connect(db_path) as conn:
        return conn.execute(sql, (since_iso,)).fetchone()[0]
