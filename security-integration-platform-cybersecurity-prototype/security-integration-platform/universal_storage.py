import os

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent / "integration_platform.db"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def save_normalized_records(
    source: str,
    records: list[dict[str, Any]]
) -> dict[str, int]:
    saved = 0
    invalid = 0

    with db_connection() as conn:
        for record in records:
            try:
                entity_type = record.get("entity")
                external_id = record.get("external_id")

                if not entity_type:
                    raise ValueError("Normalized record has no entity type.")

                if external_id is None:
                    raise ValueError("Normalized record has no external ID.")

                conn.execute(
                    """
                    INSERT INTO records
                    (source, entity_type, external_id, data_json, fetched_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(source, entity_type, external_id)
                    DO UPDATE SET
                        data_json=excluded.data_json,
                        fetched_at=excluded.fetched_at
                    """,
                    (
                        source,
                        entity_type,
                        str(external_id),
                        json.dumps(record, default=str),
                        utc_now(),
                    ),
                )

                saved += 1

            except (ValueError, TypeError) as exc:
                conn.execute(
                    """
                    INSERT INTO invalid_records
                    (source, entity_type, record_json, reason, fetched_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        source,
                        record.get("entity", "unknown"),
                        json.dumps(record, default=str),
                        str(exc),
                        utc_now(),
                    ),
                )
                invalid += 1

    return {
        "records_saved": saved,
        "invalid_records": invalid,
    }
