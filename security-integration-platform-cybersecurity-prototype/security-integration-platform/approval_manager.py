import os

import json
import sqlite3
import uuid
import hashlib

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("PLATFORM_DB_PATH") or BASE_DIR / "integration_platform.db")

APPROVAL_EXPIRY_MINUTES = 15


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def initialize_approval_database() -> None:
    """Create approval registry."""

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                approval_id TEXT UNIQUE NOT NULL,
                connector_name TEXT NOT NULL,
                action_name TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                approver TEXT,
                status TEXT NOT NULL,
                parameters_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                decided_at TEXT,
                consumed_at TEXT
            )
            """
        )


def hash_parameters(parameters: dict[str, Any]) -> str:
    """Create a stable hash of action parameters."""

    canonical = json.dumps(
        parameters,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


def request_approval(
    connector_name: str,
    action_name: str,
    requested_by: str,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Create a pending approval request."""

    initialize_approval_database()

    if not connector_name or not action_name or not requested_by:
        raise ValueError("Connector, action and requester are required.")

    if not isinstance(parameters, dict):
        raise ValueError("Parameters must be a dictionary.")

    now = utc_now()
    expires = now + timedelta(minutes=APPROVAL_EXPIRY_MINUTES)

    approval_id = str(uuid.uuid4())

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO action_approvals (
                approval_id,
                connector_name,
                action_name,
                requested_by,
                status,
                parameters_hash,
                created_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                approval_id,
                connector_name,
                action_name,
                requested_by,
                "PENDING",
                hash_parameters(parameters),
                now.isoformat(),
                expires.isoformat(),
            ),
        )

    return {
        "approval_id": approval_id,
        "status": "PENDING",
        "connector_name": connector_name,
        "action_name": action_name,
        "requested_by": requested_by,
        "expires_at": expires.isoformat(),
    }


def decide_approval(
    approval_id: str,
    approver: str,
    decision: str,
) -> dict[str, Any]:
    """Approve or reject a pending request."""

    initialize_approval_database()

    decision = decision.upper()

    if decision not in ("APPROVED", "REJECTED"):
        raise ValueError("Decision must be APPROVED or REJECTED.")

    if not approver:
        raise ValueError("Approver identity is required.")

    now = utc_now()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT *
            FROM action_approvals
            WHERE approval_id = ?
            """,
            (approval_id,),
        ).fetchone()

        if row is None:
            raise ValueError("Approval request not found.")

        if row["status"] != "PENDING":
            raise ValueError("Approval request is no longer pending.")
        if approver.strip().lower() == row["requested_by"].strip().lower():
            raise PermissionError("Separation of duties: requesters cannot decide their own requests.")

        expires_at = datetime.fromisoformat(row["expires_at"])

        if now >= expires_at:
            conn.execute(
                """
                UPDATE action_approvals
                SET status = 'EXPIRED'
                WHERE approval_id = ?
                """,
                (approval_id,),
            )
            conn.commit()
            raise ValueError("Approval request has expired.")

        conn.execute(
            """
            UPDATE action_approvals
            SET status = ?,
                approver = ?,
                decided_at = ?
            WHERE approval_id = ?
              AND status = 'PENDING'
            """,
            (
                decision,
                approver,
                now.isoformat(),
                approval_id,
            ),
        )

    return {
        "approval_id": approval_id,
        "status": decision,
        "approver": approver,
        "decided_at": now.isoformat(),
    }


def verify_approval(
    approval_id: str,
    connector_name: str,
    action_name: str,
    parameters: dict[str, Any],
) -> bool:
    """
    Verify an approval against the exact requested action.

    A successful verification consumes the approval.
    Each approval can be used only once.
    """

    initialize_approval_database()

    now = utc_now()
    supplied_hash = hash_parameters(parameters)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT *
            FROM action_approvals
            WHERE approval_id = ?
            """,
            (approval_id,),
        ).fetchone()

        if row is None:
            return False

        if row["status"] != "APPROVED":
            return False

        if row["consumed_at"] is not None:
            return False

        if now >= datetime.fromisoformat(row["expires_at"]):
            conn.execute(
                """
                UPDATE action_approvals
                SET status = 'EXPIRED'
                WHERE approval_id = ?
                """,
                (approval_id,),
            )
            return False

        if row["connector_name"] != connector_name:
            return False

        if row["action_name"] != action_name:
            return False

        if row["parameters_hash"] != supplied_hash:
            return False

        conn.execute(
            """
            UPDATE action_approvals
            SET consumed_at = ?
            WHERE approval_id = ?
              AND consumed_at IS NULL
              AND status = 'APPROVED'
            """,
            (now.isoformat(), approval_id),
        )

    return True


def get_approval_requests(limit: int = 20) -> list[dict[str, Any]]:
    """Retrieve recent approval requests."""

    if limit < 1 or limit > 500:
        raise ValueError("Limit must be between 1 and 500.")

    initialize_approval_database()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            """
            SELECT *
            FROM action_approvals
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]
