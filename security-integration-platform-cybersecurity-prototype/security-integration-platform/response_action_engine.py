import os

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from config_schema import ActionExecutionConfig
from approval_manager import verify_approval
from security_engine.http_safety import safe_path_param


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("PLATFORM_DB_PATH") or BASE_DIR / "integration_platform.db")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def initialize_action_audit() -> None:
    """Create the action audit table if it does not exist."""

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connector_name TEXT NOT NULL,
                action_name TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                dry_run INTEGER NOT NULL,
                outcome TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


def record_action_audit(
    execution: ActionExecutionConfig,
    outcome: str,
    details: dict[str, Any],
) -> None:
    """Store an audit entry without storing credentials."""

    initialize_action_audit()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO action_audit (
                connector_name,
                action_name,
                requested_by,
                risk_level,
                dry_run,
                outcome,
                details_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                execution.connector_name,
                execution.action.name,
                execution.requested_by,
                execution.action.risk_level,
                int(execution.dry_run),
                outcome,
                json.dumps(details, default=str),
                utc_now(),
            ),
        )


def prepare_action(
    execution: ActionExecutionConfig,
    supplied_parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Validate and prepare a response action.

    This function NEVER sends an HTTP request.
    It only creates a safe dry-run execution plan.
    """

    parameters = supplied_parameters or {}
    action = execution.action
    # SECURITY: the caller must never be able to switch approval off. Only "low" risk actions may skip it,
    # and only when the server-side definition says so; everything else always requires verified approval.
    approval_needed = True if action.risk_level != "low" else action.requires_approval

    result = {
        "connector": execution.connector_name,
        "action": action.name,
        "risk_level": action.risk_level,
        "requested_by": execution.requested_by,
        "dry_run": execution.dry_run,
        "approval_required": approval_needed,
        "approved": False,
        "ready": False,
        "execution_performed": False,
        "planned_method": action.method,
        "planned_path": None,
        "errors": [],
    }

    try:
        # 1. Require dry-run mode.
        if not execution.dry_run:
            raise ValueError(
                "Real action execution is not implemented. "
                "Only dry-run mode is permitted."
            )

        # 2. Ensure the action is enabled.
        if not action.enabled:
            raise ValueError(
                "This response action is disabled."
            )

        # 3. Enforce approval for high-risk actions.
        if approval_needed:
            if not execution.approval_id:
                raise ValueError("Human approval is required before this action can proceed.")
            # Verifies: exists, APPROVED by someone other than the requester, unexpired, unused,
            # same connector + action + parameters. Consumes the approval (single use).
            if not verify_approval(execution.approval_id, execution.connector_name, action.name, parameters):
                raise ValueError("Approval is missing, not approved, expired, already used, or does not match this action.")

        # 4. Validate the action path.
        if not action.path.startswith("/"):
            raise ValueError(
                "Action path must begin with '/'."
            )

        if "://" in action.path or "?" in action.path or "#" in action.path:
            raise ValueError(
                "Action path must be a relative API path."
            )

        if ".." in action.path.split("/"):
            raise ValueError(
                "Path traversal is not allowed."
            )

        # 5. Find required path parameters.
        placeholders = re.findall(
            r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}",
            action.path,
        )

        missing = [
            name for name in placeholders
            if name not in parameters or parameters[name] is None
        ]

        if missing:
            raise ValueError(
                "Missing path parameters: " + ", ".join(missing)
            )

        # 6. Safely substitute path parameters.
        planned_path = action.path

        for name in placeholders:
            value = safe_path_param(parameters[name])

            planned_path = planned_path.replace(
                "{" + name + "}",
                quote(value, safe=""),
            )

        # 7. Build the dry-run plan.
        result["planned_path"] = planned_path
        result["approved"] = True  # reaching here means verify_approval() passed (or approval not required)

        result["ready"] = True

        record_action_audit(
            execution,
            "DRY_RUN_PREPARED",
            {
                "planned_method": action.method,
                "planned_path": planned_path,
                "approval_required": approval_needed,
                "approval_id_present": bool(execution.approval_id),
                "execution_performed": False,
            },
        )

    except Exception as exc:
        result["errors"].append(str(exc))

        record_action_audit(
            execution,
            "REJECTED",
            {
                "reason": str(exc),
                "execution_performed": False,
            },
        )

    return result


def get_recent_action_audit(limit: int = 20) -> list[dict[str, Any]]:
    """Return recent action audit entries."""

    if limit < 1 or limit > 500:
        raise ValueError("Limit must be between 1 and 500.")

    initialize_action_audit()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            """
            SELECT *
            FROM action_audit
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        {
            **dict(row),
            "details": json.loads(row["details_json"]),
        }
        for row in rows
    ]
