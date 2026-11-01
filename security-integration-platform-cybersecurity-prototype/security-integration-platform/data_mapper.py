
import re
from typing import Any

from config_schema import MappingConfig


# Common security fields and their possible vendor-specific names.
FIELD_ALIASES = {
    "external_id": [
        "id", "alert_id", "incident_id", "event_id",
        "device_id", "finding_id", "uuid"
    ],
    "title": [
        "title", "name", "alert_name", "incident_name",
        "rule_name", "event_name"
    ],
    "description": [
        "description", "message", "details",
        "summary", "reason"
    ],
    "severity": [
        "severity", "risk", "risk_level",
        "risk_score", "priority"
    ],
    "status": [
        "status", "state", "alert_status",
        "incident_status"
    ],
    "timestamp": [
        "timestamp", "created_at", "event_time",
        "time", "first_seen"
    ],
    "device_name": [
        "hostname", "device_name", "endpoint_name",
        "computer_name", "host_name"
    ],
    "ip_address": [
        "ip", "ip_address", "source_ip",
        "destination_ip", "src_ip", "dst_ip"
    ],
    "username": [
        "username", "user_name", "account_name",
        "email", "user"
    ],
    "source": [
        "source", "source_name", "vendor",
        "product"
    ],
}


def get_nested_value(data: Any, path: str) -> Any:
    """Read a value using a dotted path."""

    value = data

    for part in path.split("."):
        if isinstance(value, dict):
            value = value.get(part)

        elif isinstance(value, list) and part.isdigit():
            index = int(part)
            value = value[index] if index < len(value) else None

        else:
            return None

        if value is None:
            return None

    return value


def flatten_field_paths(
    data: dict[str, Any],
    prefix: str = ""
) -> dict[str, str]:
    """Convert nested JSON objects into dotted field paths."""

    paths = {}

    for key, value in data.items():
        current_path = f"{prefix}.{key}" if prefix else key

        if isinstance(value, dict):
            paths.update(
                flatten_field_paths(value, current_path)
            )
        else:
            paths[current_path] = key

    return paths


def normalize_field_name(name: str) -> str:
    """Normalize a field name for alias matching."""

    return re.sub(r"[^a-z0-9]", "", name.lower())


def suggest_field_mapping(
    sample_record: dict[str, Any]
) -> dict[str, Any]:
    """
    Suggest mappings from vendor fields to common
    security platform fields.

    This is rule-based discovery, not an AI-generated
    or guaranteed-correct mapping.
    """

    available_fields = flatten_field_paths(sample_record)

    normalized_paths = {}

    for path in available_fields:
        normalized_name = normalize_field_name(path.split(".")[-1])
        normalized_paths.setdefault(normalized_name, path)

    suggested_fields = {}
    confidence = {}

    for common_field, aliases in FIELD_ALIASES.items():

        for alias in aliases:
            normalized_alias = normalize_field_name(alias)

            if normalized_alias in normalized_paths:
                suggested_fields[common_field] = (
                    normalized_paths[normalized_alias]
                )

                confidence[common_field] = (
                    "high" if alias in [
                        "id", "alert_id", "incident_id",
                        "title", "severity", "timestamp"
                    ] else "medium"
                )

                break

    matched_paths = set(suggested_fields.values())

    unmatched_fields = [
        path for path in available_fields
        if path not in matched_paths
    ]

    return {
        "suggested_fields": suggested_fields,
        "confidence": confidence,
        "unmatched_fields": unmatched_fields,
        "requires_review": True,
    }


def normalize_record(
    raw_record: dict[str, Any],
    mapping: MappingConfig,
    source: str
) -> dict[str, Any]:
    """Convert one vendor record into the common format."""

    normalized = {
        "entity": mapping.entity,
        "source": source,
        "external_id": None,
        "fields": {},
        "raw_data": raw_record,
    }

    for common_field, vendor_path in mapping.fields.items():

        value = get_nested_value(raw_record, vendor_path)

        if value is not None:
            normalized["fields"][common_field] = value

            if common_field == "external_id":
                normalized["external_id"] = str(value)

    missing_fields = [
        field
        for field in mapping.required
        if field not in normalized["fields"]
    ]

    if missing_fields:
        raise ValueError(
            f"Missing required mapped fields: {missing_fields}"
        )

    return normalized


def normalize_response_with_errors(
    response_data: Any,
    mapping: MappingConfig,
    source: str,
    items_path: str | None = None,
) -> dict[str, Any]:
    """
    Normalize records individually and report invalid records
    without losing valid records from the same response.
    """

    records = response_data

    if items_path:
        records = get_nested_value(response_data, items_path)

    if isinstance(records, dict):
        records = [records]

    if not isinstance(records, list):
        raise ValueError(
            "API response does not contain a record or record list."
        )

    normalized_records = []
    invalid_records = []

    for index, record in enumerate(records):

        if not isinstance(record, dict):
            invalid_records.append({
                "index": index,
                "reason": "Record is not a JSON object.",
                "raw_data": record,
            })
            continue

        try:
            normalized_records.append(
                normalize_record(record, mapping, source)
            )

        except (ValueError, TypeError) as exc:
            invalid_records.append({
                "index": index,
                "reason": str(exc),
                "raw_data": record,
            })

    return {
        "normalized_records": normalized_records,
        "invalid_records": invalid_records,
        "total_records": len(records),
    }


def normalize_response(
    response_data: Any,
    mapping: MappingConfig,
    source: str,
    items_path: str | None = None,
) -> list[dict[str, Any]]:
    """
    Backward-compatible normalization function.

    Raises an error if any record is invalid, preserving
    the behavior expected by the existing connector engine.
    """

    result = normalize_response_with_errors(
        response_data=response_data,
        mapping=mapping,
        source=source,
        items_path=items_path,
    )

    if result["invalid_records"]:
        first_error = result["invalid_records"][0]

        raise ValueError(
            f"Record normalization failed at index "
            f"{first_error['index']}: {first_error['reason']}"
        )

    return result["normalized_records"]
