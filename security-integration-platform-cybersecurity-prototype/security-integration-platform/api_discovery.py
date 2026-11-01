
import json
import re
from pathlib import Path
from typing import Any

import yaml
from openapi_spec_validator import validate


SUPPORTED_METHODS = {
    "get", "post", "put", "patch", "delete"
}

SECURITY_CATEGORIES = {
    "alerts": [
        "alert", "alarms", "detections", "finding"
    ],
    "devices": [
        "device", "endpoint", "host", "asset", "machine"
    ],
    "vulnerabilities": [
        "vulnerability", "vulnerabilities", "cve", "weakness"
    ],
    "incidents": [
        "incident", "case", "investigation"
    ],
    "users": [
        "user", "account", "identity", "access"
    ],
    "network": [
        "network", "firewall", "ip", "traffic", "domain"
    ],
    "cloud_security": [
        "cloud", "workload", "container", "kubernetes"
    ],
    "data_protection": [
        "dlp", "data_loss", "data_protection", "quarantine"
    ],
}

RESPONSE_KEYWORDS = [
    "isolate", "block", "quarantine", "disable",
    "contain", "remediate", "resolve", "close",
    "terminate", "revoke", "suspend", "delete",
    "reset", "containment"
]


def load_api_spec(file_path: str) -> dict[str, Any]:
    """Load and validate an OpenAPI JSON or YAML specification."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"API specification not found: {path}"
        )

    content = path.read_text(encoding="utf-8")

    if path.suffix.lower() == ".json":
        spec = json.loads(content)

    elif path.suffix.lower() in (".yaml", ".yml"):
        spec = yaml.safe_load(content)

    else:
        raise ValueError(
            "Only JSON, YAML and YML files are supported."
        )

    if not isinstance(spec, dict):
        raise ValueError(
            "The API specification must be an object."
        )

    validate(spec)

    return spec


def classify_operation(
    path: str,
    method: str,
    operation_id: str = "",
    summary: str = "",
    description: str = "",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Classify an API operation using descriptive keywords."""

    text = " ".join([
        path,
        operation_id or "",
        summary or "",
        description or "",
        " ".join(tags or []),
    ]).lower()

    detected_categories = []

    for category, keywords in SECURITY_CATEGORIES.items():
        if any(keyword in text for keyword in keywords):
            detected_categories.append(category)

    is_response_action = any(
        keyword in text for keyword in RESPONSE_KEYWORDS
    )

    method = method.upper()

    if method == "GET":
        operation_type = "read"
        risk_level = "low"

    elif method in {"POST", "PUT", "PATCH"}:
        operation_type = "write"
        risk_level = "medium"

    else:
        operation_type = "delete"
        risk_level = "high"

    if is_response_action and method != "GET":
        risk_level = "high"

    return {
        "categories": detected_categories or ["general"],
        "operation_type": operation_type,
        "risk_level": risk_level,
        "is_response_action": is_response_action,
        "requires_human_approval": (
            method != "GET"
        ),
    }


def merge_parameters(
    path_parameters: list[Any],
    operation_parameters: list[Any],
) -> list[Any]:
    """Merge path-level and operation-level parameters."""

    merged = {}

    for parameter in path_parameters + operation_parameters:
        if not isinstance(parameter, dict):
            continue

        key = (
            parameter.get("name"),
            parameter.get("in"),
        )

        if key != (None, None):
            merged[key] = parameter

    return list(merged.values())


def discover_api(file_path: str) -> dict[str, Any]:
    """Discover API operations and classify their capabilities."""

    spec = load_api_spec(file_path)

    info = spec.get("info", {})
    servers = spec.get("servers", [])

    global_security = spec.get("security", [])

    operations = []

    for path, path_details in spec.get("paths", {}).items():

        if not isinstance(path_details, dict):
            continue

        path_parameters = path_details.get(
            "parameters", []
        )

        if not isinstance(path_parameters, list):
            path_parameters = []

        for method, details in path_details.items():

            if method.lower() not in SUPPORTED_METHODS:
                continue

            if not isinstance(details, dict):
                continue

            operation_parameters = details.get(
                "parameters", []
            )

            if not isinstance(operation_parameters, list):
                operation_parameters = []

            parameters = merge_parameters(
                path_parameters,
                operation_parameters,
            )

            tags = details.get("tags", [])

            if not isinstance(tags, list):
                tags = []

            operation_security = details.get(
                "security",
                global_security,
            )

            classification = classify_operation(
                path=path,
                method=method,
                operation_id=details.get("operationId", ""),
                summary=details.get("summary", ""),
                description=details.get("description", ""),
                tags=tags,
            )

            operations.append({
                "path": path,
                "method": method.upper(),
                "operation_id": details.get("operationId"),
                "summary": details.get("summary"),
                "description": details.get("description"),
                "parameters": parameters,
                "request_body": details.get("requestBody"),
                "responses": details.get("responses", {}),
                "tags": tags,
                "security": operation_security,
                **classification,
            })

    security_schemes = (
        spec.get("components", {}).get(
            "securitySchemes", {}
        )
    )

    return {
        "api_title": info.get("title"),
        "api_version": info.get("version"),
        "api_description": info.get("description"),
        "servers": servers,
        "security_schemes": security_schemes,
        "global_security": global_security,
        "operation_count": len(operations),
        "operations": operations,
    }
