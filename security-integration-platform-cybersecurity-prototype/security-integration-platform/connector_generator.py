
from pathlib import Path
from typing import Any

import yaml

from api_discovery import discover_api
from config_schema import ConnectorConfig
from data_mapper import suggest_field_mapping


def discover_authentication(
    security_requirements: list,
    security_schemes: dict,
) -> dict[str, Any]:
    """Convert a supported OpenAPI security requirement into connector auth."""

    if not security_requirements:
        return {"type": "none"}

    if len(security_requirements) != 1:
        raise ValueError(
            "Multiple alternative authentication requirements "
            "are not supported yet."
        )

    requirement = security_requirements[0]

    if not isinstance(requirement, dict) or len(requirement) != 1:
        raise ValueError(
            "Combined authentication schemes are not supported yet."
        )

    scheme_name = next(iter(requirement))
    scheme = security_schemes.get(scheme_name)

    if not scheme:
        raise ValueError(
            f"Security scheme not found: {scheme_name}"
        )

    if (
        scheme.get("type") == "http"
        and scheme.get("scheme", "").lower() == "bearer"
    ):
        return {
            "type": "bearer",
            "secret_env": "CONNECTOR_API_TOKEN",
            "header_name": "Authorization",
            "prefix": "Bearer",
        }

    if scheme.get("type") == "apiKey":
        if scheme.get("in") != "header" or not scheme.get("name"):
            raise ValueError(
                "Automatic generation currently supports "
                "API keys in HTTP headers only."
            )

        return {
            "type": "api_key",
            "secret_env": "CONNECTOR_API_TOKEN",
            "header_name": scheme["name"],
        }

    raise ValueError(
        f"Unsupported authentication scheme: {scheme_name}"
    )


def generate_connector_config(
    spec_path: str,
    operation_id: str,
    connector_name: str,
    entity_name: str,
    field_mapping: dict[str, str] | None = None,
    external_id_field: str | None = None,
    sample_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Generate a validated connector configuration.

    Mapping can be supplied manually or suggested automatically
    from a sample API response.
    """

    discovery = discover_api(spec_path)

    selected = next(
        (
            operation
            for operation in discovery["operations"]
            if operation["operation_id"] == operation_id
        ),
        None,
    )

    if selected is None:
        raise ValueError(
            f"Operation not found: {operation_id}"
        )

    if selected["method"] != "GET":
        raise ValueError(
            "This initial generator supports GET operations only."
        )

    if "{" in selected["path"] or "}" in selected["path"]:
        raise ValueError(
            "Operations with required path parameters are not "
            "supported by this initial generator."
        )

    if not discovery["servers"]:
        raise ValueError(
            "OpenAPI specification does not define a server URL."
        )

    base_url = discovery["servers"][0].get("url")

    if not base_url:
        raise ValueError("The OpenAPI server URL is missing.")

    # Prefer operation-level security, including an explicit
    # empty list when the operation is public.
    auth = discover_authentication(
        selected.get("security", []),
        discovery["security_schemes"],
    )

    # Choose manual mapping or automatic suggestions.
    if field_mapping is not None:
        mapping_fields = dict(field_mapping)

    elif sample_record is not None:
        suggestions = suggest_field_mapping(sample_record)
        mapping_fields = dict(suggestions["suggested_fields"])

    else:
        raise ValueError(
            "Provide either field_mapping or sample_record "
            "to generate connector field mappings."
        )

    # Determine the external ID field.
    if external_id_field is not None:
        mapping_fields["external_id"] = external_id_field

    elif "external_id" not in mapping_fields:
        raise ValueError(
            "No external ID mapping was found. Provide "
            "external_id_field or a sample containing an ID."
        )

    if not mapping_fields.get("external_id"):
        raise ValueError("External ID mapping cannot be empty.")

    config = {
        "name": connector_name,
        "vendor": discovery["api_title"] or connector_name,
        "product": discovery["api_title"] or connector_name,
        "category": (
            selected["categories"][0]
            if selected.get("categories")
            and selected["categories"][0] != "general"
            else "security"
        ),
        "base_url": base_url,
        "auth": auth,
        "endpoint": {
            "path": selected["path"],
            "method": "GET",
        },
        "pagination": {
            "strategy": "none",
        },
        "mapping": {
            "entity": entity_name,
            "fields": mapping_fields,
            "required": ["external_id"],
        },
        "enabled": False,
        "timeout_seconds": 30,
    }

    # Validate before returning the generated configuration.
    validated = ConnectorConfig.model_validate(config)

    return validated.model_dump()


def save_connector_yaml(
    config: dict[str, Any],
    output_path: str,
) -> str:
    """Save generated connector configuration as YAML."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        yaml.safe_dump(
            config,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )

    return str(path)
