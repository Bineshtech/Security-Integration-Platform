
import os
import base64
import json
import argparse
from typing import Any
from urllib.parse import urljoin

import httpx

from connector_engine import (
    load_connector_config,
    validate_base_url,
)
from data_mapper import (
    normalize_record,
    get_nested_value,
)


def test_connector(config_path: str) -> dict[str, Any]:
    """
    Read-only connector test.

    Checks configuration, URL security, authentication,
    connectivity, JSON response, pagination configuration,
    required fields and normalization.

    Does not save records or execute response actions.
    """

    result = {
        "connector": None,
        "configuration_valid": False,
        "url_valid": False,
        "authentication_ready": False,
        "connection_successful": False,
        "json_valid": False,
        "response_structure_valid": False,
        "pagination_configured": False,
        "normalization_successful": False,
        "records_received": 0,
        "records_normalized": 0,
        "invalid_records": 0,
        "missing_fields": [],
        "http_status": None,
        "errors": [],
    }

    # 1. Load connector configuration
    try:
        config = load_connector_config(config_path)
        result["connector"] = config.name
        result["configuration_valid"] = True

    except Exception as exc:
        result["errors"].append(
            f"Configuration error: {exc}"
        )
        return result

    # 2. Only permit GET requests
    if config.endpoint.method.upper() != "GET":
        result["errors"].append(
            "Read-only tester supports GET requests only."
        )
        return result

    # 3. Validate URL and apply SSRF checks
    try:
        validate_base_url(config.base_url)
        result["url_valid"] = True

    except Exception as exc:
        result["errors"].append(
            f"URL security validation error: {exc}"
        )
        return result

    # 4. Prepare authentication
    headers = dict(config.endpoint.headers)
    auth = config.auth

    try:
        if auth.type == "none":
            pass

        elif auth.type == "bearer":
            token = os.getenv(auth.secret_env)

            if not token:
                raise ValueError(
                    f"Environment variable {auth.secret_env} is missing."
                )

            prefix = auth.prefix or "Bearer"
            headers[auth.header_name] = f"{prefix} {token}"

        elif auth.type == "api_key":
            token = os.getenv(auth.secret_env)

            if not token:
                raise ValueError(
                    f"Environment variable {auth.secret_env} is missing."
                )

            headers[auth.header_name] = token

        elif auth.type == "basic":
            username = os.getenv(auth.username_env)
            password = os.getenv(auth.password_env)

            if not username or not password:
                raise ValueError(
                    "Basic authentication environment variables are missing."
                )

            credentials = base64.b64encode(
                f"{username}:{password}".encode()
            ).decode()

            headers["Authorization"] = (
                f"Basic {credentials}"
            )

        else:
            raise ValueError(
                f"Unsupported authentication type: {auth.type}"
            )

        result["authentication_ready"] = True

    except Exception as exc:
        result["errors"].append(
            f"Authentication error: {exc}"
        )
        return result

    # 5. Construct request URL
    request_url = urljoin(
        config.base_url.rstrip("/") + "/",
        config.endpoint.path.lstrip("/")
    )

    # 6. Make a read-only request
    try:
        with httpx.Client(
            timeout=config.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        ) as client:

            response = client.get(
                request_url,
                headers=headers,
                params=config.endpoint.params,
            )

        result["http_status"] = response.status_code

        if response.status_code in (401, 403):
            result["errors"].append(
                f"Authentication rejected by API: HTTP {response.status_code}."
            )
            return result

        response.raise_for_status()

        result["connection_successful"] = True

    except httpx.TimeoutException:
        result["errors"].append(
            "API request timed out."
        )
        return result

    except httpx.HTTPStatusError as exc:
        result["errors"].append(
            f"API returned HTTP {exc.response.status_code}."
        )
        return result

    except httpx.RequestError as exc:
        result["errors"].append(
            f"Connection failed: {type(exc).__name__}."
        )
        return result

    # 7. Parse JSON
    try:
        response_data = response.json()
        result["json_valid"] = True

    except ValueError:
        result["errors"].append(
            "API response is not valid JSON."
        )
        return result

    # 8. Extract records
    try:
        items_path = config.pagination.items_path

        records = (
            get_nested_value(response_data, items_path)
            if items_path
            else response_data
        )

        if isinstance(records, dict):
            records = [records]

        if not isinstance(records, list):
            raise ValueError(
                "Response does not contain a list of records."
            )

        result["response_structure_valid"] = True
        result["records_received"] = len(records)

    except Exception as exc:
        result["errors"].append(
            f"Response structure error: {exc}"
        )
        return result

    # 9. Report pagination configuration
    result["pagination_configured"] = (
        config.pagination.strategy != "none"
    )

    # This tester currently tests one page only.
    if config.pagination.strategy != "none":
        result["errors"].append(
            "Pagination is configured but multi-page testing "
            "is not implemented yet."
        )

    # 10. Check required fields and normalize records
    normalized_records = []
    invalid_records = 0
    missing_fields = set()

    for index, record in enumerate(records):

        if not isinstance(record, dict):
            invalid_records += 1
            continue

        try:
            normalized = normalize_record(
                raw_record=record,
                mapping=config.mapping,
                source=config.name,
            )

            normalized_records.append(normalized)

        except Exception:
            invalid_records += 1

            for field in config.mapping.required:
                source_field = config.mapping.fields.get(field)

                if source_field is None:
                    missing_fields.add(field)
                elif get_nested_value(record, source_field) is None:
                    missing_fields.add(source_field)

    result["records_normalized"] = len(normalized_records)
    result["invalid_records"] = invalid_records
    result["missing_fields"] = sorted(missing_fields)

    result["normalization_successful"] = (
        len(records) > 0
        and invalid_records == 0
    )

    return result


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Read-only universal connector tester"
    )

    parser.add_argument(
        "config",
        help="Path to connector YAML configuration"
    )

    args = parser.parse_args()

    test_result = test_connector(args.config)

    print("\nUNIVERSAL CONNECTOR TEST RESULT")
    print("=" * 50)

    print(json.dumps(test_result, indent=4))

    if (
        test_result["configuration_valid"]
        and test_result["url_valid"]
        and test_result["connection_successful"]
        and test_result["json_valid"]
        and test_result["normalization_successful"]
        and not test_result["errors"]
    ):
        print("\nTEST PASSED")
    else:
        print("\nTEST FAILED OR INCOMPLETE")
