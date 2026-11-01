
import os
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import yaml

from config_schema import ConnectorConfig
from security_engine.http_safety import safe_join
from data_mapper import normalize_response
from universal_storage import save_normalized_records
import ipaddress
import socket
from urllib.parse import urlparse


def load_connector_config(file_path: str) -> ConnectorConfig:
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Connector config not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        raw_config = yaml.safe_load(file)

    if not isinstance(raw_config, dict):
        raise ValueError("Connector YAML must contain a configuration object.")

    return ConnectorConfig.model_validate(raw_config)


def build_auth(config: ConnectorConfig):
    auth = config.auth

    if auth.type == "none":
        return None, {}

    if auth.type in ("api_key", "bearer"):
        secret = os.getenv(auth.secret_env)

        if not secret:
            raise ValueError(
                f"Required environment variable is not set: {auth.secret_env}"
            )

        if auth.type == "bearer":
            return None, {
                auth.header_name: f"{auth.prefix} {secret}".strip()
            }

        return None, {auth.header_name: secret}

    if auth.type == "basic":
        username = os.getenv(auth.username_env)
        password = os.getenv(auth.password_env)

        if username is None or password is None:
            raise ValueError("Basic authentication environment variables are missing.")

        return (username, password), {}

    raise ValueError("Unsupported authentication type.")


def validate_base_url(base_url: str) -> None:
    parsed = urlparse(base_url)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Invalid connector base URL.")

    # Require HTTPS for external integrations.
    if parsed.scheme != "https":
        raise ValueError("HTTPS is required for connector URLs.")

    hostname = parsed.hostname

    # Block localhost names.
    if hostname.lower() == "localhost" or hostname.lower().endswith(".localhost"):
        raise ValueError("Localhost destinations are not allowed.")

    try:
        # Resolve the hostname to its IP addresses.
        addresses = socket.getaddrinfo(
            hostname,
            parsed.port or 443,
            type=socket.SOCK_STREAM
        )

        if not addresses:
            raise ValueError("Could not resolve connector hostname.")

        # Reject the hostname if ANY resolved address is unsafe.
        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if (
                not ip.is_global
                or ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise ValueError(
                    "Connector URL resolves to an unsafe IP address."
                )

    except socket.gaierror:
        raise ValueError("Could not resolve connector hostname.")


def get_nested_value(data: Any, path: str | None) -> Any:
    if not path:
        return None

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


def extract_items(data: Any, items_path: str | None) -> list:
    if items_path:
        data = get_nested_value(data, items_path)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        return [data]

    raise ValueError("Could not extract records from API response.")


async def execute_connector(config: ConnectorConfig) -> dict[str, Any]:
    """Execute API requests with configurable pagination and normalization."""

    validate_base_url(config.base_url)

    auth, auth_headers = build_auth(config)

    url = safe_join(config.base_url, config.endpoint.path)

    headers = {
        **config.endpoint.headers,
        **auth_headers
    }

    pagination = config.pagination
    strategy = pagination.strategy

    params = dict(config.endpoint.params)
    all_items = []
    pages_fetched = 0
    last_status_code = None

    async with httpx.AsyncClient(
        timeout=config.timeout_seconds,
        follow_redirects=False
    ) as client:

        for page_number in range(pagination.max_pages):

            response = await client.request(
                method=config.endpoint.method,
                url=url,
                headers=headers,
                params=params,
                json=config.endpoint.body,
                auth=auth
            )

            response.raise_for_status()
            last_status_code = response.status_code

            try:
                response_data = response.json()
            except ValueError:
                response_data = response.text

            pages_fetched += 1

            if not isinstance(response_data, (dict, list)):
                if strategy != "none":
                    raise ValueError("Pagination requires a JSON response.")
                break

            current_items = extract_items(
                response_data,
                pagination.items_path
            )

            all_items.extend(current_items)

            if strategy == "none":
                break

            if not current_items:
                break

            if strategy == "page":
                params[pagination.page_param] = (
                    page_number + 2
                )

                if len(current_items) < pagination.page_size:
                    break

            elif strategy == "offset":
                current_offset = int(
                    params.get(pagination.offset_param, 0)
                )

                params[pagination.offset_param] = (
                    current_offset + pagination.page_size
                )

                if len(current_items) < pagination.page_size:
                    break

            elif strategy == "cursor":
                next_cursor = get_nested_value(
                    response_data,
                    pagination.next_path
                )

                if not next_cursor:
                    break

                params[pagination.cursor_param] = next_cursor

            elif strategy == "link_header":
                next_link = response.links.get("next", {}).get("url")

                if not next_link:
                    break

                next_url = urljoin(str(response.url), next_link)

                if (
                    urlparse(next_url).scheme != urlparse(config.base_url).scheme
                    or urlparse(next_url).netloc != urlparse(config.base_url).netloc
                ):
                    raise ValueError("Pagination link points outside the configured host.")

                url = next_url
                params = {}

    normalized_data = normalize_response(
        response_data=all_items,
        mapping=config.mapping,
        source=config.name
    )

    storage_result = save_normalized_records(
    source=config.name,
    records=normalized_data
    )

    return {
        "connector": config.name,
        "status_code": last_status_code,
        "pages_fetched": pages_fetched,
        "records_fetched": len(all_items),
        "data": all_items,
        "normalized_data": normalized_data,
        "records_saved": storage_result["records_saved"],
        "invalid_records": storage_result["invalid_records"]
    }


async def run_connector(config_path: str) -> dict[str, Any]:
    config = load_connector_config(config_path)

    if not config.enabled:
        raise ValueError(f"Connector '{config.name}' is disabled.")

    return await execute_connector(config)
