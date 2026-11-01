"""
Config-Driven Security Integration Platform - starter app

Run:
    pip install fastapi uvicorn httpx pyyaml
    uvicorn app:app --reload

Environment:
    Set secrets referenced by connector YAML files, for example:
    macOS/Linux:         export PLATFORM_ADMIN_PASSWORD="choose-a-strong-password"

API:
    GET  /health
    GET  /connectors
    POST /config/validate
    POST /sync/{connector_name}
    GET  /records/{entity_type}
    GET  /runs
    GET  /docs

This is an MVP foundation. It supports API-key, bearer-token and Basic authentication;
no-pagination, Link-header, page-number and offset pagination; retries/backoff; 429
Retry-After; dotted-path field mapping; invalid-record quarantine; SQLite storage.
"""

from __future__ import annotations

import json
import logging
import threading
from contextlib import asynccontextmanager
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import yaml
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from engine_utils import parse_schedule, normalize_config, resolve_field
import secret_store
from security_engine.yaml_guard import load_safe_yaml
from security_engine.network import validate_external_url
from security_engine.database import secure_sqlite_file
from security_engine.auth import AuthManager
from security_engine.api import InMemoryRateLimiter
from security_engine.http_safety import (
    safe_join, follow_next_url, clamp_retry_after, validate_header_name,
    validate_secret_env, MAX_RESPONSE_BYTES,
)
import secrets as _secrets

# ---------------------------------------------------------------------------
# App setup and basic settings
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "configs"
DB_PATH = Path(os.environ.get("PLATFORM_DB_PATH") or BASE_DIR / "integration_platform.db")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("integration-platform")

@asynccontextmanager
async def lifespan(_app):
    """Start the connector scheduler (FR-4) unless PLATFORM_SCHEDULER=0."""
    if os.getenv("PLATFORM_SCHEDULER", "1") != "0":
        scheduler.start()
    yield
    scheduler.stop_event.set()


_DOCS = os.getenv("PLATFORM_ENABLE_DOCS") == "1"  # Swagger needs CDN scripts; off by default (strict CSP)
app = FastAPI(
    title="Config-Driven Security Integration Platform",
    description="Connect data sources using YAML configuration instead of connector-specific code.",
    version="0.4.0",
    lifespan=lifespan,
    docs_url="/docs" if _DOCS else None, redoc_url=None, openapi_url="/openapi.json" if _DOCS else None,
)

# --- Authentication state -------------------------------------------------
_key = os.getenv("PLATFORM_SIGNING_KEY") or _secrets.token_urlsafe(48)
if not os.getenv("PLATFORM_SIGNING_KEY"):
    logging.getLogger("integration-platform").warning(
        "PLATFORM_SIGNING_KEY not set: using an ephemeral key; all sessions end on restart.")
auth_manager = AuthManager(_key)
login_limiter = InMemoryRateLimiter(limit=5, window_seconds=60)      # per ip+username
ip_limiter = InMemoryRateLimiter(limit=30, window_seconds=60)        # per ip, login attempts
sync_limiter = InMemoryRateLimiter(limit=10, window_seconds=60)      # per user
api_limiter = InMemoryRateLimiter(limit=300, window_seconds=60)      # per ip, everything
ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    secure_sqlite_file(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database() -> None:
    with db_connection() as conn:
        # Migrate older databases where the login table was called `users` (that name is now the FR-11 data table).
        cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "password_hash" in cols:
            conn.execute("ALTER TABLE users RENAME TO platform_accounts")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                external_id TEXT,
                data_json TEXT NOT NULL,
                fetched_at TEXT NOT NULL,
                UNIQUE(source, entity_type, external_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                records_fetched INTEGER DEFAULT 0,
                records_saved INTEGER DEFAULT 0,
                invalid_records INTEGER DEFAULT 0,
                error TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS platform_accounts (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS invalid_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                record_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                fetched_at TEXT NOT NULL
            )
            """
        )


TYPED_TABLES = {
    "users": ("source TEXT NOT NULL, id TEXT NOT NULL, name TEXT, email TEXT, status TEXT, last_login TEXT, fetched_at TEXT NOT NULL, PRIMARY KEY (source, id)",
              ["id", "name", "email", "status", "last_login"], "source, id"),
    "devices": ("source TEXT NOT NULL, id TEXT NOT NULL, hostname TEXT, ip TEXT, os TEXT, owner TEXT, last_seen TEXT, fetched_at TEXT NOT NULL, PRIMARY KEY (source, id)",
                ["id", "hostname", "ip", "os", "owner", "last_seen"], "source, id"),
    "events": ("source TEXT NOT NULL, entity TEXT NOT NULL, id TEXT NOT NULL, type TEXT, severity TEXT, timestamp TEXT, description TEXT, fetched_at TEXT NOT NULL, PRIMARY KEY (source, entity, id)",
               ["id", "type", "severity", "timestamp", "description"], "source, entity, id"),
}
EVENT_ENTITIES = {"event", "alert", "vulnerability", "ticket"}


def initialize_typed_tables() -> None:
    """FR-11: every source lands in the same typed tables (users / devices / events)."""
    with db_connection() as conn:
        for table, (ddl, _cols, _pk) in TYPED_TABLES.items():
            conn.execute(f"CREATE TABLE IF NOT EXISTS {table} ({ddl})")


def _scalar(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float)):
        return value
    return json.dumps(value, default=str)


def save_typed(conn: sqlite3.Connection, source: str, entity: str, record: dict[str, Any]) -> None:
    entity = entity.lower()
    table = "users" if entity == "user" else "devices" if entity == "device" else "events" if entity in EVENT_ENTITIES else None
    if table is None or record.get("id") in (None, ""):
        return
    _ddl, cols, pk = TYPED_TABLES[table]
    values = {c: _scalar(record.get(c)) for c in cols}
    values.update(id=str(record["id"]), source=source, fetched_at=record["fetched_at"])
    if table == "events":
        values["entity"] = entity
    names = list(values)
    updates = ", ".join(f"{n}=excluded.{n}" for n in names if n not in {x.strip() for x in pk.split(",")})
    conn.execute(  # table/column names come from the constants above, never from input
        f"INSERT INTO {table} ({', '.join(names)}) VALUES ({', '.join('?' * len(names))}) ON CONFLICT({pk}) DO UPDATE SET {updates}",
        [values[n] for n in names],
    )


initialize_database()
initialize_typed_tables()


def bootstrap_admin() -> None:
    """Create the first admin from env vars, or generate a one-time password printed to the console."""
    with db_connection() as conn:
        if conn.execute("SELECT 1 FROM platform_accounts LIMIT 1").fetchone():
            return
        user = os.getenv("PLATFORM_ADMIN_USER", "admin")
        password = os.getenv("PLATFORM_ADMIN_PASSWORD")
        generated = not password
        if generated:
            password = _secrets.token_urlsafe(18)
        conn.execute("INSERT INTO platform_accounts VALUES (?,?,?,?)",
                     (user, auth_manager.hash_password(password), "admin", utc_now()))
    if generated:
        print(f"\n*** First-run admin created. username={user} password={password}  (shown once; change it) ***\n")


bootstrap_admin()
_DUMMY_HASH = auth_manager.hash_password("dummy-password-for-timing")


# ---------------------------------------------------------------------------
# Configuration models and validation
# ---------------------------------------------------------------------------

STRICT = ConfigDict(extra="forbid")
_CRED_HEADER = re.compile(r"auth|key|token|secret|password|cookie", re.I)


class AuthConfig(BaseModel):
    model_config = STRICT
    type: str = "none"
    secret: str | None = None
    header: str | None = None
    prefix: str | None = None
    username_env: str | None = None
    password_env: str | None = None
    optional: bool = False  # if True and the secret is not set, call the API unauthenticated

    @field_validator("type")
    @classmethod
    def supported_auth_type(cls, value: str) -> str:
        allowed = {"none", "api_key", "bearer", "basic"}
        if value not in allowed:
            raise ValueError(f"auth.type must be one of: {', '.join(sorted(allowed))}")
        return value

    @field_validator("secret", "username_env", "password_env")
    @classmethod
    def env_name_allowed(cls, value: str | None) -> str | None:
        return validate_secret_env(value) if value else value

    @field_validator("header")
    @classmethod
    def header_allowed(cls, value: str | None) -> str | None:
        return validate_header_name(value) if value else value

    @model_validator(mode="after")
    def required_fields(self):
        if self.type in {"api_key", "bearer"} and not self.secret:
            raise ValueError(f"auth.secret (a CONNECTOR_* secret name) is required for auth.type={self.type}")
        if self.type == "basic" and not (self.username_env and self.password_env):
            raise ValueError("auth.username_env and auth.password_env are required for basic auth")
        return self


class EndpointConfig(BaseModel):
    model_config = STRICT
    path: str
    method: str = "GET"
    params: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("method")
    @classmethod
    def method_ok(cls, value: str) -> str:
        if value.upper() not in {"GET", "POST"}:
            raise ValueError("endpoint.method must be GET or POST")
        return value.upper()

    @field_validator("headers")
    @classmethod
    def headers_ok(cls, value: dict[str, str]) -> dict[str, str]:
        for name in value:
            validate_header_name(name)
            if _CRED_HEADER.search(name):
                raise ValueError(f"Header '{name}' looks like a credential. Put credentials in `auth` (stored as a secret), never in endpoint.headers.")
        return value


class PaginationConfig(BaseModel):
    model_config = STRICT
    type: str = "none"
    items_path: str | None = None
    next_path: str | None = None
    page_param: str = "page"
    start_param: str = "startAt"
    limit_param: str = "maxResults"
    cursor_param: str = "cursor"
    page_size: int = Field(default=100, ge=1, le=10000)
    max_pages: int = Field(default=100, ge=1, le=1000)

    @field_validator("type")
    @classmethod
    def supported_pagination(cls, value: str) -> str:
        allowed = {"none", "link_header", "page", "offset", "cursor"}
        if value not in allowed:
            raise ValueError(f"pagination.type must be one of: {', '.join(sorted(allowed))}")
        return value

    @model_validator(mode="after")
    def cursor_needs_next_path(self):
        if self.type == "cursor" and not self.next_path:
            raise ValueError("pagination.next_path is required for cursor pagination")
        return self


class FieldSpec(BaseModel):
    """Rich mapping: {path, value, default, convert: date|int|float|str|lower|upper, format}."""
    model_config = STRICT
    path: str | None = None
    value: Any = None
    default: Any = None
    convert: str | None = None
    format: str | None = None

    @model_validator(mode="after")
    def check(self):
        if self.convert and self.convert not in {"date", "int", "float", "str", "lower", "upper"}:
            raise ValueError("convert must be one of: date, int, float, str, lower, upper")
        if self.path is None and "value" not in self.model_fields_set:
            raise ValueError("a field mapping needs `path` or `value`")
        return self


class MappingConfig(BaseModel):
    model_config = STRICT
    entity: str = "event"
    fields: dict[str, str | FieldSpec] = Field(default_factory=dict)
    required: list[str] = Field(default_factory=list)

    @field_validator("fields")
    @classmethod
    def target_names(cls, value):
        for key in value:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key):
                raise ValueError(f"Invalid mapped field name: {key!r}")
        return value


class ConnectorConfig(BaseModel):
    model_config = STRICT
    name: str
    vendor: str | None = None
    product: str | None = None
    category: str | None = None
    base_url: str
    auth: AuthConfig = Field(default_factory=AuthConfig)
    endpoint: EndpointConfig
    pagination: PaginationConfig = Field(default_factory=PaginationConfig)
    schedule: str | None = None
    mapping: MappingConfig
    enabled: bool = True
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    min_interval_seconds: float = Field(default=0, ge=0, le=60)  # polite pause between pages

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
            raise ValueError("name may only contain letters, digits, '_' and '-' (max 64)")
        return value

    @field_validator("base_url")
    @classmethod
    def valid_base_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("base_url must be a credential-free https:// URL")
        return value.rstrip("/")

    @field_validator("schedule")
    @classmethod
    def valid_schedule(cls, value: str | None) -> str | None:
        parse_schedule(value)
        return value


def _short_errors(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors()[:8]:
        where = ".".join(str(x) for x in err["loc"]) or "config"
        parts.append(f"{where}: {err['msg']}")
    return "; ".join(parts)


def load_config_file(path: Path) -> ConnectorConfig:
    try:
        return validate_config_text(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Cannot read {path.name}") from exc


def load_connector(name: str) -> ConnectorConfig:
    # Prevent path traversal; connector ids are simple identifiers.
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise HTTPException(status_code=400, detail="Invalid connector name.")
    path = CONFIG_DIR / f"{name}.yaml"
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"Config not found: configs/{name}.yaml")
    try:
        return load_config_file(path)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid connector config: {exc}") from exc


def validate_config_text(config_text: str) -> ConnectorConfig:
    try:
        raw = load_safe_yaml(config_text)
        if not isinstance(raw, dict):
            raise ValueError("Config must be a YAML mapping (key: value pairs).")
        return ConnectorConfig.model_validate(normalize_config(raw))
    except ValidationError as exc:
        raise ValueError(_short_errors(exc)) from exc
    except yaml.YAMLError as exc:
        raise ValueError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Authentication - secrets are read from environment variables, never logged
# ---------------------------------------------------------------------------

def build_auth(config: AuthConfig) -> tuple[dict[str, str], httpx.Auth | None]:
    """Secrets come from the encrypted vault (or CONNECTOR_* env vars) and are never logged."""
    headers: dict[str, str] = {}
    if config.type == "none":
        return headers, None

    def need(name: str | None) -> str | None:
        return secret_store.get_secret(name) if name else None

    if config.type in {"api_key", "bearer"}:
        value = need(config.secret)
        if not value:
            if config.optional:
                return headers, None  # works unauthenticated (lower rate limits)
            raise ValueError(f"Missing secret {config.secret}. Add it on the Secrets tab (or export it as an environment variable).")
        if config.type == "bearer":
            headers[config.header or "Authorization"] = f"{config.prefix or 'Bearer'} {value}"
        else:
            headers[config.header or "X-API-Key"] = f"{config.prefix} {value}" if config.prefix else value
        return headers, None

    username, password = need(config.username_env), need(config.password_env)
    if not username or not password:
        if config.optional:
            return headers, None
        raise ValueError(f"Missing secret(s) {config.username_env} / {config.password_env}. Add them on the Secrets tab.")
    return headers, httpx.BasicAuth(username, password)


# ---------------------------------------------------------------------------
# HTTP reliability: retries, exponential backoff and Retry-After
# ---------------------------------------------------------------------------

def retry_after_seconds(value: str | None) -> float | None:
    """Parse Retry-After, always clamped to MAX_RETRY_AFTER so a hostile API cannot stall workers."""
    if not value:
        return None
    try:
        return clamp_retry_after(float(value))
    except ValueError:
        try:
            retry_date = parsedate_to_datetime(value)
            if retry_date.tzinfo is None:
                retry_date = retry_date.replace(tzinfo=timezone.utc)
            return clamp_retry_after((retry_date - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None


def request_with_retries(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    auth: httpx.Auth | None,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    max_retries: int = 3,
) -> httpx.Response:
    last_error: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            response = client.request(
                method,
                url,
                headers=headers,
                auth=auth,
                params=params,
                json=json_body,
            )

            if response.status_code == 429:
                if attempt >= max_retries:
                    response.raise_for_status()
                wait = retry_after_seconds(response.headers.get("Retry-After"))
                time.sleep(wait if wait is not None else 2 ** attempt)
                continue

            if 500 <= response.status_code <= 599:
                if attempt >= max_retries:
                    response.raise_for_status()
                time.sleep(2 ** attempt)
                continue

            response.raise_for_status()
            return response

        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            last_error = exc
            if attempt >= max_retries:
                raise
            time.sleep(2 ** attempt)

    if last_error:
        raise last_error
    raise RuntimeError("Request failed after retries.")


# ---------------------------------------------------------------------------
# Generic response parsing, pagination and field mapping
# ---------------------------------------------------------------------------

def get_nested_value(data: Any, path: str | None) -> Any:
    if not path:
        return data
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if index < len(current) else None
        else:
            return None
    return current


def extract_records(payload: Any, items_path: str | None) -> list[dict[str, Any]]:
    items = get_nested_value(payload, items_path)
    if items is None and isinstance(payload, list):
        items = payload
    if items is None and isinstance(payload, dict):
        # Convenient default for common API response shapes.
        for candidate in ("items", "values", "data", "results"):
            if isinstance(payload.get(candidate), list):
                items = payload[candidate]
                break
    if not isinstance(items, list):
        raise ValueError(
            "Could not find a list of records. Set pagination.items_path in the YAML config."
        )
    return [item for item in items if isinstance(item, dict)]


def map_record(
    record: dict[str, Any],
    mapping: MappingConfig,
    source: str,
) -> dict[str, Any]:
    mapped: dict[str, Any] = {}
    for target_field, spec in mapping.fields.items():
        if isinstance(spec, BaseModel):
            spec = {k: getattr(spec, k) for k in spec.model_fields_set}
        mapped[target_field] = resolve_field(record, spec, get_nested_value)

    mapped["source"] = source
    mapped["fetched_at"] = utc_now()

    # Ensure the common entity categories always have a stable minimum shape.
    defaults = {
        "user": ["id", "name", "email", "status", "last_login"],
        "device": ["id", "hostname", "ip", "os", "owner", "last_seen"],
        "event": ["id", "type", "severity", "timestamp", "description"],
        "alert": ["id", "type", "severity", "timestamp", "description"],
        "vulnerability": ["id", "type", "severity", "timestamp", "description"],
        "ticket": ["id", "type", "severity", "timestamp", "description"],
    }
    for field in defaults.get(mapping.entity.lower(), []):
        mapped.setdefault(field, None)

    missing = [field for field in mapping.required if mapped.get(field) in (None, "")]
    if missing:
        raise ValueError(f"Missing required mapped fields: {', '.join(missing)}")

    return mapped


def next_link_from_header(link_header: str | None) -> str | None:
    if not link_header:
        return None
    # Parse RFC-style Link header entries, selecting rel="next".
    for part in link_header.split(","):
        match = re.match(r'\s*<([^>]+)>\s*;\s*rel="?([^";]+)"?', part)
        if match and match.group(2) == "next":
            return match.group(1)
    return None


USER_AGENT = "SecurityIntegrationPlatform/0.4 (+read-only security intelligence)"


def fetch_all_records(config: ConnectorConfig, *, max_pages: int | None = None) -> list[dict[str, Any]]:
    headers, auth = build_auth(config.auth)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json", **config.endpoint.headers, **headers}
    validate_external_url(config.base_url)
    endpoint_url = safe_join(config.base_url, config.endpoint.path)  # rejects absolute URLs / traversal
    validate_external_url(endpoint_url)
    pagination = config.pagination
    pages = min(pagination.max_pages, max_pages) if max_pages else pagination.max_pages
    all_records: list[dict[str, Any]] = []
    params = dict(config.endpoint.params)

    with httpx.Client(timeout=float(config.timeout_seconds), follow_redirects=False) as client:
        next_url: str | None = endpoint_url

        for page_index in range(pages):
            if page_index and config.min_interval_seconds:
                time.sleep(config.min_interval_seconds)
            request_params = dict(params)

            if pagination.type == "page":
                request_params[pagination.page_param] = page_index + 1
                request_params.setdefault(pagination.limit_param, pagination.page_size)

            elif pagination.type == "offset":
                request_params[pagination.start_param] = page_index * pagination.page_size
                request_params.setdefault(pagination.limit_param, pagination.page_size)

            validate_external_url(next_url or endpoint_url)
            response = request_with_retries(
                client,
                config.endpoint.method.upper(),
                next_url or endpoint_url,
                headers=headers,
                auth=auth,
                params=request_params if pagination.type != "link_header" else (params if page_index == 0 else None),
            )

            if len(response.content) > MAX_RESPONSE_BYTES:
                raise ValueError("Vendor response exceeds the maximum allowed size.")
            try:
                payload = response.json()
            except ValueError as exc:
                raise ValueError("Vendor returned a non-JSON response.") from exc
            page_records = extract_records(payload, pagination.items_path)
            all_records.extend(page_records)

            if pagination.type == "none":
                break

            if pagination.type == "link_header":
                candidate = next_link_from_header(response.headers.get("Link"))
                if not candidate:
                    break
                # Origin-lock: credentials must never follow a server-supplied URL to another host.
                next_url = follow_next_url(endpoint_url, candidate)
                continue

            if pagination.type == "cursor":
                next_cursor = get_nested_value(payload, pagination.next_path)
                if not next_cursor:
                    break
                params[pagination.cursor_param] = next_cursor
                continue

            # Page-number and offset APIs commonly return a short final page.
            if len(page_records) < pagination.page_size:
                break

    return all_records


def describe_error(exc: Exception) -> str:
    """Human-readable, secret-free failure reason (FR-10 'last error')."""
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        hint = {401: "credentials rejected - check the token/secret", 403: "forbidden - token lacks permission, or you are being rate-limited",
                404: "endpoint not found - check base_url and path", 429: "rate limited - retries exhausted"}.get(
            code, "upstream server error - retries exhausted" if code >= 500 else "request rejected")
        return f"HTTP {code}: {hint}"
    if isinstance(exc, httpx.TimeoutException):
        return "Timed out waiting for the API (retries exhausted)"
    if isinstance(exc, httpx.TransportError):
        return "Network error: could not reach the API (retries exhausted)"
    return f"{type(exc).__name__}: {str(exc)[:300]}"


# ---------------------------------------------------------------------------
# Storage and sync execution
# ---------------------------------------------------------------------------

def save_record(source: str, entity_type: str, record: dict[str, Any]) -> None:
    external_id = record.get("id")
    with db_connection() as conn:
        conn.execute(
            """
            INSERT INTO records (source, entity_type, external_id, data_json, fetched_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(source, entity_type, external_id)
            DO UPDATE SET data_json=excluded.data_json, fetched_at=excluded.fetched_at
            """,
            (
                source,
                entity_type,
                str(external_id) if external_id is not None else None,
                json.dumps(record, default=str),
                record["fetched_at"],
            ),
        )
        save_typed(conn, source, entity_type, record)


def save_invalid_record(
    source: str,
    entity_type: str,
    record: dict[str, Any],
    reason: str,
) -> None:
    with db_connection() as conn:
        conn.execute(
            """
            INSERT INTO invalid_records (source, entity_type, record_json, reason, fetched_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (source, entity_type, json.dumps(record, default=str), reason, utc_now()),
        )


def update_run(
    run_id: int,
    status: str,
    *,
    records_fetched: int = 0,
    records_saved: int = 0,
    invalid_records: int = 0,
    error: str | None = None,
) -> None:
    with db_connection() as conn:
        conn.execute(
            """
            UPDATE runs
            SET status=?, finished_at=?, records_fetched=?, records_saved=?,
                invalid_records=?, error=?
            WHERE id=?
            """,
            (status, utc_now(), records_fetched, records_saved, invalid_records, error, run_id),
        )


def run_connector(config: ConnectorConfig) -> dict[str, Any]:
    if not config.enabled:
        raise RuntimeError("Connector is disabled (enabled: false in its config).")
    started_at = utc_now()
    with db_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO runs (source, status, started_at) VALUES (?, ?, ?)",
            (config.name, "running", started_at),
        )
        run_id = cursor.lastrowid

    try:
        raw_records = fetch_all_records(config)
        saved = 0
        invalid = 0

        for raw_record in raw_records:
            try:
                normalized = map_record(raw_record, config.mapping, config.name)
                save_record(config.name, config.mapping.entity, normalized)
                saved += 1
            except ValueError as exc:
                save_invalid_record(
                    config.name,
                    config.mapping.entity,
                    raw_record,
                    str(exc),
                )
                invalid += 1

        update_run(
            run_id,
            "healthy" if invalid == 0 else "completed_with_invalid_records",
            records_fetched=len(raw_records),
            records_saved=saved,
            invalid_records=invalid,
        )
        return {
            "connector": config.name,
            "status": "healthy" if invalid == 0 else "completed_with_invalid_records",
            "records_fetched": len(raw_records),
            "records_saved": saved,
            "invalid_records": invalid,
            "started_at": started_at,
            "finished_at": utc_now(),
        }

    except Exception as exc:
        # Do not log request headers or secrets. Return a concise error to the UI.
        safe_error = describe_error(exc)
        logger.error("Connector '%s' failed: %s", config.name, safe_error)
        update_run(run_id, "failed", error=safe_error)
        raise RuntimeError(safe_error) from exc


# ---------------------------------------------------------------------------
# Security middleware and auth dependencies
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}
MAX_BODY_BYTES = 300 * 1024


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    from fastapi.responses import JSONResponse
    if not api_limiter.allow(client_ip(request)):
        response = JSONResponse({"detail": "Too many requests."}, status_code=429, headers={"Retry-After": "60"})
    elif int(request.headers.get("content-length") or 0) > MAX_BODY_BYTES:
        response = JSONResponse({"detail": "Request body too large."}, status_code=413)
    else:
        response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers[k] = v
    if not request.url.path.startswith("/ui"):
        response.headers["Cache-Control"] = "no-store"
    return response


def current_session(request: Request) -> dict[str, Any]:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Authentication required.", headers={"WWW-Authenticate": "Bearer"})
    try:
        session = auth_manager.verify_session(token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid or expired session.", headers={"WWW-Authenticate": "Bearer"})
    session["_token"] = token
    return session


def require_role(minimum: str):
    def dependency(session: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
        rank = max((ROLE_RANK.get(r, 0) for r in session.get("roles", [])), default=0)
        if rank < ROLE_RANK[minimum]:
            raise HTTPException(status_code=403, detail="Insufficient permissions.")
        return session
    return dependency


NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def valid_name(value: str, label: str = "name") -> str:
    if not NAME_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}.")
    return value


# ---------------------------------------------------------------------------
# Response actions: definitions live server-side, never in the request
# ---------------------------------------------------------------------------

ACTIONS_DIR = CONFIG_DIR / "actions"


def load_action_definition(connector: str, action_name: str):
    from config_schema import ResponseActionConfig
    valid_name(connector, "connector"); valid_name(action_name, "action")
    path = ACTIONS_DIR / f"{connector}.yaml"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="No actions defined for this connector.")
    raw = load_safe_yaml(path.read_text(encoding="utf-8"))
    for item in raw.get("actions", []):
        if item.get("name") == action_name:
            return ResponseActionConfig.model_validate(item)
    raise HTTPException(status_code=404, detail="Unknown action.")


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

class ConfigValidationRequest(BaseModel):
    config: str = Field(max_length=262144)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ApprovalRequestBody(BaseModel):
    connector_name: str
    action_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class DecisionBody(BaseModel):
    decision: str


class PrepareActionBody(BaseModel):
    connector_name: str
    action_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = Field(default=None, max_length=64)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/ui/")


@app.get("/health")
def health() -> dict[str, str]:
    """Public liveness probe only. Connector detail requires authentication (/health/connectors)."""
    return {"status": "ok"}


@app.post("/auth/login")
def login(body: LoginRequest, request: Request) -> dict[str, Any]:
    ip = client_ip(request)
    if not ip_limiter.allow(ip) or not login_limiter.allow(f"{ip}|{body.username.lower()}"):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.", headers={"Retry-After": "60"})
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM platform_accounts WHERE username=?", (body.username,)).fetchone()
    # Always run one PBKDF2 verification so unknown users cannot be told apart by timing.
    ok = auth_manager.verify_password(body.password, row["password_hash"] if row else _DUMMY_HASH)
    if not row or not ok:
        logger.warning("Failed login for %r from %s", body.username[:64], ip)
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = auth_manager.issue_session(row["username"], [row["role"]], ttl_seconds=1800)
    return {"token": token, "username": row["username"], "role": row["role"], "expires_in": 1800}


@app.post("/auth/logout")
def logout(session: dict[str, Any] = Depends(current_session)) -> dict[str, bool]:
    auth_manager.revoke_session(session["_token"])
    return {"ok": True}


@app.get("/auth/me")
def me(session: dict[str, Any] = Depends(current_session)) -> dict[str, Any]:
    return {"username": session["sub"], "roles": session["roles"]}


# ---------------------------------------------------------------------------
# Scheduler (FR-4), single-flight syncs, failure alerts (B-4)
# ---------------------------------------------------------------------------

ALERT_AFTER_FAILURES = 3
fail_counts: dict[str, int] = {}
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


class SyncBusy(Exception):
    pass


def _lock_for(name: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(name, threading.Lock())


def send_alert(name: str, error: str) -> None:
    """Log loudly; also POST to a Slack-style webhook if the CONNECTOR_ALERT_WEBHOOK secret is set."""
    message = f"ALERT: connector '{name}' failed {ALERT_AFTER_FAILURES} times in a row. Last error: {error}"
    logger.error(message)
    try:
        url = secret_store.get_secret("CONNECTOR_ALERT_WEBHOOK")
        if url:
            validate_external_url(url)
            httpx.post(url, json={"text": message}, timeout=5.0, follow_redirects=False)
    except Exception as exc:  # alerting must never break a sync
        logger.warning("Alert webhook failed: %s", type(exc).__name__)


def guarded_sync(config: ConnectorConfig) -> dict[str, Any]:
    """One sync per connector at a time; tracks consecutive failures and alerts."""
    lock = _lock_for(config.name)
    if not lock.acquire(blocking=False):
        raise SyncBusy(config.name)
    try:
        result = run_connector(config)
        fail_counts[config.name] = 0
        return result
    except RuntimeError as exc:
        fail_counts[config.name] = fail_counts.get(config.name, 0) + 1
        if fail_counts[config.name] == ALERT_AFTER_FAILURES:
            send_alert(config.name, str(exc))
        raise
    finally:
        lock.release()


def list_configs() -> list[tuple[str, ConnectorConfig]]:
    out = []
    for path in sorted(CONFIG_DIR.glob("*.yaml")):
        try:
            out.append((path.stem, load_config_file(path)))
        except ValueError:
            continue
    return out


class Scheduler(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True, name="connector-scheduler")
        self.stop_event = threading.Event()
        self.next_due: dict[str, float] = {}  # connector id -> epoch seconds

    def run(self) -> None:
        while not self.stop_event.wait(5):
            try:
                self.tick()
            except Exception:
                logger.exception("Scheduler tick failed")

    def tick(self) -> None:
        now = time.time()
        seen = set()
        for cid, config in list_configs():
            interval = parse_schedule(config.schedule)
            if not config.enabled or not interval:
                continue
            seen.add(cid)
            due = self.next_due.setdefault(cid, now + 5)  # first run shortly after start-up
            if now >= due:
                self.next_due[cid] = now + interval
                try:
                    result = guarded_sync(config)
                    logger.info("Scheduled sync %s: saved=%s invalid=%s", cid, result["records_saved"], result["invalid_records"])
                except (RuntimeError, SyncBusy) as exc:
                    logger.warning("Scheduled sync %s did not complete: %s", cid, exc)
        for gone in set(self.next_due) - seen:
            del self.next_due[gone]


scheduler = Scheduler()


# ---------------------------------------------------------------------------
# Health, connector management
# ---------------------------------------------------------------------------

@app.get("/health/connectors")
def connector_health(_: dict = Depends(require_role("viewer"))) -> dict[str, Any]:
    with db_connection() as conn:
        rows = conn.execute(
            """
            SELECT r1.source, r1.status, r1.started_at, r1.finished_at,
                   r1.records_fetched, r1.records_saved, r1.invalid_records, r1.error
            FROM runs r1
            INNER JOIN (
                SELECT source, MAX(id) AS latest_id FROM runs GROUP BY source
            ) latest ON latest.latest_id = r1.id
            ORDER BY r1.source
            """
        ).fetchall()
        out = []
        for row in rows:
            recent = conn.execute("SELECT status FROM runs WHERE source=? ORDER BY id DESC LIMIT 10", (row["source"],)).fetchall()
            streak = 0
            for r in recent:
                if r["status"] != "failed":
                    break
                streak += 1
            out.append({**dict(row), "consecutive_failures": streak})
    return {"status": "ok", "connectors": out}


@app.get("/connectors")
def list_connectors(_: dict = Depends(require_role("viewer"))) -> dict[str, Any]:
    CONFIG_DIR.mkdir(exist_ok=True)
    connectors = []
    for path in sorted(CONFIG_DIR.glob("*.yaml")):
        try:
            config = load_config_file(path)
            names = [n for n in (config.auth.secret, config.auth.username_env, config.auth.password_env) if n]
            nxt = scheduler.next_due.get(path.stem)
            connectors.append({
                "id": path.stem, "name": config.name, "valid": True, "enabled": config.enabled,
                "entity": config.mapping.entity, "auth_type": config.auth.type,
                "pagination": config.pagination.type, "schedule": config.schedule,
                "next_run": datetime.fromtimestamp(nxt, timezone.utc).isoformat() if nxt else None,
                "secrets": [{"name": n, "set": secret_store.is_set(n), "optional": config.auth.optional} for n in names],
            })
        except ValueError as exc:
            logger.warning("Config %s failed validation: %s", path.name, str(exc)[:300])
            connectors.append({"id": path.stem, "name": path.stem, "valid": False, "error": str(exc)[:400]})
    return {"connectors": connectors}


@app.get("/connectors/{connector_id}/yaml")
def connector_yaml(connector_id: str, _: dict = Depends(require_role("analyst"))) -> dict[str, str]:
    valid_name(connector_id, "connector")
    path = CONFIG_DIR / f"{connector_id}.yaml"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Config not found.")
    return {"yaml": path.read_text(encoding="utf-8")}


class SaveConnectorBody(BaseModel):
    config: str | None = Field(default=None, max_length=262144)  # YAML text...
    spec: dict[str, Any] | None = None                            # ...or the form's JSON object
    overwrite: bool = False
    validate_only: bool = False


@app.post("/connectors")
def save_connector(body: SaveConnectorBody, session: dict = Depends(require_role("admin"))) -> dict[str, Any]:
    """Add or replace a connector by supplying only configuration (YAML text or a JSON spec)."""
    if (body.config is None) == (body.spec is None):
        raise HTTPException(status_code=400, detail="Provide exactly one of `config` (YAML) or `spec` (object).")
    text = body.config if body.config is not None else yaml.safe_dump(body.spec, sort_keys=False)
    try:
        config = validate_config_text(text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)[:1500]) from exc
    if body.validate_only:
        return {"valid": True, "name": config.name, "yaml": text}
    path = CONFIG_DIR / f"{config.name}.yaml"
    if path.exists() and not body.overwrite:
        raise HTTPException(status_code=409, detail=f"Connector '{config.name}' already exists. Enable overwrite to replace it.")
    CONFIG_DIR.mkdir(exist_ok=True)
    tmp = path.with_suffix(".yaml.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    logger.info("Connector '%s' saved by %s", config.name, session["sub"])
    return {"saved": True, "id": config.name}


@app.delete("/connectors/{connector_id}")
def delete_connector(connector_id: str, session: dict = Depends(require_role("admin"))) -> dict[str, bool]:
    valid_name(connector_id, "connector")
    path = CONFIG_DIR / f"{connector_id}.yaml"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Config not found.")
    path.unlink()
    logger.info("Connector '%s' deleted by %s", connector_id, session["sub"])
    return {"deleted": True}


@app.post("/connectors/{connector_id}/test")
def test_connector(connector_id: str, session: dict = Depends(require_role("analyst"))) -> dict[str, Any]:
    """B-3: fetch ONE page and preview the mapping. Nothing is stored."""
    config = load_connector(connector_id)
    if not sync_limiter.allow(session["sub"]):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.", headers={"Retry-After": "60"})
    started = time.time()
    try:
        raw = fetch_all_records(config, max_pages=1)
    except Exception as exc:
        return {"ok": False, "error": describe_error(exc)}
    sample, bad, reasons = [], 0, []
    for record in raw[:100]:
        try:
            mapped = map_record(record, config.mapping, config.name)
            if len(sample) < 3:
                sample.append(mapped)
        except ValueError as exc:
            bad += 1
            if len(reasons) < 3:
                reasons.append(str(exc))
    return {"ok": True, "records_on_first_page": len(raw), "invalid_in_sample": bad, "invalid_reasons": reasons,
            "sample": sample, "elapsed_ms": int((time.time() - started) * 1000)}


# --- Secrets (encrypted vault; values are write-only) -----------------------

class SecretBody(BaseModel):
    value: str = Field(min_length=1, max_length=4096)


@app.get("/secrets")
def list_secrets(_: dict = Depends(require_role("admin"))) -> dict[str, Any]:
    return {"secrets": secret_store.list_names()}


@app.put("/secrets/{name}")
def put_secret(name: str, body: SecretBody, session: dict = Depends(require_role("admin"))) -> dict[str, bool]:
    try:
        secret_store.set_secret(name, body.value.strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("Secret %s set by %s", name, session["sub"])  # never log the value
    return {"ok": True}


@app.delete("/secrets/{name}")
def remove_secret(name: str, session: dict = Depends(require_role("admin"))) -> dict[str, bool]:
    try:
        secret_store.delete_secret(name)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=404, detail="Secret not found.") from exc
    logger.info("Secret %s deleted by %s", name, session["sub"])
    return {"ok": True}


@app.get("/tables/{table}")
def read_table(table: str, source: str | None = None, limit: int = Query(default=100, ge=1, le=1000),
               _: dict = Depends(require_role("viewer"))) -> dict[str, Any]:
    """FR-11: the common-schema tables (users, devices, events)."""
    if table not in TYPED_TABLES:
        raise HTTPException(status_code=404, detail="Unknown table.")
    sql, values = f"SELECT * FROM {table}", []  # table is whitelisted above
    if source:
        sql += " WHERE source=?"
        values.append(valid_name(source, "source"))
    with db_connection() as conn:
        rows = conn.execute(sql + " ORDER BY fetched_at DESC LIMIT ?", values + [limit]).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    return {"table": table, "total": total, "rows": [dict(r) for r in rows]}


@app.post("/config/validate")
def validate_config(request: ConfigValidationRequest, _: dict = Depends(require_role("analyst"))) -> dict[str, Any]:
    try:
        config = validate_config_text(request.config)
        return {
            "valid": True,
            "name": config.name,
            "auth_type": config.auth.type,
            "pagination_type": config.pagination.type,
            "entity": config.mapping.entity,
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)[:1000]) from exc


@app.post("/sync/{connector_name}")
def sync_connector(connector_name: str, session: dict = Depends(require_role("analyst"))) -> dict[str, Any]:
    if not sync_limiter.allow(session["sub"]):
        raise HTTPException(status_code=429, detail="Sync rate limit exceeded.", headers={"Retry-After": "60"})
    config = load_connector(connector_name)
    if not config.enabled:
        raise HTTPException(status_code=409, detail="Connector is disabled (enabled: false).")
    try:
        return guarded_sync(config)
    except SyncBusy as exc:
        raise HTTPException(status_code=409, detail="A sync for this connector is already running.") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


class OSVPackageQuery(BaseModel):
    model_config = STRICT
    package_name: str = Field(min_length=1, max_length=256)
    ecosystem: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=128)


@app.post("/osv/query")
def query_osv_package(
    query: OSVPackageQuery,
    session: dict = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Query OSV.dev for vulnerabilities affecting one package version."""
    url = "https://api.osv.dev/v1/query"
    validate_external_url(url)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        with httpx.Client(timeout=30.0, follow_redirects=False) as client:
            response = request_with_retries(
                client, "POST", url, headers=headers, auth=None,
                json_body={
                    "package": {"name": query.package_name, "ecosystem": query.ecosystem},
                    "version": query.version,
                },
            )
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=describe_error(exc)) from exc

    vulnerabilities = payload.get("vulns", []) if isinstance(payload, dict) else []
    saved = 0
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict) or not vuln.get("id"):
            continue
        severities = []
        for affected in vuln.get("affected", []):
            severity = (affected.get("ecosystem_specific") or {}).get("severity")
            if severity:
                severities.append(str(severity).upper())
        record = {
            "id": vuln["id"],
            "type": "open_source_advisory",
            "severity": severities[0] if severities else None,
            "timestamp": vuln.get("modified") or vuln.get("published"),
            "description": vuln.get("summary") or vuln.get("details") or "OSV vulnerability advisory",
            "package": query.package_name,
            "ecosystem": query.ecosystem,
            "version_checked": query.version,
            "aliases": vuln.get("aliases", []),
            "references": vuln.get("references", []),
            "source": "osv",
            "fetched_at": utc_now(),
        }
        save_record("osv", "vulnerability", record)
        saved += 1
    return {"connector": "osv", "package": query.package_name, "ecosystem": query.ecosystem,
            "version": query.version, "vulnerabilities_found": len(vulnerabilities),
            "records_saved": saved, "status": "healthy"}


@app.get("/records/{entity_type}")
def get_records(
    entity_type: str,
    source: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    _: dict = Depends(require_role("viewer")),
) -> dict[str, Any]:
    valid_name(entity_type, "entity type")
    query = "SELECT source, entity_type, data_json, fetched_at FROM records WHERE entity_type=?"
    values: list[Any] = [entity_type]
    if source:
        query += " AND source=?"
        values.append(valid_name(source, "source"))
    query += " ORDER BY id DESC LIMIT ?"
    values.append(limit)

    with db_connection() as conn:
        rows = conn.execute(query, values).fetchall()

    return {
        "count": len(rows),
        "records": [
            {
                "source": row["source"],
                "entity_type": row["entity_type"],
                "fetched_at": row["fetched_at"],
                "data": json.loads(row["data_json"]),
            }
            for row in rows
        ],
    }


@app.get("/runs")
def list_runs(limit: int = Query(default=50, ge=1, le=500), _: dict = Depends(require_role("viewer"))) -> dict[str, Any]:
    with db_connection() as conn:
        rows = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"runs": [dict(row) for row in rows]}


@app.get("/invalid-records")
def list_invalid_records(limit: int = Query(default=100, ge=1, le=1000), _: dict = Depends(require_role("analyst"))) -> dict[str, Any]:
    with db_connection() as conn:
        rows = conn.execute("SELECT * FROM invalid_records ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"invalid_records": [{**dict(row), "record": json.loads(row["record_json"])} for row in rows]}


# --- Response actions + approvals (dry-run only) ---------------------------

@app.get("/actions/{connector_name}")
def list_actions(connector_name: str, _: dict = Depends(require_role("viewer"))) -> dict[str, Any]:
    valid_name(connector_name, "connector")
    path = ACTIONS_DIR / f"{connector_name}.yaml"
    if not path.is_file():
        return {"actions": []}
    raw = load_safe_yaml(path.read_text(encoding="utf-8"))
    return {"actions": [{k: a.get(k) for k in ("name", "description", "method", "risk_level", "enabled")} for a in raw.get("actions", [])]}


@app.post("/approvals")
def create_approval(body: ApprovalRequestBody, session: dict = Depends(require_role("analyst"))) -> dict[str, Any]:
    import approval_manager
    load_action_definition(body.connector_name, body.action_name)  # must exist server-side
    return approval_manager.request_approval(body.connector_name, body.action_name, session["sub"], body.parameters)


@app.get("/approvals")
def list_approvals(_: dict = Depends(require_role("viewer"))) -> dict[str, Any]:
    import approval_manager
    return {"approvals": approval_manager.get_approval_requests(50)}


@app.post("/approvals/{approval_id}/decision")
def decide(approval_id: str, body: DecisionBody, session: dict = Depends(require_role("admin"))) -> dict[str, Any]:
    import approval_manager
    try:
        return approval_manager.decide_approval(approval_id, session["sub"], body.decision)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/actions/prepare")
def prepare(body: PrepareActionBody, session: dict = Depends(require_role("analyst"))) -> dict[str, Any]:
    import response_action_engine as rae
    from config_schema import ActionExecutionConfig
    action = load_action_definition(body.connector_name, body.action_name)  # server-side risk/approval policy
    execution = ActionExecutionConfig(
        connector_name=body.connector_name, action=action, dry_run=True,
        requested_by=session["sub"],  # identity comes from the session, never from the request body
        approval_id=body.approval_id,
    )
    return rae.prepare_action(execution, body.parameters)


@app.get("/actions-audit")
def audit(_: dict = Depends(require_role("admin"))) -> dict[str, Any]:
    import response_action_engine as rae
    return {"audit": rae.get_recent_action_audit(100)}


# Static single-page UI (same origin => no CORS needed, strict CSP applies)
_UI_DIR = BASE_DIR / "static"
if _UI_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=_UI_DIR, html=True), name="ui")
