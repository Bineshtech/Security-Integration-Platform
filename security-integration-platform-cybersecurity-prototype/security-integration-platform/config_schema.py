
from typing import Any, Literal
from pydantic import BaseModel, Field, ConfigDict, model_validator, field_validator
from security_engine.http_safety import validate_secret_env, validate_header_name


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["none", "api_key", "bearer", "basic"] = "none"
    secret_env: str | None = None
    username_env: str | None = None
    password_env: str | None = None
    header_name: str = "Authorization"
    prefix: str = "Bearer"

    @field_validator("secret_env", "username_env", "password_env")
    @classmethod
    def _env_allowlist(cls, v):
        return validate_secret_env(v) if v else v

    @field_validator("header_name")
    @classmethod
    def _header_ok(cls, v):
        return validate_header_name(v)


class EndpointConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    params: dict[str, Any] = Field(default_factory=dict)
    body: dict[str, Any] | None = None

    @field_validator("headers")
    @classmethod
    def _headers_ok(cls, v):
        for k in v: validate_header_name(k)
        return v


class PaginationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    strategy: Literal[
        "none", "page", "offset", "cursor", "link_header"
    ] = "none"

    items_path: str | None = None
    next_path: str | None = None
    page_param: str = "page"
    offset_param: str = "offset"
    limit_param: str = "limit"
    cursor_param: str = "cursor"
    page_size: int = Field(default=100, ge=1, le=10000)
    max_pages: int = Field(default=10, ge=1, le=1000)


class MappingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity: str
    fields: dict[str, str] = Field(default_factory=dict)
    required: list[str] = Field(default_factory=list)


class ConnectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    vendor: str | None = None
    product: str | None = None
    category: str | None = None

    base_url: str
    auth: AuthConfig = Field(default_factory=AuthConfig)
    endpoint: EndpointConfig
    pagination: PaginationConfig = Field(
        default_factory=PaginationConfig
    )
    mapping: MappingConfig

    enabled: bool = True
    timeout_seconds: int = Field(default=30, ge=1, le=300)

    @model_validator(mode="after")
    def validate_auth_settings(self):
        if self.auth.type in ("api_key", "bearer"):
            if not self.auth.secret_env:
                raise ValueError(
                    "secret_env is required for API key or bearer authentication"
                )

        if self.auth.type == "basic":
            if not self.auth.username_env or not self.auth.password_env:
                raise ValueError(
                    "username_env and password_env are required for basic authentication"
                )

        return self

      
class ResponseActionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str

    method: Literal["POST", "PUT", "PATCH", "DELETE"]

    path: str

    risk_level: Literal[
        "low",
        "medium",
        "high",
        "critical"
    ] = "high"

    requires_approval: bool = True

    parameters: dict[str, Any] = Field(
        default_factory=dict
    )

    enabled: bool = False


class ActionExecutionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connector_name: str

    action: ResponseActionConfig

    dry_run: bool = True

    requested_by: str

    approval_id: str | None = None

