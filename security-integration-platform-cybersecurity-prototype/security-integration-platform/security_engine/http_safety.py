"""Stdlib-only guards for connector HTTP behaviour (URL joining, pagination, retries, headers, secrets)."""
import math, re
from urllib.parse import urlsplit, urljoin

MAX_RETRY_AFTER = 60.0
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
_FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "cookie", "set-cookie", "proxy-authorization", "te", "upgrade", "x-forwarded-for", "x-forwarded-host"}
_SECRET_ENV = re.compile(r"CONNECTOR_[A-Z0-9_]{1,64}")
_HEADER = re.compile(r"[A-Za-z0-9-]{1,64}")

def _origin(url: str):
    p = urlsplit(url); port = p.port or {"https": 443, "http": 80}.get(p.scheme)
    return (p.scheme.lower(), (p.hostname or "").lower(), port)

def same_origin(a: str, b: str) -> bool:
    try: return _origin(a) == _origin(b)
    except ValueError: return False

def safe_join(base_url: str, path: str) -> str:
    """Join a relative endpoint path onto base_url; the result must stay on base_url's origin and path prefix."""
    if not isinstance(path, str) or not path: raise ValueError("Endpoint path is required.")
    if "\\" in path or any(ord(c) < 32 or ord(c) == 127 for c in path): raise ValueError("Illegal characters in endpoint path.")
    if "://" in path or path.startswith("//") or ":" in path.split("/")[0]: raise ValueError("Endpoint path must be relative, not an absolute URL.")
    if ".." in path.replace("\\", "/").split("?")[0].split("/"): raise ValueError("Path traversal is not allowed in endpoint path.")
    base = base_url.rstrip("/")
    url = urljoin(base + "/", path.lstrip("/"))
    if not same_origin(base, url) or not urlsplit(url).path.startswith(urlsplit(base).path.rstrip("/") + "/") and urlsplit(base).path not in ("", "/"):
        raise ValueError("Endpoint escapes the configured base_url.")
    return url

def follow_next_url(current_url: str, candidate: str) -> str:
    """Resolve a server-supplied pagination URL; refuse anything off the original origin."""
    nxt = urljoin(current_url, candidate)
    if not same_origin(current_url, nxt): raise ValueError("Pagination link points to a different origin.")
    return nxt

def clamp_retry_after(seconds, cap: float = MAX_RETRY_AFTER):
    if seconds is None: return None
    try: s = float(seconds)
    except (TypeError, ValueError): return None
    if math.isnan(s) or math.isinf(s): return cap
    return min(max(0.0, s), cap)

def safe_path_param(value) -> str:
    v = str(value)
    if not v or len(v) > 256 or v in (".", "..") or any(ord(c) < 32 or ord(c) == 127 for c in v) or "/" in v or "\\" in v:
        raise ValueError("Illegal path parameter value.")
    return v

def validate_header_name(name: str) -> str:
    if not _HEADER.fullmatch(name or "") or name.lower() in _FORBIDDEN_HEADERS: raise ValueError(f"Header name not allowed: {name!r}")
    return name

def validate_secret_env(name: str) -> str:
    """Connectors may only read env vars prefixed CONNECTOR_, so YAML can't exfiltrate platform keys."""
    if not name or not _SECRET_ENV.fullmatch(name): raise ValueError("Secret env var names must match CONNECTOR_[A-Z0-9_]+.")
    return name
