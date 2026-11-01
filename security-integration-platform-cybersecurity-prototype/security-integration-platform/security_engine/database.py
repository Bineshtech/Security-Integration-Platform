"""SQLite safety helpers: strictly tenant-scoped queries and restrictive local file permissions."""
import re, sqlite3
from pathlib import Path

_PREDICATE = re.compile(r"\btenant_id\s*=\s*:tenant_id\b", re.I)
_ANY_TENANT_REF = re.compile(r"(?<![:\w])tenant_id\b", re.I)
_FORBIDDEN = re.compile(r"(--|/\*|\*/|;|\bor\b|\bunion\b|\battach\b|\bpragma\b|\(\s*select\b)", re.I)

def execute_tenant_query(conn: sqlite3.Connection, sql: str, params: dict | None, tenant_id: str):
    """Run one SELECT/UPDATE/DELETE that contains exactly `tenant_id = :tenant_id` as an AND-ed predicate.

    Named parameters only. OR, UNION, comments, stacked statements, subqueries and any other use of
    tenant_id (e.g. `!=`, `<>`, LIKE, IN) are rejected, so the scope cannot be widened.
    """
    if not tenant_id or not isinstance(tenant_id, str): raise ValueError("tenant_id is required.")
    params = dict(params or {})
    if not isinstance(sql, str) or not re.match(r"\s*(select|update|delete)\b", sql, re.I): raise ValueError("Only SELECT/UPDATE/DELETE are allowed.")
    if _FORBIDDEN.search(sql): raise ValueError("Query contains a forbidden construct.")
    if len(_PREDICATE.findall(sql)) != 1 or len(_ANY_TENANT_REF.findall(sql)) != 1 or sql.count(":tenant_id") != 1:
        raise ValueError("Query must contain exactly one `tenant_id = :tenant_id` predicate.")
    if "tenant_id" in params: raise ValueError("tenant_id cannot be supplied in params.")
    params["tenant_id"] = tenant_id
    return conn.execute(sql, params)

def secure_sqlite_file(path: str | Path) -> None:
    p = Path(path)
    if p.exists():
        try: p.chmod(0o600)
        except OSError: pass
