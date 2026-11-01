# Security Test Report (updated 2026-10-31)

## Flaws found in the original engine and fixed

| # | Flaw | Fix |
|---|------|-----|
| 1 | `endpoint.path` could be an absolute URL and override `base_url` (credentials sent to attacker host) | `safe_join()` rejects absolute/`//`/traversal paths and verifies same origin (app.py and connector_engine.py) |
| 2 | Link-header pagination followed any URL, with credentials attached | `follow_next_url()` origin-lock |
| 3 | `Retry-After` unbounded (`inf`, 999999999 s) → worker stall | clamped to 60 s, NaN/inf handled |
| 4 | Response actions: any `approval_id` string accepted; caller could set `requires_approval=false`; requester could approve own request; `..` accepted as path parameter | approval now verified (exists, approved by *another* user, unexpired, single-use, bound to connector+action+params); non-low-risk actions always need approval; action definitions live server-side in `configs/actions/`; requester identity comes from the session; `safe_path_param()` |
| 5 | Tenant helper accepted `!=`, `OR`, comments, `UNION`, stacked statements | exactly one `tenant_id = :tenant_id`, named params only, forbidden constructs rejected |
| 6 | SSRF via NAT64 `64:ff9b::/96` (also hardened 6to4/Teredo/mapped) | embedded IPv4 extracted and checked |
| 7 | Roles-as-string substring privilege match | roles must be a list of strings |
| 8 | YAML alias/anchor amplification | aliases rejected, depth ≤ 20, nodes ≤ 20 000 |
| 9 | Generated connectors all shared one secret env var; YAML could name *any* env var (e.g. the signing key) and send it to a vendor | env names must match `CONNECTOR_[A-Z0-9_]+`; header names validated |
| 10 | Rate limiter kept every key forever (memory DoS) | bounded, purges expired keys, fails closed |
| 11 | Webhook replay accepted when guard omitted | guard is mandatory |
| 12 | `/records`, `/sync`, `/runs`, `/invalid-records`, `/connectors` unauthenticated | signed-session login, roles viewer < analyst < admin on every route; only `/health` (liveness) is public |
| 13 | No security headers | CSP (`script-src 'self'`), nosniff, frame deny, HSTS, no-store, etc.; Swagger off by default |
| + | http:// base URLs allowed; no body/response size limits; login brute force | https only; 300 KB request cap, 10 MB vendor-response cap; per-IP and per-user login throttling, constant-time unknown-user check; session revocation on logout |

## Verification actually performed
- `python -m unittest discover -s tests -p test_hardening.py` → **15 passed** (SSRF, safe_join, pagination lock, Retry-After, path params, secret/header allowlists, YAML bombs, tenant scoping, rate limiter, webhook, roles, revocation, full approval lifecycle against real SQLite).
- All Python files compile; `static/app.js` passes `node --check`.

## NOT verified in this environment (run these yourself)
- `tests/test_api.py` (FastAPI TestClient end-to-end) — written but **not executed**: FastAPI/pydantic could not be installed (no network). Run `pip install -r requirements.txt && pytest -q`.
- The UI has not been opened in a browser; no live vendor sync was run.

## Remaining deployment work
- Serve behind TLS; set `PLATFORM_SIGNING_KEY`, `PLATFORM_ADMIN_PASSWORD`, `CONNECTOR_*` secrets.
- Rate limits/revocation list are in-memory (single process) → use Redis for multi-worker.
- DNS-rebinding: preflight check only; add egress firewall or IP pinning.
- Records are not tenant-partitioned in the schema yet; DB not encrypted at rest.


## Repackaged real-integration build (2026-10-31)

- Removed placeholder `example.com` security connectors and the JSONPlaceholder demo connector from production `configs/`.
- Jira now uses Jira Cloud's `nextPageToken` cursor pagination on `/rest/api/3/search/jql`; it remains disabled until a real tenant URL and credentials are supplied.
- CISA KEV mapping no longer mislabels the feed's exploited status as a severity score.
- Updated the approval-flow API test to use an isolated test fixture, not a fake production connector.
- Verification after these changes: `pytest -q` -> **36 passed**.
- All production YAML connectors are still configured to use live external APIs. This environment did not execute authenticated vendor syncs; those require the user's network and (for Jira) real tenant credentials. Passing tests do not claim live API connectivity.
