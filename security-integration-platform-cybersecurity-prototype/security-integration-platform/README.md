# Security Integration Platform — Cybersecurity Prototype

A local, read-only security intelligence aggregation prototype. It stores normalized findings in SQLite and exposes a web dashboard/API.

## Included public sources

- **CISA KEV** — known exploited vulnerabilities; no API key.
- **NVD** — CVE records; no key required, but a free NVD API key improves rate limits.
- **FIRST EPSS** — daily exploitation-probability scores; no API key.
- **OSV.dev** — package-version vulnerability lookups; no API key. Query it through `POST /osv/query` after logging in as an analyst/admin.

GitHub and Jira connectors have been removed. No GitLab connector is included because repository metadata is not cybersecurity intelligence.

## Requirements

Python 3.11 or 3.12 recommended. macOS/Linux supported.

## Quick start (macOS)

```bash
cd "security-integration platform"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
export PLATFORM_SCHEDULER=0
export PLATFORM_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export PLATFORM_ADMIN_USER=admin
export PLATFORM_ADMIN_PASSWORD='change-this-to-a-long-unique-password'
uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/ui/ and sign in with the admin credentials you set above. Keep the terminal open while using the app. `PLATFORM_SCHEDULER=0` disables background polling; use the dashboard Sync controls to fetch data on demand. Set it to `1` (or remove it) to enable scheduled syncs.

## OSV package lookup

Use the authenticated API `POST /osv/query` with JSON:

```json
{"package_name":"fastapi","ecosystem":"PyPI","version":"0.115.0"}
```

The API saves returned advisories into the same vulnerability records table. Available ecosystems include PyPI, npm, Go, Maven, NuGet, RubyGems, crates.io and others supported by OSV.

## API endpoints

- `GET /health` — liveness
- `GET /connectors` — configured connectors (authenticated)
- `POST /sync/{connector_name}` — manually sync a source (analyst/admin)
- `POST /osv/query` — query OSV for a package version (analyst/admin)
- `GET /records/vulnerability` — stored vulnerability records (viewer+)

## Security notes

This prototype is intended for local evaluation. Bind to `127.0.0.1`; do not expose it directly to the public internet. Use a unique admin password and signing key. NVD rate limits apply; add a free NVD API key in the Secrets tab if you need higher throughput. Data is advisory intelligence, not proof that a system is vulnerable; validate findings against your own software inventory.
