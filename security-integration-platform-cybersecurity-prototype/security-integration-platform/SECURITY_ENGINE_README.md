# Central Security Layer

This package adds seven reusable security-control areas to the existing local integration prototype. It is intentionally additive: the original connector/config API remains, while the app now uses bounded duplicate-key-rejecting safe YAML parsing, validates connector destinations before requests, disables automatic redirects, validates pagination URLs before each request, and applies restrictive SQLite file permissions where supported.

## Modules

- `security_engine.secrets.SecretVault`: Fernet-encrypted local vault. Install `cryptography`; keep `SECURITY_VAULT_KEY` outside source control (prefer OS credential storage). Losing the key means secrets cannot be recovered.
- `security_engine.auth.AuthManager`: PBKDF2-SHA256 password hashes, HMAC-signed expiring sessions, and role checks. Store users/roles securely and add login throttling/CSRF protection when wiring routes.
- `security_engine.yaml_guard.load_safe_yaml`: SafeLoader, duplicate-key rejection, size limit, mapping-root requirement.
- `security_engine.network.validate_external_url`: HTTPS-only by default, DNS/IP checks blocking non-public destinations. The app disables redirects and validates every request URL. For high assurance against DNS rebinding, enforce egress policy or pin validated DNS at the actual connection layer.
- `security_engine.database`: parameterized tenant-query helper and SQLite file permissions. SQLite is not transparently encrypted by this module; use encrypted disk/SQLCipher and backups for at-rest encryption. Existing app endpoints still need authentication and tenant identity wiring before multi-user exposure.
- `security_engine.api`: in-process rate limiter and timestamped HMAC webhook verification with nonce replay guard. Use Redis/shared storage for multi-process deployments.
- `security_engine.execution.run_restricted`: no-shell subprocess execution, timeout and allowlisted environment. It is not a full OS sandbox; use containers/OS isolation for untrusted code.

## Install and test

```bash
python -m pip install -r requirements.txt
python -m pytest -q
```

## Create a vault key (run once; store it securely)

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set `SECURITY_VAULT_KEY` in your local environment; never put it in YAML, Git, or this ZIP. Example:

```python
import os
from security_engine import SecretVault
vault = SecretVault('private/secrets.vault', os.environ['SECURITY_VAULT_KEY'])
vault.set('github_token', 'replace-with-real-token')
token = vault.get('github_token')
```

## Important rollout notes

- The existing prototype's routes are not automatically forced behind login in this delivery, to avoid locking out the current local workflow. Before network exposure, wire `AuthManager` into FastAPI dependencies and protect every non-health route; use role checks per operation.
- The helper modules are building blocks, not a claim that all 18 attack classes are fully eliminated. Apply tenant scoping to every data access, move rate limiting to shared middleware/store, configure webhook endpoints to call `verify_webhook`, and use OS/container isolation for workers.
- Do not distribute your real database, backup, `.env`, vault, or master key. This ZIP excludes local databases, virtual environments, caches and backups.

## Running (v0.2)
```
pip install -r requirements.txt
export PLATFORM_SIGNING_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
export PLATFORM_ADMIN_PASSWORD='choose-a-long-password'   # else a one-time password is printed at first start
export CONNECTOR_GITHUB_TOKEN=...                          # connector secrets must be CONNECTOR_*
uvicorn app:app            # UI at http://127.0.0.1:8000/ui/
```
Roles: viewer (read) < analyst (sync, request approvals, dry-run) < admin (decide approvals, audit).


## Running the prototype (v0.3)

```bash
pip install -r requirements.txt
export PLATFORM_ADMIN_PASSWORD='choose-a-long-password'   # first start only; otherwise a one-time password is printed
uvicorn app:app --port 8000                               # open http://127.0.0.1:8000/ui/
```

* **Security intelligence sources in the current prototype:** `cisa_kev` (public KEV feed), `nvd` (public CVE API; optional API key), `epss` (public FIRST EPSS feed), plus the OSV.dev package/version lookup exposed by `POST /osv/query`. GitHub and Jira are not included in this security-focused build.
* **Secrets:** add them on the **Secrets** tab (encrypted vault in `~/.security_platform`, no restart needed) or export `CONNECTOR_*` env vars.
* **Add any source:** drop a YAML into `configs/`, or use **Add / edit connector** (paste/upload YAML or the web form). Both config dialects are accepted.
* **Common schema tables (FR-11):** `users`, `devices`, `events`. Login accounts now live in `platform_accounts` (older databases are migrated automatically).
* The scheduler runs enabled connectors on their `schedule`; set `PLATFORM_SCHEDULER=0` to disable. Samples that are not connectors live in `samples/`.
