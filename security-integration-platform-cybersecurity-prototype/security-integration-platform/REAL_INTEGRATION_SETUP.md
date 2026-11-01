# Real Security Data Integrations

This build is intentionally focused on cybersecurity intelligence. It ships three scheduled, public read-only feed connectors and one on-demand package lookup:

| Source | Purpose | Credentials |
|---|---|---|
| CISA KEV | Known exploited vulnerabilities | None |
| NVD | CVE records and CVSS metadata | Optional free NVD API key for higher rate limits |
| FIRST EPSS | Exploitation probability and percentile by CVE | None |
| OSV.dev | Vulnerabilities affecting a specific package/version | None |

## Configure NVD (optional)

Create a free NVD API key from the NVD website, then add it in the app's **Secrets** tab with the name `CONNECTOR_NVD_API_KEY`. The NVD connector works without it, but anonymous requests are more tightly rate-limited. The connector's `auth.optional: true` setting intentionally permits unauthenticated access.

## Run feeds

Use **Sync now** on the Dashboard for `cisa_kev`, `nvd`, and `epss`. They can also be run by an enabled scheduler. All are read-only GET requests.

## Query open-source package vulnerabilities

Open **Package vulnerability lookup** while signed in as an analyst or admin. Enter the exact package name, ecosystem and version. The app calls OSV.dev's `POST /v1/query` endpoint and stores any returned advisories as vulnerability records.

The OSV API is a package/version query API, not a complete bulk vulnerability feed. Use this lookup against your software inventory or SBOM package list for meaningful coverage.

## Important limitations

- These sources provide vulnerability intelligence, not proof that a specific host or application is exploitable.
- NVD may rate-limit anonymous requests. A free API key is recommended for regular use.
- EPSS is a probability score for CVEs; it is not a verdict that exploitation has occurred.
- OSV results depend on the ecosystem and exact package/version supplied.
- Keep the service bound to localhost unless you have deployed it behind a properly configured TLS reverse proxy and hardened authentication.
