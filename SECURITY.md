# Security notes

## Authentication and authorisation

- `X-API-Key` protects detection/read endpoints (`/detect`, `/check`, `/logs`,
  `/stats`, `/replay`).
- A separate admin key protects `/threshold`, `/clear` and the retraining API.
- The dashboard uses HTTP Basic auth. Put it behind TLS and change the default
  credentials.
- API keys are compared with constant-time comparison in the dashboard path;
  store them as environment values (never in git).

## Data handling

- Request bodies/headers are needed for model inference but are **not**
  persisted raw. `src/utils/redaction.py` masks:
  - `Authorization`, `Cookie`, `X-API-Key` and CSRF headers
  - password/token/API-key/secret/card fields in JSON and forms
  - JWT/Bearer tokens and email addresses
- Stored events are truncated to 1,000 characters after redaction.
- The audit log stores a SHA-256 fingerprint of the API key, never the key.
- `data/` and `logs/` are git-ignored. Apply filesystem permissions and a
  retention policy in production.

## Network and edge

- nginx terminates TLS 1.2/1.3, redirects HTTP to HTTPS, sets HSTS and
  security headers, disables server tokens and enforces body-size limits.
- Redis requires a password and is not published on a host port.
- The gateway rejects oversized bodies/paths/headers and rate-limits clients.
- Optional static `WAF_IP_ALLOWLIST` / `WAF_IP_BLOCKLIST` CIDR lists provide an
  emergency deny-list and a management-plane allow-list.
- Ambiguous `Content-Length` + `Transfer-Encoding` requests are rejected.
- Detection failures fail closed (`503`), never open.

## Known gaps before production

- Real certificate management (Let's Encrypt/ACME or an internal CA) instead of
  the included self-signed helper.
- Centralised secrets (Vault/KMS/Docker secrets) instead of `.env`.
- RBAC/SSO for the dashboard; Basic auth is an MVP choice.
- PostgreSQL/HA instead of single-node SQLite; horizontal scaling needs shared
  storage and a shared rate-limit cache.
- SIEM forwarding, alerting and long-term log retention.
- Independent penetration test and WAF evasion/fuzzing before handling real
  production traffic.

## Reporting

For this prototype, open a private issue in the repository. Do not include
credentials or customer data in reports.
