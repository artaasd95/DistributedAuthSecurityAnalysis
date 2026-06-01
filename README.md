# Distributed Auth Security Analysis

Research-focused lab for demonstrating OAuth 2.0 and OpenID Connect (OIDC) weaknesses and hardening strategies using Keycloak and FastAPI.

## Highlights

- Vulnerable FastAPI resource server to demonstrate signature-bypass issues.
- Secure FastAPI resource server enforcing strict JWT validation via Keycloak JWKS.
- Keycloak + Postgres Docker stack with a preloaded lab realm.
- Attacker script, automated pytest suite, and a Postman collection.
- Full technical report and reference materials under [Docs/](Docs/).

## Project layout

- [docker-compose.yml](docker-compose.yml)
- [keycloak/](keycloak/) (realm import: [keycloak/realm-security-lab.json](keycloak/realm-security-lab.json))
- [vulnerable_server/](vulnerable_server/)
- [secure_server/](secure_server/)
- [scripts/](scripts/) (attacker: [scripts/attacker.py](scripts/attacker.py))
- [tests/](tests/)
- [postman/](postman/) (collection: [postman/oidc-security-lab.postman_collection.json](postman/oidc-security-lab.postman_collection.json))
- [Docs/](Docs/)
- [requirements.txt](requirements.txt)
- [requirements-dev.txt](requirements-dev.txt)

## Prerequisites

- Docker + Docker Compose
- Python 3.9+ (recommended)

## Quick start (Keycloak + Postgres)

1. Create a local environment file (ignored by Git):

   ```text
   KEYCLOAK_ADMIN=kcadmin
   KEYCLOAK_ADMIN_PASSWORD=ChangeMe-Strong-Admin-2026!
   POSTGRES_PASSWORD=ChangeMe-Strong-Db-2026!
   ```

2. Start Keycloak and Postgres:

   ```text
   docker compose up -d
   ```

3. Access Keycloak admin console at http://localhost:8080

The realm `security-lab` is auto-imported from [keycloak/realm-security-lab.json](keycloak/realm-security-lab.json).

## Run the vulnerable resource server (intentionally insecure)

Install dependencies from [requirements.txt](requirements.txt), then run:

```text
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn vulnerable_server.main:app --reload --port 8000
```

This server accepts `alg=none` tokens by design for research and testing. Do **not** deploy it in production.

## Run the secure resource server

Install dependencies from [requirements.txt](requirements.txt), then run:

```text
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn secure_server.main:app --reload --port 8001
```

Optional environment overrides for strict validation:

```text
KEYCLOAK_JWKS_URL=http://localhost:8080/realms/security-lab/protocol/openid-connect/certs
KEYCLOAK_ISSUER=http://localhost:8080/realms/security-lab
KEYCLOAK_AUDIENCE=account
```

## Attack simulation (alg=none)

Use the attacker script at [scripts/attacker.py](scripts/attacker.py) to forge a token and demonstrate the vulnerable behavior:

```text
python scripts/attacker.py --token <valid_jwt> --url http://localhost:8000/api/v1/admin/dashboard
```

## Automated test suite (pytest)

Install test dependencies from [requirements-dev.txt](requirements-dev.txt):

```text
pip install -r requirements-dev.txt
```

Environment variables for tests:

- `VULNERABLE_BASE_URL` (default: `http://localhost:8000`)
- `SECURE_BASE_URL` (default: `http://localhost:8001`)
- `VALID_JWT` (optional, preferred for fast runs)
- `EXPIRED_RS256_JWT` (optional, preferred for expiry validation)
- `KEYCLOAK_BASE_URL` (default: `http://localhost:8080`)
- `KEYCLOAK_REALM` (default: `security-lab`)
- `KEYCLOAK_CLIENT_ID` (default: `secure-client`)
- `KEYCLOAK_REDIRECT_URI` (default: `https://secure.example.com/callback`)
- `KEYCLOAK_ADMIN_USER` / `KEYCLOAK_ADMIN_PASSWORD`
- `KEYCLOAK_TEST_USERNAME` / `KEYCLOAK_TEST_PASSWORD`
- `KEYCLOAK_SCOPE` (default: `openid`)
- `REQUEST_TIMEOUT_SECONDS` (default: `10`)

Run the tests:

```text
pytest -v
```

## Postman collection

Import [postman/oidc-security-lab.postman_collection.json](postman/oidc-security-lab.postman_collection.json) and set collection variables:

- `keycloak_base_url`, `realm`, `client_id_vulnerable`, `client_id_secure`
- `redirect_uri_vulnerable`, `redirect_uri_secure`
- `code_verifier`, `code_challenge`, `authorization_code`, `access_token`
- `vulnerable_rs_base_url`, `secure_rs_base_url`

## jwt.io and curl usage

The vulnerable client uses `https://jwt.io/*` as its redirect URI so you can inspect tokens directly in jwt.io.
For API-level demonstrations, you can also use curl:

```text
curl -H "Authorization: Bearer <forged_jwt>" http://localhost:8000/api/v1/admin/dashboard
curl -H "Authorization: Bearer <forged_jwt>" http://localhost:8001/api/v1/admin/dashboard
```

## Documentation

- Technical report: [Docs/report.pdf](Docs/report.pdf)
- Source: [Docs/report.tex](Docs/report.tex)
- Reference materials: [Docs/References/](Docs/References/)

## Safety and ethical use

This repository contains intentionally vulnerable components. Use only in isolated lab environments and do not expose the vulnerable server to untrusted networks.

## License

GPL-3.0-only. See [LICENSE](LICENSE) for details.
