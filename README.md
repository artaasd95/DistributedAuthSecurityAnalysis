# Distributed Auth Security Analysis

A local security lab for studying OAuth 2.0 and OpenID Connect (OIDC) weaknesses and hardening strategies. It ships with:
- A **vulnerable** FastAPI resource server to demonstrate signature-bypass issues.
- A **secure** FastAPI resource server enforcing strict JWT validation via Keycloak JWKS.
- A Keycloak + Postgres Docker stack with a preloaded lab realm.
- An attacker script, automated pytest suite, and a Postman collection.

## Project layout

```
.
├── docker-compose.yml
├── keycloak/
│   └── realm-security-lab.json
├── vulnerable_server/
├── secure_server/
├── scripts/
│   └── attacker.py
├── tests/
├── postman/
│   └── oidc-security-lab.postman_collection.json
├── requirements.txt
├── requirements-dev.txt
└── .env (ignored)
```

## Prerequisites

- Docker + Docker Compose
- Python 3.9+ (recommended)

## Quick start (Keycloak + Postgres)

1. Create a local `.env` file (this file is ignored by Git):

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

The realm `security-lab` is auto-imported from `keycloak/realm-security-lab.json`.

## Running the vulnerable resource server (intentionally insecure)

```text
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn vulnerable_server.main:app --reload --port 8000
```

This server accepts `alg=none` tokens by design for research and testing. Do **not** deploy it in production.

## Running the secure resource server

```text
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn secure_server.main:app --reload --port 8001
```

Optional environment overrides for strict validation:

```text
KEYCLOAK_JWKS_URL=http://localhost:8080/realms/security-lab/.well-known/jwks.json
KEYCLOAK_ISSUER=http://localhost:8080/realms/security-lab
KEYCLOAK_AUDIENCE=secure-client
```

## Attack simulation (alg=none)

Use the attacker script to forge a token and demonstrate the vulnerable behavior:

```text
python scripts/attacker.py --token <valid_jwt> --url http://localhost:8000/api/v1/admin/dashboard
```

## Automated test suite (pytest)

Install test dependencies:

```text
pip install -r requirements-dev.txt
```

### Environment variables for tests

You can provide tokens directly or let the suite fetch them from Keycloak:

- `VULNERABLE_BASE_URL` (default: `http://localhost:8000`)
- `SECURE_BASE_URL` (default: `http://localhost:8001`)
- `VALID_JWT` (optional, preferred for fast runs)
- `EXPIRED_RS256_JWT` (optional, preferred for expiry validation)
- `KEYCLOAK_TOKEN_URL` (e.g., `http://localhost:8080/realms/security-lab/protocol/openid-connect/token`)
- `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET` (optional), `KEYCLOAK_USERNAME`, `KEYCLOAK_PASSWORD`
- `KEYCLOAK_SCOPE` (default: `openid`)
- `EXPIRED_WAIT_SECONDS` (only if you want the test to wait for token expiry)

Run the tests:

```text
pytest -v
```

## Postman collection

Import `postman/oidc-security-lab.postman_collection.json` and set collection variables:

- `keycloak_base_url`, `realm`, `client_id_vulnerable`, `client_id_secure`
- `redirect_uri_vulnerable`, `redirect_uri_secure`
- `code_verifier`, `code_challenge`, `authorization_code`, `access_token`
- `vulnerable_rs_base_url`, `secure_rs_base_url`

## Security note

The `vulnerable_server` package intentionally disables JWT signature verification to demonstrate real-world risks. Keep it isolated and never expose it outside a controlled lab environment.
