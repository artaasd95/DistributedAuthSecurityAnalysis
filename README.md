# Distributed Auth Security Analysis

This repository is a controlled lab for studying OAuth 2.0 and OpenID Connect security boundaries with Keycloak and FastAPI. It includes both intentionally vulnerable components and hardened counterparts so you can demonstrate attacks, validate defenses, and document the results in a repeatable way.

## Overview

The project is organized around three ideas:

- A deliberately vulnerable FastAPI resource server that accepts weak JWT validation patterns for research purposes.
- A secure FastAPI resource server that validates tokens through Keycloak JWKS and strict claim checks.
- A supporting lab stack with Keycloak, Postgres, automated tests, an attacker script, and a technical report.

## Learning Objectives

- Demonstrate how JWT signature validation failures can break authorization boundaries.
- Compare insecure and secure server behavior under identical request conditions.
- Validate hardening controls with automated regression tests.
- Provide a reproducible reference implementation for teaching and research.

## Security Scope

- In scope: OAuth 2.0 / OIDC token handling at the resource server boundary.
- In scope: signature bypass (`alg=none`), expiry validation, and role enforcement.
- Out of scope: production deployment hardening, advanced WAF controls, and SIEM integration.

## Repository Layout

```text
DistributedAuthSecurityAnalysis/
|- docker-compose.yml          # Keycloak + Postgres lab stack
|- requirements.txt            # Runtime dependencies
|- requirements-dev.txt        # Test and development dependencies
|- README.md                   # Project overview and usage
|- CONTRIBUTING.md             # Contribution workflow and standards
|
|- keycloak/
|  |- realm-security-lab.json  # Realm import with lab clients and settings
|
|- vulnerable_server/          # Intentionally insecure resource server
|  |- core/                    # Vulnerable JWT handling logic
|  |- middleware/              # Insecure auth middleware
|  |- routes/                  # API routes
|  |- services/                # Business logic layer
|  |- models/                  # Response schemas
|  |- main.py                  # App entrypoint
|
|- secure_server/              # Hardened resource server
|  |- core/                    # Secure JWT validation and settings
|  |- middleware/              # Strict auth middleware
|  |- dependencies/            # Route-level authorization guards
|  |- routes/                  # API routes
|  |- services/                # Business logic layer
|  |- models/                  # Response schemas
|  |- main.py                  # App entrypoint
|
|- scripts/
|  |- attacker.py              # Token forgery / bypass demonstration tool
|
|- tests/
|  |- conftest.py              # Shared fixtures and Keycloak test helpers
|  |- test_unit_auth.py        # Unit tests for auth/config/dependencies
|  |- test_unit_middleware.py  # Unit tests for middleware behavior
|  |- test_security_flows.py   # End-to-end vulnerability regressions
|
|- postman/
|  |- oidc-security-lab.postman_collection.json  # Manual API and OIDC flows
|
|- Docs/
   |- README.md                # Documentation index and build notes
   |- report.tex               # Technical report source
   |- report.pdf               # Compiled report artifact
   |- References/              # RFCs, OWASP, and supporting references
```

This layout intentionally keeps vulnerable and secure implementations separate, so attack and mitigation paths can be compared side by side without altering the overall architecture.

## Prerequisites

- Docker and Docker Compose
- Python 3.9 or newer

## Quick Start

1. Create a local environment file with lab credentials:

   ```text
   KEYCLOAK_ADMIN=kcadmin
   KEYCLOAK_ADMIN_PASSWORD=ChangeMe-Strong-Admin-2026!
   POSTGRES_PASSWORD=ChangeMe-Strong-Db-2026!
   ```

2. Start the Keycloak and Postgres stack:

   ```text
   docker compose up -d
   ```

3. Open the Keycloak admin console at http://localhost:8080.
4. Start the vulnerable API on port 8000.
5. Start the secure API on port 8001.

The `security-lab` realm is imported automatically from [keycloak/realm-security-lab.json](keycloak/realm-security-lab.json).

## Typical Lab Workflow

1. Start infrastructure and both API variants.
2. Obtain or generate a valid access token.
3. Forge a token with [scripts/attacker.py](scripts/attacker.py).
4. Compare responses from vulnerable and secure endpoints.
5. Run the automated test suites to confirm expected behavior.

## Running the Servers

Install runtime dependencies first:

```text
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Start the vulnerable server on port 8000:

```text
uvicorn vulnerable_server.main:app --reload --port 8000
```

Start the secure server on port 8001:

```text
uvicorn secure_server.main:app --reload --port 8001
```

Optional validation overrides for the secure server:

```text
KEYCLOAK_JWKS_URL=http://localhost:8080/realms/security-lab/.well-known/jwks.json
KEYCLOAK_ISSUER=http://localhost:8080/realms/security-lab
KEYCLOAK_AUDIENCE=secure-client
```

These values are the secure server defaults from `secure_server/core/config.py`; set them only when your Keycloak realm or client settings differ.

The vulnerable server is intentionally insecure and accepts `alg=none` tokens for demonstration purposes. Do not expose it outside an isolated lab network.

## Attack Demonstration

Use [scripts/attacker.py](scripts/attacker.py) to forge a token and show the signature-bypass issue end to end:

```text
python scripts/attacker.py --token <valid_jwt> --url http://localhost:8000/api/v1/admin/dashboard
```

You can also probe the resource servers directly with curl:

```text
curl -H "Authorization: Bearer <forged_jwt>" http://localhost:8000/api/v1/admin/dashboard
curl -H "Authorization: Bearer <forged_jwt>" http://localhost:8001/api/v1/admin/dashboard
```

## Test Strategy

Install the development dependencies from [requirements-dev.txt](requirements-dev.txt):

```text
pip install -r requirements-dev.txt
```

The test suite is split into two layers:

- Unit tests for helpers, auth/config logic, middleware, services, and authorization dependencies.
- Vulnerability and integration tests that validate forged-token, missing-auth, malformed-token, and expiry behavior against running services.

Unit test files:

- [tests/test_unit_auth.py](tests/test_unit_auth.py)
- [tests/test_unit_helpers.py](tests/test_unit_helpers.py)
- [tests/test_unit_middleware.py](tests/test_unit_middleware.py)
- [tests/test_unit_services.py](tests/test_unit_services.py)

Vulnerability and integration test file:

- [tests/test_security_flows.py](tests/test_security_flows.py)

Common environment variables for the integration tests:

- `VULNERABLE_BASE_URL` - default `http://localhost:8000`
- `SECURE_BASE_URL` - default `http://localhost:8001`
- `VALID_JWT` - optional valid token for faster runs
- `EXPIRED_RS256_JWT` - optional expired token for expiry checks
- `KEYCLOAK_BASE_URL` - default `http://localhost:8080`
- `KEYCLOAK_REALM` - default `security-lab`
- `KEYCLOAK_CLIENT_ID` - default `secure-client`
- `KEYCLOAK_REDIRECT_URI` - default `https://secure.example.com/callback`
- `KEYCLOAK_ADMIN_USER` and `KEYCLOAK_ADMIN_PASSWORD`
- `KEYCLOAK_TEST_USERNAME` and `KEYCLOAK_TEST_PASSWORD`
- `KEYCLOAK_SCOPE` - default `openid`
- `REQUEST_TIMEOUT_SECONDS` - default `10`

Run the full suite with:

```text
python -m pytest -v
```

Run only unit tests:

```text
python -m pytest tests/test_unit_*.py -v
```

Run only vulnerability and integration flows:

```text
python -m pytest tests/test_security_flows.py -v
```

## Documentation

- Technical report source: [Docs/report.tex](Docs/report.tex)
- Technical report PDF: [Docs/report.pdf](Docs/report.pdf)
- Documentation index: [Docs/README.md](Docs/README.md)
- Reference material: [Docs/References/](Docs/References/)

## Troubleshooting

- If Keycloak token acquisition fails in tests, verify admin credentials and realm import.
- If secure server tests fail with JWKS errors, confirm the issuer and JWKS URLs match Keycloak realm settings.
- If integration tests time out, ensure both API servers are running and reachable on configured ports.

## Safety

This repository is intended for isolated research and teaching environments only. The vulnerable service exists so the security failure can be demonstrated safely and reproducibly.

## License

GPL-3.0-only. See [LICENSE](LICENSE) for details.
