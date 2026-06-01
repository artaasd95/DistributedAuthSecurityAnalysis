"""Unit tests for security middleware behavior."""

from __future__ import annotations

from typing import Any
from unittest.mock import Mock

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import pytest
from jwt import (
    ExpiredSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    PyJWKClientError,
)

from secure_server.middleware.auth import SecureAuthMiddleware
from vulnerable_server.middleware.auth import VulnerableAuthMiddleware


def _build_app(middleware_class: Any, auth: Mock) -> FastAPI:
    app = FastAPI()
    app.add_middleware(middleware_class, auth=auth, protected_paths=["/api/v1/admin"])

    @app.get("/api/v1/admin/dashboard")
    async def dashboard(request: Request) -> dict[str, object]:
        return {"user": getattr(request.state, "user", None)}

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_secure_middleware_attaches_verified_claims() -> None:
    auth = Mock()
    auth.extract_bearer_token.return_value = "signed-token"
    auth.verify_and_decode.return_value = {"sub": "user-1", "role": "admin"}
    client = TestClient(_build_app(SecureAuthMiddleware, auth))

    response = client.get(
        "/api/v1/admin/dashboard",
        headers={"Authorization": "Bearer signed-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"user": {"sub": "user-1", "role": "admin"}}
    auth.extract_bearer_token.assert_called_once_with("Bearer signed-token")
    auth.verify_and_decode.assert_called_once_with("signed-token")


@pytest.mark.parametrize(
    "side_effect, expected_status, expected_detail, use_extract",
    [
        (ExpiredSignatureError(), 401, "Token expired.", False),
        (InvalidSignatureError(), 401, "Invalid token signature.", False),
        (InvalidAlgorithmError(), 401, "Invalid token signature.", False),
        (InvalidAudienceError(), 401, "Invalid token claims.", False),
        (InvalidIssuerError(), 401, "Invalid token claims.", False),
        (PyJWKClientError("jwks unavailable"), 401, "Unable to fetch JWKS.", False),
        (ValueError("missing header"), 401, "Unauthorized.", True),
    ],
)
def test_secure_middleware_maps_auth_failures(
    side_effect: Exception,
    expected_status: int,
    expected_detail: str,
    use_extract: bool,
) -> None:
    auth = Mock()
    if use_extract:
        auth.extract_bearer_token.side_effect = side_effect
    else:
        auth.extract_bearer_token.return_value = "signed-token"
        auth.verify_and_decode.side_effect = side_effect

    client = TestClient(_build_app(SecureAuthMiddleware, auth))

    response = client.get(
        "/api/v1/admin/dashboard",
        headers={"Authorization": "Bearer signed-token"},
    )

    assert response.status_code == expected_status
    assert response.json() == {"detail": expected_detail}


def test_secure_middleware_bypasses_unprotected_routes() -> None:
    auth = Mock()
    client = TestClient(_build_app(SecureAuthMiddleware, auth))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    auth.extract_bearer_token.assert_not_called()
    auth.verify_and_decode.assert_not_called()


def test_vulnerable_middleware_allows_admin_claims() -> None:
    auth = Mock()
    auth.extract_bearer_token.return_value = "forged-token"
    auth.decode_unverified.return_value = {"sub": "attacker", "role": "admin"}
    client = TestClient(_build_app(VulnerableAuthMiddleware, auth))

    response = client.get(
        "/api/v1/admin/dashboard",
        headers={"Authorization": "Bearer forged-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"user": {"sub": "attacker", "role": "admin"}}


def test_vulnerable_middleware_rejects_non_admin_claims() -> None:
    auth = Mock()
    auth.extract_bearer_token.return_value = "token"
    auth.decode_unverified.return_value = {"sub": "user-1", "role": "user"}
    client = TestClient(_build_app(VulnerableAuthMiddleware, auth))

    response = client.get(
        "/api/v1/admin/dashboard",
        headers={"Authorization": "Bearer token"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}


def test_vulnerable_middleware_bypasses_unprotected_routes() -> None:
    auth = Mock()
    client = TestClient(_build_app(VulnerableAuthMiddleware, auth))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    auth.extract_bearer_token.assert_not_called()
    auth.decode_unverified.assert_not_called()