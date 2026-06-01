"""Unit tests for JWT helpers and authorization dependencies."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Optional
from unittest.mock import Mock, patch

import jwt
import pytest
from fastapi import HTTPException
from jwt import InvalidAlgorithmError

from secure_server.core.auth import SecureJwtAuth
from secure_server.core.config import SecuritySettings
from secure_server.dependencies.auth import RequireAdmin
from tests.helpers import forge_alg_none_token
from vulnerable_server.core.auth import VulnerableJwtAuth


def test_security_settings_from_env_uses_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KEYCLOAK_JWKS_URL", raising=False)
    monkeypatch.delenv("KEYCLOAK_ISSUER", raising=False)
    monkeypatch.delenv("KEYCLOAK_AUDIENCE", raising=False)

    settings = SecuritySettings.from_env()

    assert settings.jwks_url.endswith("/realms/security-lab/.well-known/jwks.json")
    assert settings.issuer == "http://localhost:8080/realms/security-lab"
    assert settings.audience == "secure-client"
    assert settings.allowed_algorithm == "RS256"


def test_security_settings_from_env_honors_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYCLOAK_JWKS_URL", "https://idp.example.com/jwks")
    monkeypatch.setenv("KEYCLOAK_ISSUER", "https://idp.example.com/realms/lab")
    monkeypatch.setenv("KEYCLOAK_AUDIENCE", "api://secure-resource")

    settings = SecuritySettings.from_env()

    assert settings.jwks_url == "https://idp.example.com/jwks"
    assert settings.issuer == "https://idp.example.com/realms/lab"
    assert settings.audience == "api://secure-resource"


@pytest.mark.parametrize(
    "authorization, expected",
    [
        ("Bearer token-value", "token-value"),
        ("bearer token-value", "token-value"),
    ],
)
def test_extract_bearer_token_accepts_valid_header(authorization: str, expected: str) -> None:
    auth = SecureJwtAuth(
        SecuritySettings(
            jwks_url="https://example.com/jwks",
            issuer="https://example.com",
            audience="api",
        )
    )

    assert auth.extract_bearer_token(authorization) == expected


@pytest.mark.parametrize("authorization", [None, "", "Token abc", "Bearer"])
def test_extract_bearer_token_rejects_invalid_header(authorization: Optional[str]) -> None:
    auth = SecureJwtAuth(
        SecuritySettings(
            jwks_url="https://example.com/jwks",
            issuer="https://example.com",
            audience="api",
        )
    )

    with pytest.raises(ValueError):
        auth.extract_bearer_token(authorization)


def test_secure_jwt_auth_rejects_unsupported_algorithm_before_jwks_lookup() -> None:
    auth = SecureJwtAuth(
        SecuritySettings(
            jwks_url="https://example.com/jwks",
            issuer="https://example.com",
            audience="api",
        )
    )
    auth._jwks_client = Mock()
    token = jwt.encode({"sub": "user-1"}, key="secret", algorithm="HS256")

    with pytest.raises(InvalidAlgorithmError):
        auth.verify_and_decode(token)

    auth._jwks_client.get_signing_key_from_jwt.assert_not_called()


def test_secure_jwt_auth_decodes_with_expected_validation_parameters() -> None:
    auth = SecureJwtAuth(
        SecuritySettings(
            jwks_url="https://example.com/jwks",
            issuer="https://example.com",
            audience="api",
        )
    )
    auth._jwks_client = Mock()
    auth._jwks_client.get_signing_key_from_jwt.return_value = SimpleNamespace(key="public-key")
    claims = {"sub": "user-1", "aud": "api", "iss": "https://example.com"}

    with (
        patch("secure_server.core.auth.jwt.get_unverified_header", return_value={"alg": "RS256"}),
        patch("secure_server.core.auth.jwt.decode", return_value=claims) as decode_mock,
    ):
        result = auth.verify_and_decode("header.payload.signature")

    assert result == claims
    decode_mock.assert_called_once_with(
        "header.payload.signature",
        key="public-key",
        algorithms=["RS256"],
        issuer="https://example.com",
        audience="api",
        options={
            "require": ["exp", "iss", "aud"],
            "verify_signature": True,
            "verify_exp": True,
            "verify_aud": True,
            "verify_iss": True,
        },
    )


@pytest.mark.parametrize(
    "claims, expected_status",
    [
        (None, 401),
        ({"sub": "user-1", "role": "user"}, 403),
    ],
)
def test_require_admin_rejects_missing_or_non_admin_claims(
    claims: Optional[dict[str, str]],
    expected_status: int,
) -> None:
    dependency = RequireAdmin()
    request = SimpleNamespace(state=SimpleNamespace(user=claims))

    with pytest.raises(HTTPException) as exc_info:
        dependency(request)

    assert exc_info.value.status_code == expected_status


def test_require_admin_allows_admin_claims() -> None:
    dependency = RequireAdmin()
    request = SimpleNamespace(state=SimpleNamespace(user={"sub": "user-1", "role": "admin"}))

    assert dependency(request) == {"sub": "user-1", "role": "admin"}


def test_vulnerable_jwt_auth_accepts_unsigned_forged_token() -> None:
    auth = VulnerableJwtAuth()
    signed_token = jwt.encode({"sub": "user-1", "role": "user"}, key="secret", algorithm="HS256")
    forged_token = forge_alg_none_token(signed_token, role="admin")

    assert auth.decode_unverified(forged_token)["role"] == "admin"