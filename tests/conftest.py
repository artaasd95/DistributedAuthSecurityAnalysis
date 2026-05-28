"""Pytest fixtures for OIDC security validation."""

from __future__ import annotations

from dataclasses import dataclass
import os
import time
from typing import Optional

import pytest
import requests

from tests.helpers import forge_alg_none_token


@dataclass(frozen=True)
class TestConfig:
    """Runtime configuration for integration tests."""

    vulnerable_base_url: str
    secure_base_url: str
    valid_jwt: Optional[str]
    expired_jwt: Optional[str]
    keycloak_token_url: Optional[str]
    keycloak_client_id: Optional[str]
    keycloak_client_secret: Optional[str]
    keycloak_username: Optional[str]
    keycloak_password: Optional[str]
    keycloak_scope: str
    request_timeout: int
    expired_wait_seconds: int


@dataclass(frozen=True)
class TokenResponse:
    """Token response data extracted from Keycloak."""

    access_token: str
    expires_in: int


def _read_env(name: str) -> Optional[str]:
    value = os.getenv(name)
    return value if value else None


def _load_config() -> TestConfig:
    return TestConfig(
        vulnerable_base_url=os.getenv("VULNERABLE_BASE_URL", "http://localhost:8000").rstrip("/"),
        secure_base_url=os.getenv("SECURE_BASE_URL", "http://localhost:8001").rstrip("/"),
        valid_jwt=_read_env("VALID_JWT"),
        expired_jwt=_read_env("EXPIRED_RS256_JWT"),
        keycloak_token_url=_read_env("KEYCLOAK_TOKEN_URL"),
        keycloak_client_id=_read_env("KEYCLOAK_CLIENT_ID"),
        keycloak_client_secret=_read_env("KEYCLOAK_CLIENT_SECRET"),
        keycloak_username=_read_env("KEYCLOAK_USERNAME"),
        keycloak_password=_read_env("KEYCLOAK_PASSWORD"),
        keycloak_scope=os.getenv("KEYCLOAK_SCOPE", "openid"),
        request_timeout=int(os.getenv("REQUEST_TIMEOUT_SECONDS", "10")),
        expired_wait_seconds=int(os.getenv("EXPIRED_WAIT_SECONDS", "0")),
    )


def _fetch_token_with_password_grant(config: TestConfig) -> Optional[TokenResponse]:
    if not all(
        [
            config.keycloak_token_url,
            config.keycloak_client_id,
            config.keycloak_username,
            config.keycloak_password,
        ]
    ):
        return None

    payload = {
        "grant_type": "password",
        "client_id": config.keycloak_client_id,
        "username": config.keycloak_username,
        "password": config.keycloak_password,
        "scope": config.keycloak_scope,
    }
    if config.keycloak_client_secret:
        payload["client_secret"] = config.keycloak_client_secret

    response = requests.post(
        config.keycloak_token_url,
        data=payload,
        timeout=config.request_timeout,
    )
    if response.status_code != 200:
        pytest.fail(
            "Keycloak token request failed. "
            f"Status: {response.status_code}. Body: {response.text}"
        )

    try:
        data = response.json()
    except ValueError as exc:
        pytest.fail(f"Token endpoint returned non-JSON data: {exc}")

    access_token = data.get("access_token")
    if not access_token:
        pytest.fail("Token endpoint response missing access_token.")

    expires_in = int(data.get("expires_in", 0))
    return TokenResponse(access_token=access_token, expires_in=expires_in)


@pytest.fixture(scope="session")
def config() -> TestConfig:
    """Provide test configuration loaded from environment variables."""
    return _load_config()


@pytest.fixture(scope="session")
def token_response(config: TestConfig) -> Optional[TokenResponse]:
    """Return a token response from env or Keycloak if available."""
    if config.valid_jwt:
        return TokenResponse(access_token=config.valid_jwt, expires_in=0)
    return _fetch_token_with_password_grant(config)


@pytest.fixture(scope="session")
def valid_token(token_response: Optional[TokenResponse]) -> str:
    """Provide a valid JWT for test cases that require it."""
    if token_response is None:
        pytest.fail(
            "Set VALID_JWT or provide KEYCLOAK_TOKEN_URL, KEYCLOAK_CLIENT_ID, "
            "KEYCLOAK_USERNAME, and KEYCLOAK_PASSWORD to obtain a token."
        )
    return token_response.access_token


@pytest.fixture(scope="session")
def forged_token(valid_token: str) -> str:
    """Provide a forged alg=none token for signature bypass testing."""
    return forge_alg_none_token(valid_token, role="admin")


@pytest.fixture(scope="session")
def expired_token(config: TestConfig, token_response: Optional[TokenResponse]) -> str:
    """Provide an expired but otherwise valid JWT for secure backend tests."""
    if config.expired_jwt:
        return config.expired_jwt

    if token_response is None:
        pytest.fail(
            "Set EXPIRED_RS256_JWT or provide Keycloak credentials to fetch a token."
        )

    if config.expired_wait_seconds <= 0:
        pytest.fail(
            "Set EXPIRED_RS256_JWT or EXPIRED_WAIT_SECONDS to wait for token expiry."
        )

    if token_response.expires_in <= 0:
        pytest.fail("Token response missing expires_in; provide EXPIRED_RS256_JWT.")

    required_wait = token_response.expires_in + 5
    if config.expired_wait_seconds < required_wait:
        pytest.fail(
            f"EXPIRED_WAIT_SECONDS must be >= {required_wait} to ensure token expiry."
        )

    time.sleep(config.expired_wait_seconds)
    return token_response.access_token
