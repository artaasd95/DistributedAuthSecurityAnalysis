"""Pytest fixtures for OIDC security validation."""

from __future__ import annotations

from dataclasses import dataclass
import html
import os
import re
import time
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import pytest
import requests
import jwt

from tests.helpers import (
    forge_alg_none_token,
    generate_code_challenge,
    generate_code_verifier,
)


@dataclass(frozen=True)
class LabConfig:
    """Runtime configuration for integration tests."""

    vulnerable_base_url: str
    secure_base_url: str
    valid_jwt: Optional[str]
    expired_jwt: Optional[str]
    keycloak_base_url: str
    keycloak_realm: str
    keycloak_client_id: str
    keycloak_redirect_uri: str
    keycloak_scope: str
    keycloak_admin_user: str
    keycloak_admin_password: str
    keycloak_test_username: str
    keycloak_test_password: str
    request_timeout: int


@dataclass(frozen=True)
class TokenResponse:
    """Token response data extracted from Keycloak."""

    access_token: str
    expires_in: int


def _read_env(name: str) -> Optional[str]:
    value = os.getenv(name)
    return value if value else None


def _load_config() -> LabConfig:
    return LabConfig(
        vulnerable_base_url=os.getenv("VULNERABLE_BASE_URL", "http://localhost:8000").rstrip("/"),
        secure_base_url=os.getenv("SECURE_BASE_URL", "http://localhost:8001").rstrip("/"),
        valid_jwt=_read_env("VALID_JWT"),
        expired_jwt=_read_env("EXPIRED_RS256_JWT"),
        keycloak_base_url=os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8080").rstrip("/"),
        keycloak_realm=os.getenv("KEYCLOAK_REALM", "security-lab"),
        keycloak_client_id=os.getenv("KEYCLOAK_CLIENT_ID", "secure-client"),
        keycloak_redirect_uri=os.getenv(
            "KEYCLOAK_REDIRECT_URI",
            "https://secure.example.com/callback",
        ),
        keycloak_scope=os.getenv("KEYCLOAK_SCOPE", "openid"),
        keycloak_admin_user=os.getenv("KEYCLOAK_ADMIN_USER", "kcadmin"),
        keycloak_admin_password=os.getenv(
            "KEYCLOAK_ADMIN_PASSWORD",
            "ChangeMe-Strong-Admin-2026!",
        ),
        keycloak_test_username=os.getenv("KEYCLOAK_TEST_USERNAME", "lab-user"),
        keycloak_test_password=os.getenv(
            "KEYCLOAK_TEST_PASSWORD",
            "Lab-User-Password-2026!",
        ),
        request_timeout=int(os.getenv("REQUEST_TIMEOUT_SECONDS", "10")),
    )


def _token_url(config: LabConfig) -> str:
    return (
        f"{config.keycloak_base_url}/realms/{config.keycloak_realm}/"
        "protocol/openid-connect/token"
    )


def _auth_url(config: LabConfig) -> str:
    return (
        f"{config.keycloak_base_url}/realms/{config.keycloak_realm}/"
        "protocol/openid-connect/auth"
    )


def _admin_token_url(config: LabConfig) -> str:
    return f"{config.keycloak_base_url}/realms/master/protocol/openid-connect/token"


def _admin_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _get_admin_token(config: LabConfig) -> str:
    payload = {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": config.keycloak_admin_user,
        "password": config.keycloak_admin_password,
    }
    response = requests.post(
        _admin_token_url(config),
        data=payload,
        timeout=config.request_timeout,
    )
    if response.status_code != 200:
        pytest.fail(
            "Failed to obtain Keycloak admin token. "
            f"Status: {response.status_code}. Body: {response.text}"
        )

    try:
        data = response.json()
    except ValueError as exc:
        pytest.fail(f"Admin token response was not JSON: {exc}")

    token = data.get("access_token")
    if not token:
        pytest.fail("Admin token response missing access_token.")

    return token


def _find_user_id(config: LabConfig, admin_token: str) -> Optional[str]:
    url = f"{config.keycloak_base_url}/admin/realms/{config.keycloak_realm}/users"
    response = requests.get(
        url,
        params={"username": config.keycloak_test_username},
        headers=_admin_headers(admin_token),
        timeout=config.request_timeout,
    )
    if response.status_code != 200:
        pytest.fail(
            "Failed to query Keycloak users. "
            f"Status: {response.status_code}. Body: {response.text}"
        )

    users = response.json()
    if not users:
        return None
    return users[0].get("id")


def _create_user(config: LabConfig, admin_token: str) -> str:
    url = f"{config.keycloak_base_url}/admin/realms/{config.keycloak_realm}/users"
    payload = {
        "username": config.keycloak_test_username,
        "enabled": True,
    }
    response = requests.post(
        url,
        json=payload,
        headers=_admin_headers(admin_token),
        timeout=config.request_timeout,
    )
    if response.status_code not in {201, 204}:
        pytest.fail(
            "Failed to create test user. "
            f"Status: {response.status_code}. Body: {response.text}"
        )

    user_id = _find_user_id(config, admin_token)
    if not user_id:
        pytest.fail("Unable to locate newly created test user.")
    return user_id


def _set_user_password(config: LabConfig, admin_token: str, user_id: str) -> None:
    url = (
        f"{config.keycloak_base_url}/admin/realms/{config.keycloak_realm}"
        f"/users/{user_id}/reset-password"
    )
    payload = {
        "type": "password",
        "value": config.keycloak_test_password,
        "temporary": False,
    }
    response = requests.put(
        url,
        json=payload,
        headers=_admin_headers(admin_token),
        timeout=config.request_timeout,
    )
    if response.status_code not in {204, 200}:
        pytest.fail(
            "Failed to set test user password. "
            f"Status: {response.status_code}. Body: {response.text}"
        )


def _clear_required_actions(config: LabConfig, admin_token: str, user_id: str) -> None:
    url = (
        f"{config.keycloak_base_url}/admin/realms/{config.keycloak_realm}"
        f"/users/{user_id}"
    )
    response = requests.get(
        url,
        headers=_admin_headers(admin_token),
        timeout=config.request_timeout,
    )
    if response.status_code != 200:
        pytest.fail(
            "Failed to fetch user profile. "
            f"Status: {response.status_code}. Body: {response.text}"
        )

    profile = response.json()
    profile["enabled"] = True
    profile["emailVerified"] = True
    profile["requiredActions"] = []
    if not profile.get("email"):
        profile["email"] = f"{config.keycloak_test_username}@example.com"
    if not profile.get("firstName"):
        profile["firstName"] = "Lab"
    if not profile.get("lastName"):
        profile["lastName"] = "User"

    update = requests.put(
        url,
        json=profile,
        headers=_admin_headers(admin_token),
        timeout=config.request_timeout,
    )
    if update.status_code not in {204, 200}:
        pytest.fail(
            "Failed to update user profile. "
            f"Status: {update.status_code}. Body: {update.text}"
        )


def _ensure_test_user(config: LabConfig) -> None:
    admin_token = _get_admin_token(config)
    user_id = _find_user_id(config, admin_token)
    if not user_id:
        user_id = _create_user(config, admin_token)
    _set_user_password(config, admin_token, user_id)
    _clear_required_actions(config, admin_token, user_id)


def _extract_form_action(html_text: str) -> Optional[str]:
    match = re.search(r'action="([^"]+)"', html_text)
    if not match:
        return None
    return html.unescape(match.group(1))


def _extract_form_fields(html_text: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    inputs = re.findall(r"<input[^>]+>", html_text)
    for inp in inputs:
        name_match = re.search(r'name="([^"]+)"', inp)
        if not name_match:
            continue
        value_match = re.search(r'value="([^"]*)"', inp)
        fields[name_match.group(1)] = value_match.group(1) if value_match else ""
    return fields


def _get_login_page(session: requests.Session, config: LabConfig, params: Dict[str, str]) -> requests.Response:
    response = session.get(
        _auth_url(config),
        params=params,
        timeout=config.request_timeout,
        allow_redirects=False,
    )
    if response.status_code == 200:
        return response

    if response.status_code in {302, 303}:
        location = response.headers.get("Location", "")
        if not location:
            pytest.fail("Authorization redirect missing location header.")
        if location.startswith("/"):
            location = urljoin(config.keycloak_base_url, location)
        if not location.startswith(config.keycloak_base_url):
            pytest.fail("Authorization redirect did not return a login page.")
        follow = session.get(location, timeout=config.request_timeout, allow_redirects=False)
        if follow.status_code != 200:
            pytest.fail(
                "Failed to load login page. "
                f"Status: {follow.status_code}. Body: {follow.text}"
            )
        return follow

    pytest.fail(
        "Authorization request failed. "
        f"Status: {response.status_code}. Body: {response.text}"
    )


def _perform_pkce_login(config: LabConfig) -> TokenResponse:
    session = requests.Session()
    verifier = generate_code_verifier()
    challenge = generate_code_challenge(verifier)

    params = {
        "client_id": config.keycloak_client_id,
        "response_type": "code",
        "scope": config.keycloak_scope,
        "redirect_uri": config.keycloak_redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "lab-state",
    }

    auth_request = _get_login_page(session, config, params)

    action_url = _extract_form_action(auth_request.text)
    if not action_url:
        pytest.fail("Unable to locate Keycloak login form action URL.")

    if action_url.startswith("/"):
        action_url = urljoin(config.keycloak_base_url, action_url)

    login_payload = _extract_form_fields(auth_request.text)
    login_payload.update(
        {
            "username": config.keycloak_test_username,
            "password": config.keycloak_test_password,
            "credentialId": "",
        }
    )
    login_response = session.post(
        action_url,
        data=login_payload,
        timeout=config.request_timeout,
        allow_redirects=False,
    )

    if login_response.status_code not in {302, 303}:
        pytest.fail(
            "Login failed. "
            f"Status: {login_response.status_code}. Body: {login_response.text}"
        )

    location = login_response.headers.get("Location", "")
    if not location:
        pytest.fail("Login response missing redirect location with auth code.")

    query = urlparse(location).query
    code_list = parse_qs(query).get("code")
    if not code_list:
        pytest.fail("Authorization code missing from redirect URL.")

    code = code_list[0]
    token_response = session.post(
        _token_url(config),
        data={
            "grant_type": "authorization_code",
            "client_id": config.keycloak_client_id,
            "code": code,
            "redirect_uri": config.keycloak_redirect_uri,
            "code_verifier": verifier,
        },
        timeout=config.request_timeout,
    )
    if token_response.status_code != 200:
        pytest.fail(
            "Token exchange failed. "
            f"Status: {token_response.status_code}. Body: {token_response.text}"
        )

    try:
        data = token_response.json()
    except ValueError as exc:
        pytest.fail(f"Token exchange response was not JSON: {exc}")

    access_token = data.get("access_token")
    if not access_token:
        pytest.fail("Token exchange response missing access_token.")

    expires_in = int(data.get("expires_in", 0))
    return TokenResponse(access_token=access_token, expires_in=expires_in)


def _get_client_representation(config: LabConfig, admin_token: str) -> Dict[str, object]:
    url = f"{config.keycloak_base_url}/admin/realms/{config.keycloak_realm}/clients"
    response = requests.get(
        url,
        params={"clientId": config.keycloak_client_id},
        headers=_admin_headers(admin_token),
        timeout=config.request_timeout,
    )
    if response.status_code != 200:
        pytest.fail(
            "Failed to query Keycloak client. "
            f"Status: {response.status_code}. Body: {response.text}"
        )

    clients = response.json()
    if not clients:
        pytest.fail("Secure client not found in Keycloak.")
    return clients[0]


def _update_client(config: LabConfig, admin_token: str, client_id: str, payload: Dict[str, object]) -> None:
    url = f"{config.keycloak_base_url}/admin/realms/{config.keycloak_realm}/clients/{client_id}"
    response = requests.put(
        url,
        json=payload,
        headers=_admin_headers(admin_token),
        timeout=config.request_timeout,
    )
    if response.status_code not in {204, 200}:
        pytest.fail(
            "Failed to update Keycloak client. "
            f"Status: {response.status_code}. Body: {response.text}"
        )


@pytest.fixture(scope="session")
def config() -> LabConfig:
    """Provide test configuration loaded from environment variables."""
    return _load_config()


@pytest.fixture(scope="session")
def token_response(config: LabConfig) -> Optional[TokenResponse]:
    """Return a token response from env or Keycloak using auth code + PKCE."""
    if config.valid_jwt:
        return TokenResponse(access_token=config.valid_jwt, expires_in=0)

    _ensure_test_user(config)
    return _perform_pkce_login(config)


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
def expired_token(config: LabConfig) -> str:
    """Provide an expired but otherwise valid JWT for secure backend tests."""
    if config.expired_jwt:
        return config.expired_jwt

    _ensure_test_user(config)
    admin_token = _get_admin_token(config)
    client = _get_client_representation(config, admin_token)
    client_id = client.get("id")
    if not client_id:
        pytest.fail("Client id missing from Keycloak response.")

    attributes = dict(client.get("attributes") or {})
    original_lifespan = attributes.get("access.token.lifespan")
    attributes["access.token.lifespan"] = "1"
    client["attributes"] = attributes

    _update_client(config, admin_token, str(client_id), client)

    try:
        token_response = _perform_pkce_login(config)
        payload = jwt.decode(
            token_response.access_token,
            options={
                "verify_signature": False,
                "verify_aud": False,
                "verify_iss": False,
                "verify_exp": False,
            },
            algorithms=["RS256", "HS256", "none"],
        )
        exp = payload.get("exp")
        if exp:
            wait_seconds = max(0, int(exp) - int(time.time()) + 2)
            if wait_seconds:
                time.sleep(wait_seconds)
        else:
            time.sleep(2)
        return token_response.access_token
    finally:
        attributes = dict(client.get("attributes") or {})
        if original_lifespan is None:
            attributes.pop("access.token.lifespan", None)
        else:
            attributes["access.token.lifespan"] = str(original_lifespan)
        client["attributes"] = attributes
        _update_client(config, admin_token, str(client_id), client)
