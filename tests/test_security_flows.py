"""Security regression tests for the OIDC lab."""

from __future__ import annotations

import requests

from tests.conftest import TestConfig


def _build_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}{path}"


def _extract_detail(response: requests.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return response.text
    return str(data.get("detail", ""))


class TestOidcSecurity:
    """Integration tests that verify vulnerable and secure behaviors."""

    def test_vulnerable_accepts_forged_token(
        self, config: TestConfig, forged_token: str
    ) -> None:
        url = _build_url(config.vulnerable_base_url, "/api/v1/admin/dashboard")
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {forged_token}"},
            timeout=config.request_timeout,
        )

        # A 200 response proves the vulnerable server accepts unsigned alg=none tokens.
        assert response.status_code == 200

    def test_secure_rejects_forged_token(self, config: TestConfig, forged_token: str) -> None:
        url = _build_url(config.secure_base_url, "/api/v1/admin/dashboard")
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {forged_token}"},
            timeout=config.request_timeout,
        )

        # A 401 response confirms secure middleware rejects alg=none signature bypasses.
        assert response.status_code == 401
        detail = _extract_detail(response).lower()
        # The error message should indicate invalid signature or algorithm enforcement.
        assert "invalid" in detail or "signature" in detail

    def test_secure_rejects_expired_token(self, config: TestConfig, expired_token: str) -> None:
        url = _build_url(config.secure_base_url, "/api/v1/admin/dashboard")
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {expired_token}"},
            timeout=config.request_timeout,
        )

        # A 401 response verifies that expired tokens are blocked even if signed.
        assert response.status_code == 401
        detail = _extract_detail(response).lower()
        # Explicit expiry errors confirm strict exp claim enforcement.
        assert "expired" in detail
