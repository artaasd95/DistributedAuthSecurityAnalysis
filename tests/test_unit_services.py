"""Unit tests for service-level response contracts."""

from __future__ import annotations

from secure_server.services.admin_service import AdminService as SecureAdminService
from vulnerable_server.services.admin_service import AdminService as VulnerableAdminService


def test_secure_admin_service_response_contract() -> None:
    service = SecureAdminService()
    claims = {"sub": "user-1", "role": "admin"}

    response = service.get_dashboard(claims)

    assert response.message == "Secure admin dashboard access granted."
    assert response.user == claims


def test_vulnerable_admin_service_response_contract() -> None:
    service = VulnerableAdminService()
    claims = {"sub": "attacker", "role": "admin"}

    response = service.get_dashboard(claims)

    assert response.message == "Welcome to the admin dashboard."
    assert response.user == claims
