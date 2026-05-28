"""Secure admin routes."""

from fastapi import APIRouter, Depends, Request

from secure_server.dependencies.auth import RequireAdmin
from secure_server.models.schemas import AdminDashboardResponse
from secure_server.services.admin_service import AdminService


class AdminRouter:
    """Router for secured admin endpoints."""

    def __init__(self, service: AdminService, require_admin: RequireAdmin) -> None:
        self._service = service
        self.router = APIRouter(dependencies=[Depends(require_admin)])
        self.router.add_api_route(
            "/api/v1/admin/dashboard",
            self.get_dashboard,
            methods=["GET"],
            response_model=AdminDashboardResponse,
        )

    async def get_dashboard(self, request: Request) -> AdminDashboardResponse:
        """Return the secured dashboard response."""
        user_claims = getattr(request.state, "user", {})
        return self._service.get_dashboard(user_claims)
