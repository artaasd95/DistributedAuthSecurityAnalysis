"""Admin dashboard routes."""

from fastapi import APIRouter, Request

from app.models.schemas import AdminDashboardResponse
from app.services.admin_service import AdminService


class AdminRouter:
    """Routes for the admin dashboard."""

    def __init__(self, service: AdminService) -> None:
        self._service = service
        self.router = APIRouter()
        self.router.add_api_route(
            "/api/v1/admin/dashboard",
            self.get_dashboard,
            methods=["GET"],
            response_model=AdminDashboardResponse,
        )

    async def get_dashboard(self, request: Request) -> AdminDashboardResponse:
        """Return the dashboard response for authorized users."""
        user_claims = getattr(request.state, "user", {})
        return self._service.get_dashboard(user_claims)
