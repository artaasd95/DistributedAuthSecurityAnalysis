"""Admin dashboard service implementation."""

from typing import Any, Dict

from secure_server.models.schemas import AdminDashboardResponse


class AdminService:
    """Business logic for the admin dashboard."""

    def get_dashboard(self, user_claims: Dict[str, Any]) -> AdminDashboardResponse:
        """Generate a secure dashboard response."""
        return AdminDashboardResponse(
            message="Secure admin dashboard access granted.",
            user=user_claims,
        )
