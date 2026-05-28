"""Admin dashboard service logic."""

from typing import Any, Dict

from app.models.schemas import AdminDashboardResponse


class AdminService:
    """Business logic for admin dashboard operations."""

    def get_dashboard(self, user_claims: Dict[str, Any]) -> AdminDashboardResponse:
        """Build the admin dashboard response."""
        return AdminDashboardResponse(
            message="Welcome to the admin dashboard.",
            user=user_claims,
        )
