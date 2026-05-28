"""API request and response schemas."""

from typing import Any, Dict

from pydantic import BaseModel


class AdminDashboardResponse(BaseModel):
    """Response payload for the admin dashboard endpoint."""

    message: str
    user: Dict[str, Any]
