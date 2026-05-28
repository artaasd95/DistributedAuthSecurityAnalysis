"""API schemas for the secure server."""

from typing import Any, Dict

from pydantic import BaseModel


class AdminDashboardResponse(BaseModel):
    """Payload returned by the admin dashboard endpoint."""

    message: str
    user: Dict[str, Any]
