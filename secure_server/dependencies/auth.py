"""Authorization dependencies for secured routes."""

from typing import Any, Dict

from fastapi import HTTPException, Request, status


class RequireAdmin:
    """Dependency that enforces the admin role."""

    def __call__(self, request: Request) -> Dict[str, Any]:
        user_claims = getattr(request.state, "user", None)
        if not user_claims:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized.",
            )

        if user_claims.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden.",
            )

        return user_claims
