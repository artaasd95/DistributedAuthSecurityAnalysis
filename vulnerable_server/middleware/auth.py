"""Vulnerable JWT authentication middleware."""

from typing import Iterable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from vulnerable_server.core.auth import VulnerableJwtAuth


class VulnerableAuthMiddleware(BaseHTTPMiddleware):
    """Intentionally vulnerable JWT middleware for research labs."""

    def __init__(
        self,
        app,
        auth: VulnerableJwtAuth,
        protected_paths: Iterable[str],
    ) -> None:
        super().__init__(app)
        self._auth = auth
        self._protected_paths = list(protected_paths)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        if not self._is_protected(path):
            return await call_next(request)

        try:
            token = self._auth.extract_bearer_token(request.headers.get("Authorization"))
            # Intentionally insecure: decode without signature verification.
            claims = self._auth.decode_unverified(token)
        except Exception:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        if claims.get("role") != "admin":
            return JSONResponse(status_code=403, content={"detail": "Forbidden"})

        request.state.user = claims
        return await call_next(request)

    def _is_protected(self, path: str) -> bool:
        return any(path.startswith(prefix) for prefix in self._protected_paths)
