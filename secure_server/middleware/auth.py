"""Secure authentication middleware."""

from typing import Iterable

from fastapi import Request
from jwt import (
    ExpiredSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    PyJWKClientError,
)
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from secure_server.core.auth import SecureJwtAuth


class SecureAuthMiddleware(BaseHTTPMiddleware):
    """Validate JWTs and attach claims to the request state."""

    def __init__(
        self,
        app,
        auth: SecureJwtAuth,
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
            claims = self._auth.verify_and_decode(token)
        except ExpiredSignatureError:
            return JSONResponse(status_code=401, content={"detail": "Token expired."})
        except (InvalidSignatureError, InvalidAlgorithmError):
            return JSONResponse(status_code=401, content={"detail": "Invalid token signature."})
        except (InvalidAudienceError, InvalidIssuerError):
            return JSONResponse(status_code=401, content={"detail": "Invalid token claims."})
        except PyJWKClientError:
            return JSONResponse(status_code=401, content={"detail": "Unable to fetch JWKS."})
        except Exception:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized."})

        request.state.user = claims
        return await call_next(request)

    def _is_protected(self, path: str) -> bool:
        return any(path.startswith(prefix) for prefix in self._protected_paths)
