"""Application entry point for the secure resource server."""

from fastapi import FastAPI
from starlette.middleware import Middleware

from secure_server.core.auth import SecureJwtAuth
from secure_server.core.config import SecuritySettings
from secure_server.dependencies.auth import RequireAdmin
from secure_server.middleware.auth import SecureAuthMiddleware
from secure_server.routes.admin import AdminRouter
from secure_server.services.admin_service import AdminService


def create_app() -> FastAPI:
    """Create and configure the secure FastAPI application."""
    settings = SecuritySettings.from_env()
    auth = SecureJwtAuth(settings)

    middleware = [
        Middleware(
            SecureAuthMiddleware,
            auth=auth,
            protected_paths=["/api/v1/admin"],
        )
    ]

    app = FastAPI(
        title="Secure Resource Server",
        version="1.0.0",
        middleware=middleware,
    )

    admin_service = AdminService()
    admin_router = AdminRouter(admin_service, RequireAdmin())
    app.include_router(admin_router.router)

    return app


app = create_app()
