"""Application entry point for the vulnerable resource server."""

from fastapi import FastAPI
from starlette.middleware import Middleware

from vulnerable_server.core.auth import VulnerableJwtAuth
from vulnerable_server.middleware.auth import VulnerableAuthMiddleware
from vulnerable_server.routes.admin import AdminRouter
from vulnerable_server.services.admin_service import AdminService


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    auth = VulnerableJwtAuth()
    middleware = [
        Middleware(
            VulnerableAuthMiddleware,
            auth=auth,
            protected_paths=["/api/v1/admin"],
        )
    ]

    app = FastAPI(
        title="Vulnerable Resource Server",
        version="0.1.0",
        middleware=middleware,
    )

    admin_service = AdminService()
    admin_router = AdminRouter(admin_service)
    app.include_router(admin_router.router)

    return app


app = create_app()
