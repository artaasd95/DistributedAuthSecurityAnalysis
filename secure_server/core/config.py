"""Runtime configuration for secure JWT validation."""

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class SecuritySettings:
    """Settings required for validating JWTs."""

    jwks_url: str
    issuer: str
    audience: str
    allowed_algorithm: str = "RS256"

    @classmethod
    def from_env(cls) -> "SecuritySettings":
        """Load settings from environment variables with safe defaults."""
        jwks_url = os.getenv(
            "KEYCLOAK_JWKS_URL",
            "http://localhost:8080/realms/security-lab/.well-known/jwks.json",
        )
        issuer = os.getenv(
            "KEYCLOAK_ISSUER",
            "http://localhost:8080/realms/security-lab",
        )
        audience = os.getenv("KEYCLOAK_AUDIENCE", "secure-client")
        return cls(jwks_url=jwks_url, issuer=issuer, audience=audience)
