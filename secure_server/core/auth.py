"""Secure JWT validation using JWKS discovery."""

from typing import Any, Dict, Optional

import jwt
from jwt import InvalidAlgorithmError, PyJWKClient

from secure_server.core.config import SecuritySettings


class SecureJwtAuth:
    """JWT validator that enforces RS256 and standard claim checks."""

    def __init__(self, settings: SecuritySettings) -> None:
        self._settings = settings
        self._jwks_client = PyJWKClient(settings.jwks_url)

    def extract_bearer_token(self, authorization: Optional[str]) -> str:
        """Extract a bearer token from the Authorization header."""
        if not authorization:
            raise ValueError("Missing Authorization header.")

        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise ValueError("Invalid Authorization header.")

        return token

    def verify_and_decode(self, token: str) -> Dict[str, Any]:
        """Verify the JWT signature and validate registered claims."""
        header = jwt.get_unverified_header(token)
        if header.get("alg") != self._settings.allowed_algorithm:
            raise InvalidAlgorithmError("Unsupported JWT algorithm.")

        signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            key=signing_key.key,
            algorithms=[self._settings.allowed_algorithm],
            issuer=self._settings.issuer,
            audience=self._settings.audience,
            options={
                "require": ["exp", "iss", "aud"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
