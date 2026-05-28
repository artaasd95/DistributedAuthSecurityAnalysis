"""JWT authentication helpers (intentionally vulnerable for research)."""

from typing import Any, Dict, Iterable, Optional

import jwt


class VulnerableJwtAuth:
    """Intentionally vulnerable JWT handler for security testing."""

    def __init__(self, accepted_algorithms: Optional[Iterable[str]] = None) -> None:
        self._accepted_algorithms = list(accepted_algorithms or ["none", "HS256", "RS256"])

    def extract_bearer_token(self, authorization: Optional[str]) -> str:
        """Extract a bearer token from an Authorization header value."""
        if not authorization:
            raise ValueError("Missing Authorization header.")

        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise ValueError("Invalid Authorization header.")

        return token

    def decode_unverified(self, token: str) -> Dict[str, Any]:
        """Decode a JWT without verifying its signature or claims (vulnerable)."""
        return jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_aud": False,
                "verify_iss": False,
                "verify_exp": False,
            },
            algorithms=self._accepted_algorithms,
        )
