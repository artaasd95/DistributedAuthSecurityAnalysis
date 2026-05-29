"""JWT helper utilities for the test suite."""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any, Dict

import jwt


def generate_code_verifier(length: int = 64) -> str:
    """Generate a high-entropy PKCE code_verifier string."""
    return secrets.token_urlsafe(length)[:length]


def generate_code_challenge(code_verifier: str) -> str:
    """Create a Base64 URL-safe SHA-256 code_challenge from the verifier."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _strip_signature(token: str) -> str:
    """Remove the signature part of a JWT, leaving a trailing dot."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format.")
    return f"{parts[0]}.{parts[1]}."


def forge_alg_none_token(token: str, role: str = "admin") -> str:
    """Forge a JWT with alg=none and a modified role claim."""
    payload: Dict[str, Any] = jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_aud": False,
            "verify_iss": False,
            "verify_exp": False,
        },
        algorithms=["none", "HS256", "RS256"],
    )
    payload["role"] = role

    header = jwt.get_unverified_header(token)
    header["alg"] = "none"

    unsigned = jwt.encode(payload, key=None, algorithm="none", headers=header)
    return _strip_signature(unsigned)
