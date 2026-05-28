"""JWT helper utilities for the test suite."""

from __future__ import annotations

from typing import Any, Dict

import jwt


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
