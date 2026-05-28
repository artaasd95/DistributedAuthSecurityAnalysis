"""PKCE S256 helper snippet for client applications."""

from __future__ import annotations

import base64
import hashlib
import secrets


def generate_code_verifier(length: int = 64) -> str:
    """Generate a high-entropy code_verifier string."""
    return secrets.token_urlsafe(length)[:length]


def generate_code_challenge(code_verifier: str) -> str:
    """Create a Base64 URL-safe SHA-256 code_challenge from the verifier."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


if __name__ == "__main__":
    verifier = generate_code_verifier()
    challenge = generate_code_challenge(verifier)
    print(f"code_verifier: {verifier}")
    print(f"code_challenge: {challenge}")
