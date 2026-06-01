"""Unit tests for helper utilities used by the security test suite."""

from __future__ import annotations

import jwt

from tests.helpers import (
    forge_alg_none_token,
    generate_code_challenge,
    generate_code_verifier,
)


def test_generate_code_verifier_respects_requested_length() -> None:
    verifier = generate_code_verifier(length=64)

    assert len(verifier) == 64


def test_generate_code_challenge_is_urlsafe_and_deterministic() -> None:
    verifier = "test-verifier-123"
    challenge_1 = generate_code_challenge(verifier)
    challenge_2 = generate_code_challenge(verifier)

    assert challenge_1 == challenge_2
    assert "+" not in challenge_1
    assert "/" not in challenge_1
    assert "=" not in challenge_1


def test_forge_alg_none_token_sets_role_and_none_algorithm() -> None:
    token = jwt.encode({"sub": "user-1", "role": "user"}, key="secret", algorithm="HS256")
    forged = forge_alg_none_token(token, role="admin")

    header = jwt.get_unverified_header(forged)
    payload = jwt.decode(
        forged,
        options={
            "verify_signature": False,
            "verify_aud": False,
            "verify_iss": False,
            "verify_exp": False,
        },
        algorithms=["none", "HS256", "RS256"],
    )

    assert header.get("alg") == "none"
    assert payload.get("role") == "admin"
