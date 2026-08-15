"""Token generation and hashing. Pure logic — no database, no event loop."""

from __future__ import annotations

import hashlib

import pytest
from starlette.requests import Request

from app.core.exceptions import UnauthorizedError
from app.core.security import (
    PREFIX_DISPLAY_LEN,
    TOKEN_PREFIX,
    extract_bearer_token,
    generate_token,
    hash_token,
)


def _request(*authorization_values: str) -> Request:
    """A minimal ASGI request carrying zero or more `Authorization` header lines."""
    headers = [(b"authorization", value.encode()) for value in authorization_values]
    return Request({"type": "http", "headers": headers})


def test_generated_token_is_prefixed_and_unguessable() -> None:
    token = generate_token()
    assert token.plaintext.startswith(TOKEN_PREFIX)
    # 32 random bytes → 43 base64url chars, plus the 4-char marker.
    assert len(token.plaintext) >= 40


def test_tokens_are_unique() -> None:
    assert len({generate_token().plaintext for _ in range(500)}) == 500


def test_hash_is_sha256_of_plaintext() -> None:
    token = generate_token()
    assert token.token_hash == hashlib.sha256(token.plaintext.encode()).hexdigest()
    assert len(token.token_hash) == 64


def test_hash_is_deterministic() -> None:
    """Lookup is by hash equality, so the same input must always produce the same digest."""
    assert hash_token("omc_example") == hash_token("omc_example")
    assert hash_token("omc_example") != hash_token("omc_example ")


def test_prefix_is_display_only_and_reveals_nothing_usable() -> None:
    token = generate_token()
    assert token.token_prefix == token.plaintext[:PREFIX_DISPLAY_LEN]
    assert len(token.token_prefix) == PREFIX_DISPLAY_LEN
    # The stored fragment must not be enough to reconstruct the secret.
    assert token.token_prefix != token.plaintext
    assert hash_token(token.token_prefix) != token.token_hash


def test_plaintext_never_appears_in_the_hash() -> None:
    """A one-way digest: DB disclosure must not yield working credentials."""
    token = generate_token()
    assert token.plaintext not in token.token_hash


# --- extract_bearer_token: one credential, fail-closed on ambiguity (M1.3-G, ADR-0016 §3) ---


def test_missing_authorization_is_rejected() -> None:
    with pytest.raises(UnauthorizedError, match="Missing Authorization header"):
        extract_bearer_token(_request())


def test_a_single_bearer_credential_is_returned_verbatim() -> None:
    assert extract_bearer_token(_request("Bearer omc_abc123")) == "omc_abc123"
    # Scheme is case-insensitive; surrounding whitespace on the credential is trimmed.
    assert extract_bearer_token(_request("bearer   tok  ")) == "tok"


def test_a_non_bearer_or_empty_scheme_is_rejected() -> None:
    for bad in ("Basic dXNlcjpwYXNz", "Bearer", "Bearer    ", "omc_no_scheme"):
        with pytest.raises(UnauthorizedError, match="must be 'Bearer <token>'"):
            extract_bearer_token(_request(bad))


def test_duplicate_authorization_headers_are_rejected_not_silently_resolved() -> None:
    """The core M1.3-G hardening: two `Authorization` lines never silently bind the first.

    `Headers.get()` would return whichever the framework/proxy ordered first, so a
    `Bearer <valid>` smuggled alongside `Bearer <attacker>` could bind either. Rejecting the
    ambiguity outright is the same fail-closed rule ADR-0016 §3 already applies to
    `X-Workspace-Id`. Order-independent: neither the valid-first nor valid-second arrangement
    is accepted, and two identical values are still two headers.
    """
    for a, b in (
        ("Bearer omc_valid", "Bearer garbage"),
        ("Bearer garbage", "Bearer omc_valid"),
        ("Bearer omc_valid", "Bearer omc_valid"),
    ):
        with pytest.raises(UnauthorizedError, match="single Authorization header"):
            extract_bearer_token(_request(a, b))
