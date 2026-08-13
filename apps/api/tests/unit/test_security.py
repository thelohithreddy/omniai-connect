"""Token generation and hashing. Pure logic — no database, no event loop."""

from __future__ import annotations

import hashlib

from app.core.security import (
    PREFIX_DISPLAY_LEN,
    TOKEN_PREFIX,
    generate_token,
    hash_token,
)


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
