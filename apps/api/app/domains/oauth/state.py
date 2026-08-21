"""State and PKCE primitives for the authorization-code flow (M2.5, ADR-0038).

Pure functions over `secrets` + `hashlib` — no IO, no DB, no policy. Two values are generated
per flow and neither is ever logged, echoed, or persisted in the clear:

- **`state`** (RFC 6749 §10.12) — an opaque CSPRNG value returned by the provider. Persisted as
  a **SHA-256 hash** so a database read cannot forge a callback; the raw value exists only in
  the authorize URL and the provider's redirect. This mirrors how `api_tokens` stores a hash.
- **`code_verifier` / `code_challenge`** (RFC 7636) — the proof-of-possession that replaces a
  client secret for a public client. **S256 only**: `plain` is not generated and not accepted,
  so a downgrade has nothing to fall back to.

Verifier length: 96 random bytes → 128 base64url characters, the RFC 7636 §4.1 maximum
(43–128), maximizing entropy within the legal range.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Final

#: RFC 7636 §4.2 — the only challenge method this server generates or accepts.
CODE_CHALLENGE_METHOD: Final = "S256"

_STATE_BYTES: Final = 32  # 256 bits of entropy
_VERIFIER_BYTES: Final = 96  # → 128 base64url chars, the RFC 7636 §4.1 maximum


def _b64url(raw: bytes) -> str:
    """base64url without padding (RFC 7636 §A: the unreserved-character encoding)."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def generate_state() -> str:
    """An opaque, unguessable CSPRNG state value."""
    return _b64url(secrets.token_bytes(_STATE_BYTES))


def hash_state(state: str) -> str:
    """The stored form of a state value: SHA-256 hex. The raw state is never persisted.

    Used both to write the row and to look it up at callback time, so an attacker who can read
    `oauth_states` still cannot produce a state the provider redirect would satisfy.
    """
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def generate_code_verifier() -> str:
    """A high-entropy PKCE `code_verifier` (RFC 7636 §4.1)."""
    return _b64url(secrets.token_bytes(_VERIFIER_BYTES))


def derive_code_challenge(verifier: str) -> str:
    """`S256` challenge for a verifier: base64url(SHA-256(verifier)) (RFC 7636 §4.2)."""
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


@dataclass(frozen=True, repr=False, slots=True)
class FlowSecrets:
    """The per-flow secrets. `repr` is redacted so they can never surface in a log or traceback."""

    state: str
    code_verifier: str
    code_challenge: str

    def __repr__(self) -> str:  # never leak state/verifier through repr / f-strings / tracebacks
        return "<FlowSecrets redacted>"


def new_flow_secrets() -> FlowSecrets:
    """Generate one flow's `state`, `code_verifier`, and derived S256 `code_challenge`."""
    verifier = generate_code_verifier()
    return FlowSecrets(
        state=generate_state(),
        code_verifier=verifier,
        code_challenge=derive_code_challenge(verifier),
    )


__all__ = [
    "CODE_CHALLENGE_METHOD",
    "FlowSecrets",
    "derive_code_challenge",
    "generate_code_verifier",
    "generate_state",
    "hash_state",
    "new_flow_secrets",
]
