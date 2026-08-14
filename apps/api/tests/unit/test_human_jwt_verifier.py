"""The negative matrix for human JWT verification (M1.3-B, ADR-0015).

Every test here drives the REAL verifier — `resolve_human_subject` and `JWKSCache` — over
genuine Ed25519 cryptography. The only double is the JWKS *endpoint* (an in-process
MockTransport), which is the seam the cache exposes by design. Nothing about signature
verification, claim validation, or failure mapping is mocked, because a mocked verifier
proves nothing about the one property this module exists for: that forged, tampered,
expired, or misdirected tokens do not authenticate.

Structure follows the attack surface:
  1. the happy path (the control every negative needs)
  2. token structure  — malformed inputs of every shape
  3. signature        — wrong keys, tampering, stripped signatures
  4. algorithm        — none, confusion, unsupported
  5. claims           — each required claim absent, wrong, or expired
  6. key resolution   — kid games, attacker-controlled locations
  7. JWKS transport   — outages, malformed documents, cache behavior, amplification
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from typing import Any

import pytest

from app.core import human_auth
from app.core.config import settings
from app.core.exceptions import UnauthorizedError
from app.core.human_auth import (
    HUMAN_AUTH_FAILED,
    JWKS_REFRESH_COOLDOWN_SECONDS,
    JWKSCache,
    resolve_human_subject,
)
from tests.conftest import FakeJWKSEndpoint, SigningAuthority

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def rewrite_segment(token: str, index: int, mutate: dict[str, Any]) -> str:
    """Re-encode one JWT segment with `mutate` applied, keeping the original signature."""
    parts = token.split(".")
    raw = parts[index] + "=" * (-len(parts[index]) % 4)
    decoded = json.loads(base64.urlsafe_b64decode(raw))
    decoded.update(mutate)
    parts[index] = b64url(json.dumps(decoded, separators=(",", ":")).encode())
    return ".".join(parts)


async def expect_rejection(token: str, cache: JWKSCache) -> None:
    """The one acceptable failure: canonical 401, uniform message, no other exception."""
    with pytest.raises(UnauthorizedError) as excinfo:
        await resolve_human_subject(token, cache)
    assert excinfo.value.message == HUMAN_AUTH_FAILED
    assert excinfo.value.http_status == 401


# ---------------------------------------------------------------------------------------
# 0. Configuration invariants (defense in depth)
# ---------------------------------------------------------------------------------------


def test_allowlist_and_required_claims_are_pinned() -> None:
    """Pin the security-critical constants directly.

    The behavioral tests below prove alg-confusion is rejected, but a PyJWK key object
    binds the algorithm to EdDSA independently — so widening `ALLOWED_ALGORITHMS` in source
    does not, on its own, change observable behavior (a mutation testing found exactly this:
    adding "none"/"HS256" is inert against the running verifier because the key binding is a
    second gate). That defense-in-depth is good, but it must not let the allowlist silently
    rot: this asserts the layer directly, so widening it is a failing test even though the
    key binding would still hold.
    """
    from app.core.human_auth import ALLOWED_ALGORITHMS, REQUIRED_CLAIMS

    assert ALLOWED_ALGORITHMS == ("EdDSA",)
    assert set(REQUIRED_CLAIMS) == {"exp", "iat", "sub", "iss", "aud"}


# ---------------------------------------------------------------------------------------
# 1. Control
# ---------------------------------------------------------------------------------------


async def test_a_valid_token_resolves_to_its_subject(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """The control for the whole file: with everything right, verification succeeds.

    Without this, every negative below is ambiguous — a verifier that rejects *all*
    tokens would pass the entire matrix.
    """
    token = authority.sign("human-42")
    assert await resolve_human_subject(token, jwks_endpoint.cache()) == "human-42"


async def test_extra_unknown_claims_do_not_break_verification(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """Better Auth embeds email/name/etc.; the verifier must tolerate and ignore them."""
    token = authority.sign(
        "human-42", email="x@example.test", name="X", role="owner", workspace_id="w"
    )
    assert await resolve_human_subject(token, jwks_endpoint.cache()) == "human-42"


# ---------------------------------------------------------------------------------------
# 2. Token structure
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "broken",
    [
        "",  # empty
        "just-a-string",  # no dots
        "a.b",  # two segments
        "a.b.c.d",  # four segments
        "!!!.???.###",  # not base64
        "Zm9v.Zm9v.Zm9v",  # base64 but not JSON
        "bearer omc_notajwt",  # something machine-shaped smuggled here
    ],
)
async def test_malformed_tokens_are_rejected(broken: str, jwks_endpoint: FakeJWKSEndpoint) -> None:
    await expect_rejection(broken, jwks_endpoint.cache())


async def test_valid_json_header_with_invalid_json_claims_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    token = authority.sign()
    parts = token.split(".")
    parts[1] = b64url(b"this is not json {")
    await expect_rejection(".".join(parts), jwks_endpoint.cache())


# ---------------------------------------------------------------------------------------
# 3. Signature
# ---------------------------------------------------------------------------------------


async def test_a_token_signed_by_a_different_key_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """The forger's key claims the trusted kid; only the signature gives it away."""
    forger = SigningAuthority(kid=authority.kid)
    await expect_rejection(forger.sign(), jwks_endpoint.cache())


async def test_a_tampered_payload_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    token = rewrite_segment(authority.sign("victim"), 1, {"sub": "attacker"})
    await expect_rejection(token, jwks_endpoint.cache())


async def test_a_tampered_header_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    # Bit-flip the header while keeping it valid JSON: signature covers it, so it dies.
    token = rewrite_segment(authority.sign(), 0, {"typ": "SPOOF"})
    await expect_rejection(token, jwks_endpoint.cache())


async def test_a_stripped_signature_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    header, payload, _ = authority.sign().split(".")
    await expect_rejection(f"{header}.{payload}.", jwks_endpoint.cache())


# ---------------------------------------------------------------------------------------
# 4. Algorithm
# ---------------------------------------------------------------------------------------


async def test_alg_none_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """The classic: an unsigned token whose header says nothing needs verifying."""
    now = int(time.time())
    claims = {
        "sub": "attacker",
        "iss": settings.better_auth_url,
        "aud": settings.better_auth_url,
        "iat": now,
        "exp": now + 900,
    }
    header = b64url(json.dumps({"alg": "none", "kid": authority.kid}).encode())
    payload = b64url(json.dumps(claims).encode())
    await expect_rejection(f"{header}.{payload}.", jwks_endpoint.cache())


async def test_hmac_algorithm_confusion_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """HS256 'signed' with the public key bytes as the shared secret.

    The historical JWT-library kill shot (CVE-2015-9235 class, and PyJWT's own
    CVE-2022-29217): if the verifier lets the token pick the algorithm family, the public
    key becomes an HMAC secret the attacker also knows. The pinned allowlist must refuse
    before any key material is used.
    """
    import hashlib
    import hmac as hmac_mod

    now = int(time.time())
    claims = {
        "sub": "attacker",
        "iss": settings.better_auth_url,
        "aud": settings.better_auth_url,
        "iat": now,
        "exp": now + 900,
    }
    header = b64url(json.dumps({"alg": "HS256", "kid": authority.kid}).encode())
    payload = b64url(json.dumps(claims).encode())
    secret = authority.jwk["x"].encode()  # the "known to everyone" public material
    mac = hmac_mod.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    await expect_rejection(f"{header}.{payload}.{b64url(mac)}", jwks_endpoint.cache())


async def test_every_non_eddsa_algorithm_header_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    for alg in ("RS256", "ES256", "PS256", "HS512"):
        header = b64url(json.dumps({"alg": alg, "kid": authority.kid}).encode())
        _, payload, signature = authority.sign().split(".")
        await expect_rejection(f"{header}.{payload}.{signature}", jwks_endpoint.cache())


# ---------------------------------------------------------------------------------------
# 5. Claims
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("claim", ["exp", "iat", "sub", "iss", "aud"])
async def test_each_missing_required_claim_is_rejected(
    claim: str, authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    await expect_rejection(authority.sign(drop=(claim,)), jwks_endpoint.cache())


async def test_an_expired_token_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    now = int(time.time())
    token = authority.sign(iat=now - 2000, exp=now - 1000)
    await expect_rejection(token, jwks_endpoint.cache())


async def test_expiry_just_inside_leeway_is_accepted(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """Pins the leeway to ~30 s: a token 10 s past exp verifies, one 60 s past does not.

    Together with the rejection above this brackets the constant — a mutation that zeroes
    the leeway breaks this test, one that widens it to minutes breaks the next.
    """
    now = int(time.time())
    ten_past = authority.sign(iat=now - 900, exp=now - 10)
    assert await resolve_human_subject(ten_past, jwks_endpoint.cache())


async def test_expiry_beyond_leeway_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    now = int(time.time())
    sixty_past = authority.sign(iat=now - 900, exp=now - 60)
    await expect_rejection(sixty_past, jwks_endpoint.cache())


async def test_a_future_nbf_is_rejected_and_a_present_valid_nbf_accepted(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """The provider emits no nbf, but a token carrying one must still have it honored."""
    now = int(time.time())
    not_yet = authority.sign(nbf=now + 3600)
    await expect_rejection(not_yet, jwks_endpoint.cache())
    already = authority.sign(nbf=now - 60)
    assert await resolve_human_subject(already, jwks_endpoint.cache())


async def test_a_non_numeric_iat_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    await expect_rejection(authority.sign(iat="yesterday"), jwks_endpoint.cache())


async def test_wrong_issuer_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """A token from a *different* Better Auth deployment — validly signed by a key this
    JWKS even publishes — must still fail: our issuer pin is what makes 'any Better Auth
    instance an attacker can stand up' not a credential mint for this API."""
    token = authority.sign(iss="https://evil-but-real-better-auth.example")
    await expect_rejection(token, jwks_endpoint.cache())


async def test_wrong_audience_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    token = authority.sign(aud="https://some-other-consumer.example")
    await expect_rejection(token, jwks_endpoint.cache())


@pytest.mark.parametrize("bad_sub", ["", 12345, None, ["u1"], {"id": "u1"}])
async def test_non_string_or_empty_sub_is_rejected(
    bad_sub: object, authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    await expect_rejection(authority.sign(bad_sub), jwks_endpoint.cache())


# ---------------------------------------------------------------------------------------
# 6. Key resolution
# ---------------------------------------------------------------------------------------


async def test_a_missing_kid_header_is_rejected(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    import jwt as pyjwt

    now = int(time.time())
    token = pyjwt.encode(
        {
            "sub": "u",
            "iss": settings.better_auth_url,
            "aud": settings.better_auth_url,
            "iat": now,
            "exp": now + 900,
        },
        authority.signer,
        algorithm="EdDSA",
        # No kid at all: a verifier that "just tries every key" would accept this.
    )
    await expect_rejection(token, jwks_endpoint.cache())


async def test_an_unknown_kid_is_rejected_after_one_refresh(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    token = authority.sign(headers={"kid": "no-such-key"})
    cache = jwks_endpoint.cache()
    await expect_rejection(token, cache)
    # It *did* check upstream once — that is the rotation path — and only once.
    assert jwks_endpoint.calls == 1


async def test_attacker_supplied_jku_and_x5u_are_ignored(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """A forged token pointing at an attacker-hosted key set via jku/x5u/embedded jwk.

    The resolver's key source is the configured URL and nothing else, so these headers
    must be dead weight: the token still fails on signature, and no fetch of the
    attacker's URL is ever attempted (the fake endpoint's counter would not show it, but
    the rejection itself proves the attacker's key was never used to verify).
    """
    forger = SigningAuthority(kid=authority.kid)
    token = forger.sign(
        headers={
            "jku": "https://attacker.example/jwks",
            "x5u": "https://attacker.example/cert.pem",
            "jwk": forger.jwk,
        }
    )
    await expect_rejection(token, jwks_endpoint.cache())


async def test_key_rotation_new_kid_is_picked_up_on_refresh(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """The provider rotates: a new key signs, the old document is cached and expired."""
    cache = jwks_endpoint.cache()
    assert await resolve_human_subject(authority.sign(), cache)  # warm with key 1

    successor = SigningAuthority(kid="rotated-key-2")
    jwks_endpoint.document = {"keys": [authority.jwk, successor.jwk]}

    # Within the cooldown the new kid is unknown and refresh is suppressed — fail closed.
    await expect_rejection(successor.sign(), cache)

    # Once the cooldown passes, the unknown kid forces the refresh and rotation lands.
    cache._last_attempt_at = time.monotonic() - JWKS_REFRESH_COOLDOWN_SECONDS - 1
    assert await resolve_human_subject(successor.sign(), cache)


# ---------------------------------------------------------------------------------------
# 7. JWKS transport and cache
# ---------------------------------------------------------------------------------------


async def test_jwks_unavailable_with_cold_cache_fails_closed(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    jwks_endpoint.mode = "timeout"
    await expect_rejection(authority.sign(), jwks_endpoint.cache())


async def test_jwks_http_error_with_cold_cache_fails_closed(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    jwks_endpoint.mode = "http_error"
    await expect_rejection(authority.sign(), jwks_endpoint.cache())


@pytest.mark.parametrize("mode", ["not_json", "wrong_shape"])
async def test_a_malformed_jwks_document_fails_closed(
    mode: str, authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    jwks_endpoint.mode = mode
    await expect_rejection(authority.sign(), jwks_endpoint.cache())


async def test_jwks_outage_after_warmup_serves_cached_keys(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """Stale-on-error (ADR-0015 §6): a provider blip must not log every human out."""
    cache = jwks_endpoint.cache()
    assert await resolve_human_subject(authority.sign(), cache)
    jwks_endpoint.mode = "timeout"
    # Force the TTL to expire so the next call *wants* a refresh and that refresh fails.
    cache._fetched_at = time.monotonic() - human_auth.JWKS_CACHE_TTL_SECONDS - 1
    cache._last_attempt_at = None
    assert await resolve_human_subject(authority.sign(), cache) == "user-under-test"


async def test_verification_still_fails_correctly_while_serving_stale_keys(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """Stale keys are still *keys*: forgeries keep failing during an outage."""
    cache = jwks_endpoint.cache()
    assert await resolve_human_subject(authority.sign(), cache)
    jwks_endpoint.mode = "timeout"
    cache._fetched_at = time.monotonic() - human_auth.JWKS_CACHE_TTL_SECONDS - 1
    forger = SigningAuthority(kid=authority.kid)
    await expect_rejection(forger.sign(), cache)


async def test_unknown_kid_flood_is_amplification_bounded(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """Fifty garbage-kid tokens cost the provider exactly one fetch, not fifty."""
    cache = jwks_endpoint.cache()
    for i in range(50):
        await expect_rejection(authority.sign(headers={"kid": f"garbage-{i}"}), cache)
    assert jwks_endpoint.calls == 1


async def test_concurrent_cold_start_is_single_flight(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """Twenty simultaneous first requests produce one JWKS fetch, and all twenty verify."""
    cache = jwks_endpoint.cache()
    token = authority.sign("concurrent-user")
    results = await asyncio.gather(*(resolve_human_subject(token, cache) for _ in range(20)))
    assert results == ["concurrent-user"] * 20
    assert jwks_endpoint.calls == 1


async def test_warm_cache_does_not_refetch_within_ttl(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    cache = jwks_endpoint.cache()
    for _ in range(10):
        assert await resolve_human_subject(authority.sign(), cache)
    assert jwks_endpoint.calls == 1


async def test_jwks_entries_that_cannot_be_trusted_are_skipped_not_fatal(
    authority: SigningAuthority,
) -> None:
    """One good key among garbage entries still authenticates; the garbage never loads."""
    endpoint = FakeJWKSEndpoint(
        {
            "keys": [
                "not-even-an-object",
                {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA"},  # no kid
                {"kty": "RSA", "alg": "RS256", "kid": "rsa-key", "n": "AAAA", "e": "AQAB"},
                {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": "broken", "x": "!!"},
                authority.jwk,
            ]
        }
    )
    cache = endpoint.cache()
    assert await resolve_human_subject(authority.sign(), cache)
    # The RSA key must not have been loaded under its kid — wrong family, never trusted.
    assert await cache.key_for("rsa-key") is None


async def test_uniform_message_across_every_failure_class(
    authority: SigningAuthority, jwks_endpoint: FakeJWKSEndpoint
) -> None:
    """One assertion over the whole matrix: no failure class gets its own message.

    The per-test `expect_rejection` already checks this individually; this test exists so
    a future 'helpful' per-case message diff shows up as exactly one obvious failure.
    """
    now = int(time.time())
    failures = [
        "garbage",
        authority.sign(drop=("exp",)),
        authority.sign(iss="https://wrong.example"),
        authority.sign(aud="https://wrong.example"),
        authority.sign(iat=now - 2000, exp=now - 1000),
        SigningAuthority(kid=authority.kid).sign(),
        authority.sign(headers={"kid": "unknown"}),
    ]
    messages = set()
    for token in failures:
        with pytest.raises(UnauthorizedError) as excinfo:
            await resolve_human_subject(token, jwks_endpoint.cache())
        messages.add(excinfo.value.message)
    assert messages == {HUMAN_AUTH_FAILED}
