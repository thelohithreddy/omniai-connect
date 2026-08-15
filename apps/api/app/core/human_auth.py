"""Human identity: Better Auth JWT verification against the published JWKS (ADR-0015).

This is the *human* half of the two identity planes (ADR-0002). The machine half —
workspace-scoped API tokens — lives in `core/security.py` and is untouched by this module.
`get_workspace_context` discriminates between the two by credential shape and calls
`resolve_human_subject` here for anything that is not an `omc_` token.

The trust chain is deliberately short:

    configured JWKS URL → Ed25519 public key (selected by `kid`)
    → signature over the presented JWT
    → pinned issuer/audience/lifetime claims
    → the `sub` claim, and nothing else

`sub` is the only output. Every other claim — including the PII Better Auth embeds
(`email`, `name`) and anything a future plugin might add — is discarded here and confers
nothing. Role and permissions come from the persisted membership row, read under RLS by
the existing `resolve_member_role`; a JWT cannot carry authorization (ADR-0015 §11).

**Every validation failure is the same failure.** Malformed token, unknown `kid`, bad
signature, wrong issuer, wrong audience, expiry, and JWKS unavailability all raise the one
`UnauthorizedError` with `HUMAN_AUTH_FAILED`. Distinguishing them in the response would
hand an attacker an oracle for *why* their forgery failed; the distinction lives in
structured log events instead — event names only, never token material.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import NoReturn

import httpx
import jwt
import structlog

from app.core.config import settings
from app.core.exceptions import UnauthorizedError

log = structlog.get_logger(__name__)

# One message for every human credential failure, mirroring the machine plane's
# "Invalid or revoked API token." precedent (ADR-0015 §10).
HUMAN_AUTH_FAILED = "Invalid or expired credentials."

# The observed provider contract (ADR-0015): Better Auth's jwt() plugin signs EdDSA and
# nothing else. A tuple, not a list, so nothing can append to it at runtime.
ALLOWED_ALGORITHMS: tuple[str, ...] = ("EdDSA",)

# exp/iat/sub prove freshness and subject; iss/aud prove the token was minted by OUR
# provider FOR our deployment rather than by any other Better Auth instance whose JWKS
# an attacker controls. `nbf` is validated when present but not required — the provider
# does not emit it (observed, recorded in ADR-0015 §4).
REQUIRED_CLAIMS: tuple[str, ...] = ("exp", "iat", "sub", "iss", "aud")

# 30 s absorbs real NTP skew between containers/platforms without materially extending
# the 900 s token lifetime (ADR-0015 §4).
JWT_LEEWAY_SECONDS = 30.0

# Cache policy (ADR-0015 §6). TTL bounds how long a *removed* key keeps verifying — key
# removal is the revocation lever. The cooldown bounds attacker-driven amplification:
# unknown `kid`s force at most one fetch per cooldown window, process-wide. The fetch
# timeout follows the readiness-probe precedent (ADR-0013).
JWKS_CACHE_TTL_SECONDS = 300.0
JWKS_REFRESH_COOLDOWN_SECONDS = 30.0
JWKS_FETCH_TIMEOUT_SECONDS = 2.0


@dataclass
class JWKSCache:
    """Bounded, single-flight cache of the provider's public signing keys.

    The URL comes exclusively from configuration. Nothing a caller sends — not `jku`,
    not `x5u`, not an embedded key — can change where keys come from; the only
    caller-influenced input is the `kid` used to select among already-fetched keys.

    Failure posture (ADR-0015 §6): a process that has *never* fetched keys fails closed;
    a process whose refresh fails keeps serving the last-good keys with a warning. Public
    keys are not secrets and do not expire — dropping them on a control-plane blip would
    convert that blip into a human-auth outage, while serving them stale only delays the
    rotation-revocation lever by the outage duration.
    """

    url: str
    # Injectable for tests only (httpx.MockTransport); None means real HTTP.
    transport: httpx.AsyncBaseTransport | None = None

    _keys: dict[str, jwt.PyJWK] = field(default_factory=dict)
    _fetched_at: float | None = None
    _last_attempt_at: float | None = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def key_for(self, kid: str) -> jwt.PyJWK | None:
        """The verification key named by `kid`, or None if no such trusted key exists.

        Refreshes when the cache is cold, expired, or does not know `kid` — the
        unknown-`kid` case is what makes key rotation work without a restart. All three
        are gated by the same cooldown so a flood of garbage `kid`s cannot become a
        fetch-per-request amplifier against the control plane.
        """
        now = time.monotonic()
        fresh = self._fetched_at is not None and now - self._fetched_at < JWKS_CACHE_TTL_SECONDS
        if fresh and kid in self._keys:
            return self._keys[kid]

        async with self._lock:
            # Re-check under the lock: a concurrent caller may have refreshed while this
            # one waited, which is the whole point of single-flight.
            now = time.monotonic()
            fresh = self._fetched_at is not None and now - self._fetched_at < JWKS_CACHE_TTL_SECONDS
            attempted_recently = (
                self._last_attempt_at is not None
                and now - self._last_attempt_at < JWKS_REFRESH_COOLDOWN_SECONDS
            )
            if (not fresh or kid not in self._keys) and not attempted_recently:
                await self._refresh()
            return self._keys.get(kid)

    async def _refresh(self) -> None:
        """Fetch and replace the key set. Failures keep the previous keys."""
        self._last_attempt_at = time.monotonic()
        try:
            async with httpx.AsyncClient(
                transport=self.transport, timeout=JWKS_FETCH_TIMEOUT_SECONDS
            ) as client:
                response = await client.get(self.url)
                response.raise_for_status()
                document = response.json()
            keys = self._parse(document)
        except Exception as exc:
            # The URL is configuration, not secret — but the exception is reduced to its
            # class name so a response body can never smuggle content into the log.
            log.warning(
                "human_auth.jwks_refresh_failed",
                url=self.url,
                error=type(exc).__name__,
                serving_cached_keys=bool(self._keys),
            )
            return

        self._keys = keys
        self._fetched_at = time.monotonic()
        log.info("human_auth.jwks_refreshed", url=self.url, key_count=len(keys))

    def _parse(self, document: object) -> dict[str, jwt.PyJWK]:
        """Keys from a JWKS document, keeping only what the allowlist can ever use.

        A key with the wrong `kty`/`alg`, a missing `kid`, or malformed material is
        skipped, not fatal: one bad entry must not take down the good keys next to it.
        An entirely malformed document raises, so `_refresh` treats it as a failed fetch.
        """
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise ValueError("JWKS document does not have the {keys: [...]} shape")

        keys: dict[str, jwt.PyJWK] = {}
        for entry in document["keys"]:
            if not isinstance(entry, dict):
                continue
            kid = entry.get("kid")
            if not isinstance(kid, str) or not kid:
                # A key a verifier cannot select by kid is a key this verifier never uses.
                continue
            if entry.get("kty") != "OKP" or entry.get("alg") not in ALLOWED_ALGORITHMS:
                continue
            try:
                keys[kid] = jwt.PyJWK(entry)
            except Exception as exc:
                # Deliberately total. PyJWK raises PyJWKError for a bad structure but
                # InvalidKeyError — a different branch of the exception tree — for bad key
                # material, and base64 problems can surface as binascii.Error. Which class
                # a given malformation raises is an implementation detail of the library;
                # what is NOT negotiable is that one unparseable entry must never poison
                # the trusted keys next to it. Found by the test that feeds a garbage `x`
                # alongside a good key: a narrow except let the whole document fail.
                log.debug("human_auth.jwks_key_skipped", kid=kid, error=type(exc).__name__)
                continue
        return keys


# Module singleton, created lazily so importing this module never performs IO and tests
# can replace it wholesale. `get_jwks_cache` is a FastAPI dependency precisely so tests
# override it via `app.dependency_overrides` (BACKEND_SPEC §3) instead of patching.
_cache: JWKSCache | None = None


def get_jwks_cache() -> JWKSCache:
    global _cache
    if _cache is None:
        _cache = JWKSCache(url=settings.resolved_jwks_url)
    return _cache


def reset_jwks_cache() -> None:
    """Drop the singleton. Test isolation only — asyncio primitives must not cross loops."""
    global _cache
    _cache = None


@dataclass(frozen=True, slots=True)
class HumanIdentity:
    """A verified human's identity claims.

    `sub` is the permanent, authoritative identity (the value `members.user_id` stores).
    `email` and `email_verified` are the ONE narrow exception to ADR-0015's "claims confer
    nothing" rule, ratified for M1.3-F (ADR-0017 §3): they exist solely so the invitation
    acceptance path can bind an invitation to the accepting person. They never inform role,
    permission, workspace, or member identity — `email` is a *matching* value, never
    authority. Every path that only needs the subject uses `resolve_human_subject`, which
    returns `sub` alone and never surfaces these.
    """

    sub: str
    email: str | None
    email_verified: bool


async def _verify(token: str, cache: JWKSCache) -> dict[str, object]:
    """Cryptographically verify a Better Auth JWT and return its claims, or raise 401.

    The single verification path shared by `resolve_human_subject` and
    `resolve_human_identity`. The failure mapping is deliberately total: *any* `PyJWTError`
    — malformed segments, bad base64, invalid JSON, disallowed algorithm, bad signature,
    expired, wrong issuer/audience, missing claims — becomes the one uniform
    UnauthorizedError. No error class escapes as a 500; an auth endpoint that a crafted
    token can crash is an availability oracle.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        _reject("malformed_token")

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        _reject("missing_kid")

    key = await cache.key_for(kid)
    if key is None:
        _reject("unknown_kid")

    try:
        claims: dict[str, object] = jwt.decode(
            token,
            key=key,
            algorithms=list(ALLOWED_ALGORITHMS),
            issuer=settings.better_auth_url,
            audience=settings.better_auth_url,
            leeway=JWT_LEEWAY_SECONDS,
            options={"require": list(REQUIRED_CLAIMS)},
        )
    except jwt.PyJWTError as exc:
        _reject(type(exc).__name__)

    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        # `require` proves presence, not shape; a numeric or empty sub matches no member
        # and is rejected here rather than being coerced into a lookup value.
        _reject("invalid_sub")

    return claims


async def resolve_human_subject(token: str, cache: JWKSCache) -> str:
    """Verify a Better Auth JWT and return its `sub`. Everything else raises 401."""
    claims = await _verify(token, cache)
    return str(claims["sub"])


async def resolve_human_identity(token: str, cache: JWKSCache) -> HumanIdentity:
    """Verify a Better Auth JWT and return `sub` plus the email-binding claims (ADR-0017 §3).

    Used ONLY by invitation acceptance. `email_verified` defaults to False for any shape
    that is not exactly the boolean `true`, so a missing, string, or absent claim can never
    pass an acceptance's verified-email gate — fail closed. The email is lower-cased and
    stripped here so the caller compares normalized values.
    """
    claims = await _verify(token, cache)
    raw_email = claims.get("email")
    email = raw_email.strip().lower() if isinstance(raw_email, str) and raw_email.strip() else None
    # Better Auth emits `emailVerified` (camelCase). Only the boolean `true` passes; a
    # missing/string/None claim is treated as unverified — fail closed.
    return HumanIdentity(
        sub=str(claims["sub"]),
        email=email,
        email_verified=claims.get("emailVerified") is True,
    )


def _reject(reason: str) -> NoReturn:
    """Log the stage that failed — never the token — and raise the uniform 401."""
    log.debug("human_auth.rejected", reason=reason)
    raise UnauthorizedError(HUMAN_AUTH_FAILED)
