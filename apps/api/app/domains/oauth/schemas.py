"""Wire schemas for the OAuth surface (M2.5, ADR-0038).

Security by omission, exactly as the credentials domain does it: the authorize response carries
the provider URL and an expiry and **nothing else** — no `state`, no `code_verifier`, no
`code_challenge`, no client secret, no token. The raw `state` does travel inside `authorize_url`
(the provider requires it), but it is never a standalone field a client could log, store, or
replay independently, and it is never persisted in the clear.

There is no request body: the Connection comes from the path and the workspace from the
authenticated context, so nothing a client sends can establish tenant authority.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AuthorizeStartRead(BaseModel):
    """The response of starting an authorization: where to send the browser, and until when."""

    authorize_url: str = Field(
        description="Provider authorization URL. Redirect the user agent here; it expires."
    )
    expires_at: datetime = Field(
        description="When this in-flight authorization stops being redeemable (RFC 3339 UTC)."
    )


__all__ = ["AuthorizeStartRead"]
