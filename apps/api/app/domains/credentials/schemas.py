"""Pydantic request/response schemas for the credentials domain (M1-Credentials-v1).

Security by omission: the **request** carries the secret in `SecretStr` fields (masked in any repr
or accidental log), and the **response** (`CredentialRead`) has **no** secret field at all — no
ciphertext, encrypted_dek, nonce, or plaintext. `workspace_id`, `status`, `credential_id`, and
`connection_id` are never request-body fields (the connection comes from the path, the workspace
from the authenticated context), so nothing in the body can establish tenant authority or forge a
lifecycle transition.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, SecretStr, model_validator


class CredentialWrite(BaseModel):
    """The client-controlled surface of attaching/rotating a Credential (M1 types only).

    `extra="forbid"` so a server-owned field is a `400`. Exactly one secret shape per type:
    `api_key`/`bearer` carry a single `value`; `basic` carries `username` + `password`
    (CONNECTOR_SPECIFICATION §5). Secrets are `SecretStr` so they never render into logs.
    """

    model_config = ConfigDict(extra="forbid")

    credential_type: Literal["api_key", "bearer", "basic"]
    value: SecretStr | None = None  # api_key / bearer
    username: str | None = None  # basic
    password: SecretStr | None = None  # basic

    @model_validator(mode="after")
    def _shape(self) -> CredentialWrite:
        if self.credential_type in ("api_key", "bearer"):
            if self.value is None or not self.value.get_secret_value().strip():
                raise ValueError("api_key/bearer require a non-empty `value`")
            if self.username is not None or self.password is not None:
                raise ValueError("api_key/bearer must not include username/password")
        else:  # basic
            if not self.username or self.username.strip() == "":
                raise ValueError("basic requires a non-empty `username`")
            if self.password is None or not self.password.get_secret_value():
                raise ValueError("basic requires a non-empty `password`")
            if self.value is not None:
                raise ValueError("basic must not include `value`")
        return self


class CredentialRead(BaseModel):
    """A Credential's **metadata** — never its secret (SECURITY.md §2.2). No ciphertext, no DEK, no
    nonce, no plaintext, no secret-derived field."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connection_id: uuid.UUID
    credential_type: str
    key_version: int
    expires_at: datetime | None
    rotated_at: datetime | None
    created_at: datetime


__all__ = ["CredentialRead", "CredentialWrite"]
