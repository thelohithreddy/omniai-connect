"""The `oauth_states` ORM model (M2.5, ADR-0038) — the callback's only source of identity.

A provider redirect arrives unauthenticated, carrying only `code` and `state`, both of which an
attacker can influence. This row is what makes it safe: it is created *before* the redirect, by
an authenticated request, and it carries the workspace/connection the flow belongs to. The
callback looks the row up by the **hash** of the presented state, consumes it atomically, and
takes identity from the row — never from the request.

`state` is stored hashed (a database read cannot forge a callback); the PKCE `code_verifier` is
stored **sealed** by the credential vault, because RFC 7636 §4.5 requires presenting it verbatim
at the token endpoint. No `updated_at`: a row is written once and consumed once.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

# Imported for their side effect: the composite FK targets must be registered on the metadata.
from app.domains.connections import models as _connections_models  # noqa: F401
from app.shared.models import Base, UUIDPrimaryKeyMixin, WorkspaceScopedMixin


class OAuthState(UUIDPrimaryKeyMixin, WorkspaceScopedMixin, Base):
    """One in-flight authorization-code flow. Single-use, short-lived, tenant-bound."""

    __tablename__ = "oauth_states"

    connection_id: Mapped[UUID] = mapped_column(postgresql.UUID(as_uuid=True), nullable=False)
    #: SHA-256 hex of the opaque `state`. The raw value exists only in the authorize response
    #: and the provider redirect — it is never persisted and never logged.
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The PKCE code_verifier under the vault's envelope (AAD = workspace‖connection).
    verifier_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    verifier_encrypted_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    verifier_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    #: Replayed verbatim in the token request (RFC 6749 §4.1.3); never read from the callback.
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    #: Non-secret record of the scope set requested.
    scopes: Mapped[Any] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    #: Set exactly once by the atomic consume; a racing second callback finds it set and loses.
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )

    __table_args__ = (
        # Global uniqueness: the callback resolves a flow by hash alone, before any tenant
        # context exists, so the constraint cannot be workspace-scoped.
        UniqueConstraint("state_hash", name="uq_oauth_states_state_hash"),
        # A state binds a connection in the same workspace (composite intra-tenant FK): the row
        # can never reference another tenant's connection, and revoking the connection sweeps
        # its in-flight states.
        ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["connections.workspace_id", "connections.id"],
            name="fk_oauth_states_connection_id",
            ondelete="CASCADE",
        ),
        # Drives the expiry sweep, index-backed as the table grows.
        Index("ix_oauth_states_expires_at", "expires_at"),
    )


__all__ = ["OAuthState"]
