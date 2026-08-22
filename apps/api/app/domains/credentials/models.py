"""SQLAlchemy model for the credentials domain (M1-Credentials-v1, ADR-0030).

A Credential is the **radioactive** encrypted secret bound 1:1 to a Connection (Bible §4,
DATABASE_DESIGN.md §3). It stores only ciphertext material — never plaintext: `ciphertext`,
`encrypted_dek` (the per-Credential DEK wrapped by the master KEK), `nonce`, and `key_version`.
Decryption happens only inside the Execution Runtime (SECURITY.md §2.2); no soft delete —
revocation deletes the row.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

# The credential's Connection (and, through it, workspace) must be registered for the composite FK
# to resolve. Module-style import so the connections↔credentials FK cycle loads. Import-only.
import app.domains.connections.models  # noqa: F401
from app.shared.models import Base, TimestampMixin, UUIDPrimaryKeyMixin, WorkspaceScopedMixin

# Canonical credential-type domain (DATABASE_DESIGN.md §3). The DB CHECK admits all six for forward
# compatibility; the M1 application layer supports only the first three (schemas restrict it).
CREDENTIAL_TYPES = ("api_key", "bearer", "basic", "jwt", "oauth2", "custom_headers")
M1_CREDENTIAL_TYPES = ("api_key", "bearer", "basic")


class Credential(UUIDPrimaryKeyMixin, WorkspaceScopedMixin, TimestampMixin, Base):
    """An envelope-encrypted secret bound to a Connection (DATABASE_DESIGN §3, SECURITY §2)."""

    __tablename__ = "credentials"

    # 1:1 with a Connection (unique below).
    connection_id: Mapped[UUID] = mapped_column(postgresql.UUID(as_uuid=True), nullable=False)
    credential_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # AES-256-GCM ciphertext (+tag) of the secret. Never plaintext.
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # The per-Credential DEK, wrapped by the key for this row's `key_version`
    # (wrap-nonce ‖ ciphertext+tag): the master KEK itself at version 1, an HKDF-derived
    # per-workspace key at 2+ (M2.6, ADR-0039).
    encrypted_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Which KEK version wrapped the DEK — the rotation runbook's state (M2.6, ADR-0039).
    # Version 1 means M1's direct-KEK wrapping; 2+ means the DEK is wrapped by an HKDF-derived
    # per-workspace key. Indexed below: the re-wrap sweep and the retirement gate both ask
    # `key_version < target` across every tenant at once.
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # The GCM nonce for the payload encryption.
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # OAuth token expiry (drives the refresh worker, M2). NULL for api_key/bearer/basic.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Set when the credential's secret is re-sealed (rotation). NULL on first attach.
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "credential_type IN ('api_key', 'bearer', 'basic', 'jwt', 'oauth2', 'custom_headers')",
            name="credential_type_valid",
        ),
        # One credential per Connection (the 1:1 binding).
        UniqueConstraint("connection_id", name="uq_credentials_connection_id"),
        # Composite-FK target for connections.credential_id (added additively in migration 0011).
        UniqueConstraint("workspace_id", "id", name="uq_credentials_workspace_id_id"),
        # Rotation discovery + the retirement gate (migration 0014). A platform-level scan, so
        # unlike every tenant query this index cannot lead with `workspace_id`.
        Index("ix_credentials_key_version", "key_version"),
        # A credential binds a connection in the same workspace (composite intra-tenant FK).
        ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["connections.workspace_id", "connections.id"],
            name="fk_credentials_connection_id",
            ondelete="CASCADE",
        ),
    )


__all__ = ["CREDENTIAL_TYPES", "M1_CREDENTIAL_TYPES", "Credential"]
