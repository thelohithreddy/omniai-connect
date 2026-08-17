"""Alembic environment — async engine, admin role.

Migrations run as the *admin* role (`DATABASE_ADMIN_URL`), which owns the schema. The
application connects as a separate, less-privileged role that is neither superuser nor
table owner, so Row-Level Security actually applies to it (DATABASE_DESIGN.md §6).
Running migrations as the app role would either fail on DDL or, worse, make the app the
table owner and hand it an RLS bypass.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from sqlalchemy import Connection, pool
from sqlalchemy.ext.asyncio import async_engine_from_config

# Importing the domain models registers them on Base.metadata for autogenerate.
# Without this import autogenerate sees an empty schema and cheerfully drops everything.
import app.domains.connections.models  # noqa: F401
import app.domains.connectors.models  # noqa: F401
import app.domains.credentials.models  # noqa: F401
import app.domains.workspaces.models  # noqa: F401
from alembic import context
from app.core.config import settings
from app.shared.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Detect column type changes; without this, a varchar->text change is invisible.
        compare_type=True,
        compare_server_default=True,
        # Everything lives in the default schema for now; naming conventions come from
        # Base.metadata so constraint names are deterministic across autogenerate runs.
        include_schemas=False,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a DB connection (`alembic upgrade head --sql`)."""
    context.configure(
        url=settings.database_admin_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    connectable = async_engine_from_config(
        {"sqlalchemy.url": settings.database_admin_url},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_configure)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(_run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
