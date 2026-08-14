#!/usr/bin/env bash
# Provision the Better Auth identity boundary: its own role, its own schema, and no
# reach into the application's data.
#
# Better Auth is *global identity* infrastructure. Its tables are not tenant-owned, so
# they cannot live in `public`, whose stated invariant is that the only tables without
# `workspace_id` are `workspaces` itself and global reference data (DATABASE_DESIGN.md §1).
# They also cannot live in `auth`, which Alembic created for `auth.resolve_api_token` and
# which migration 0001 drops with `DROP SCHEMA auth CASCADE` on downgrade — a path CI runs
# on every push. `identity` is a third schema owned by neither of those lifecycles.
#
# The role separation is the security boundary. `omniai_app` — the least-privileged role
# the API runs as — is granted **nothing** here, not even USAGE. A compromise of the
# application's database credential therefore cannot read password hashes, sessions, or
# the JWT signing keys, and the reverse holds too: the identity role cannot read tenant
# data. That is the whole reason Better Auth was given its own schema rather than a corner
# of `public`.
set -eu

IDENTITY_DB_USER="${IDENTITY_DB_USER:-omniai_identity}"
IDENTITY_DB_PASSWORD="${IDENTITY_DB_PASSWORD:-omniai_identity}"
IDENTITY_SCHEMA="${IDENTITY_SCHEMA:-identity}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v identity_user="$IDENTITY_DB_USER" \
  -v identity_password="'$IDENTITY_DB_PASSWORD'" \
  -v identity_schema="$IDENTITY_SCHEMA" <<'EOSQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %s', :'identity_user', :'identity_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'identity_user')
\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'identity_user')
\gexec

-- Better Auth owns this schema outright: it creates, alters and migrates its own tables
-- here through its own CLI. Alembic never touches it, and it is deliberately absent from
-- every Alembic migration so that `alembic downgrade base` cannot destroy identity data.
SELECT format('CREATE SCHEMA IF NOT EXISTS %I AUTHORIZATION %I',
              :'identity_schema', :'identity_user')
\gexec

-- PUBLIC gets nothing. Postgres grants USAGE on a new schema to nobody by default, but
-- being explicit means a future `GRANT ... TO PUBLIC` elsewhere is a visible regression
-- rather than a silent one.
SELECT format('REVOKE ALL ON SCHEMA %I FROM PUBLIC', :'identity_schema')
\gexec

-- Explicitly NOT granted to the application role: USAGE, SELECT, or anything else on
-- `identity`. The API has no reason to read identity tables — it resolves a human by the
-- `sub` claim of a verified JWT (M1.3-B), never by querying Better Auth's storage.
EOSQL

echo "postgres-init: role '${IDENTITY_DB_USER}' and schema '${IDENTITY_SCHEMA}' ready (no omniai_app access)"
