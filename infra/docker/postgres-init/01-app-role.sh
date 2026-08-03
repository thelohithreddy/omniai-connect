#!/bin/sh
# Provision the least-privileged application role for local development.
#
# POSIX sh, not bash: postgres:16-alpine is musl/BusyBox based.
#
# The app must NOT connect as a superuser or as the table owner: superusers bypass
# Row-Level Security unconditionally, and owners bypass it unless FORCE is set. Either
# would silently disable tenant isolation while every policy still looked correct
# (docs/DATABASE_DESIGN.md §6).
#
# Role creation lives here rather than in an Alembic migration because it needs a
# password, and a password in a migration is a secret committed to git (P-18). In
# staging/production the equivalent step is a runbook against the platform (Neon).
#
# Postgres runs files in /docker-entrypoint-initdb.d/ exactly once, when the data
# directory is first initialised. Re-run locally with: make db-reset
set -eu

APP_DB_USER="${APP_DB_USER:-omniai_app}"
APP_DB_PASSWORD="${APP_DB_PASSWORD:-omniai_app}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_user="$APP_DB_USER" -v app_password="'$APP_DB_PASSWORD'" <<'EOSQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %s', :'app_user', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user')
\gexec

-- Connect only. Table privileges are granted by the migration that creates each table,
-- so a new table is unreadable by the app until its migration says otherwise.
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'app_user')
\gexec

-- Explicitly NOT granted: SUPERUSER, BYPASSRLS, CREATEDB, CREATEROLE, or ownership of
-- anything. This role's entire purpose is to be constrained by RLS.
EOSQL

echo "postgres-init: role '${APP_DB_USER}' ready (non-superuser, non-owner)"
