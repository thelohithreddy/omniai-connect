"""Typed application settings. All config comes from environment variables.

Never read os.environ directly anywhere else — import `settings` from here (P-11).
See .env.example at the repo root for the full variable list.

Two rules this module enforces mechanically rather than by convention:

1. `extra="forbid"` — a variable present in the environment file but not declared here
   is a hard boot failure, not a shrug. Previously `extra="ignore"` meant a renamed or
   misspelled variable fell back to a default silently, which for `database_url` means
   "quietly connect to localhost in production".
2. `SecretStr` on every secret **that is consumed as a bare value** — its repr is
   `**********`, so a stray f-string, a `model_dump()` in a debug log, or a Sentry frame
   local cannot leak it (SECURITY.md §2.3: omission is the design, redaction is the
   backstop).

   Two deliberate exceptions, called out because SECURITY.md §1.1 classifies DB URLs as
   secret assets and a Postgres DSN embeds the role password: `database_url` and
   `database_admin_url` are plain `str`. They are handed straight to
   `create_async_engine`, so `SecretStr` would mean `.get_secret_value()` at every
   construction site — including Alembic's env and the test fixtures — which trades a
   real leak surface for six easy-to-forget unwrapping calls.

   Be aware of what that costs: the log redactor in `core.logging` matches on *key
   names*, and neither `database_url` nor `database_admin_url` contains one of its
   markers, so a `settings.model_dump()` written to a log would emit both DSNs verbatim.
   Nothing in the codebase does that today. Do not add it, and do not assume the backstop
   covers these two fields.
"""

from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # Repo root first (running from apps/api), then cwd (running from the root).
        env_file=("../../.env", ".env"),
        env_file_encoding="utf-8",
        extra="forbid",
        case_sensitive=False,
    )

    # --- Core ---
    app_env: Literal["development", "staging", "production"] = "development"
    log_level: str = "info"

    # --- Database ---
    # The application role: NOT superuser, NOT the table owner, no BYPASSRLS. Row-Level
    # Security exempts superusers unconditionally and owners unless FORCE is set, so
    # connecting as either silently disables tenant isolation (DATABASE_DESIGN.md §6).
    database_url: str = "postgresql+asyncpg://omniai_app:omniai_app@localhost:5432/omniai"
    # Schema owner. Alembic only; never serves a request.
    database_admin_url: str = "postgresql+asyncpg://omniai:omniai@localhost:5432/omniai"

    # --- Cache / Queue ---
    redis_url: str = "redis://localhost:6379/0"
    # The Celery broker (ADR-0007, ADR-0021). Kept an *explicit* setting rather than silently
    # reusing `redis_url` so a deployment can put the broker on its own Redis / logical DB
    # without disturbing the app cache. Empty → falls back to `redis_url` (the least-invasive
    # local default; the same canonical Redis, no second server).
    celery_broker_url: str = ""

    @property
    def resolved_celery_broker_url(self) -> str:
        return self.celery_broker_url or self.redis_url

    # --- Auth (Better Auth — provider in apps/web per ADR-0002/0014; verified here per
    # ADR-0015) ---
    better_auth_secret: SecretStr = SecretStr("change-me-32-chars-minimum")
    # Doubles as the expected `iss` and `aud` of every human JWT: Better Auth derives both
    # claims from its baseURL, so this single value is the trust anchor for issuer pinning.
    better_auth_url: str = "http://localhost:3000"
    # Where to FETCH the JWKS, when that differs from the public issuer URL. Empty means
    # "derive from better_auth_url". The only reason this exists is container networking:
    # inside docker-compose the API reaches the web app at http://web:3000 while tokens
    # carry iss=http://localhost:3000. It changes the fetch address only — never the
    # issuer/audience the verifier requires (ADR-0015 §5).
    better_auth_jwks_url: str = ""

    @property
    def resolved_jwks_url(self) -> str:
        """The JWKS document location: the override, or derived from the issuer URL."""
        return self.better_auth_jwks_url or f"{self.better_auth_url}/api/auth/jwks"

    # --- Invitations (ADR-0017) ---
    # The From address for first-party invitation email sent via Resend. A plain str, not a
    # secret: it appears in every message header. Verify the domain in Resend before use.
    invitation_from_email: str = "OmniAI Connect <invites@omni.example>"
    # Server-enforced invitation lifetime. 7 days per the ratified contract.
    invitation_expiry_days: int = 7

    # --- Encryption (credential vault — SECURITY.md §2.1) ---
    credential_master_key: SecretStr = SecretStr("change-me")

    # --- Frontend ---
    next_public_app_url: str = "http://localhost:3000"
    next_public_api_url: str = "http://localhost:8000"

    # --- Billing ---
    stripe_secret_key: SecretStr = SecretStr("")
    stripe_webhook_secret: SecretStr = SecretStr("")

    # --- Email ---
    resend_api_key: SecretStr = SecretStr("")

    # --- Monitoring ---
    sentry_dsn: str = ""
    posthog_api_key: SecretStr = SecretStr("")

    # --- Object storage (S3-compatible: Cloudflare R2 in prod, MinIO in local/CI — M1.4-B0.5) ---
    r2_account_id: str = ""
    r2_access_key_id: str = ""
    r2_secret_access_key: SecretStr = SecretStr("")
    r2_bucket: str = ""
    # The S3 endpoint. In production this is the R2 account endpoint (https://<acct>.r2
    # .cloudflarestorage.com); local/CI point it at MinIO (http://minio:9000). Empty = storage
    # is unconfigured, which app.core.object_store treats as a fail-closed error (never a silent
    # MinIO fallback in production). Canon names no endpoint var, so B0.5 introduces it (ADR-0024).
    r2_endpoint: str = ""
    # R2 ignores the region and documents "auto"; MinIO accepts any value. Not secret.
    r2_region: str = "auto"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


settings = Settings()
