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

    # --- Auth (Better Auth — wired in M1.2, ADR-0002) ---
    better_auth_secret: SecretStr = SecretStr("change-me-32-chars-minimum")
    better_auth_url: str = "http://localhost:3000"

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

    # --- Object storage ---
    r2_account_id: str = ""
    r2_access_key_id: str = ""
    r2_secret_access_key: SecretStr = SecretStr("")
    r2_bucket: str = ""

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


settings = Settings()
