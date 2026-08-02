"""Typed application settings. All config comes from environment variables.

Never read os.environ directly anywhere else — import `settings` from here.
See .env.example at the repo root for the full variable list.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    log_level: str = "info"

    database_url: str = "postgresql+asyncpg://omniai:omniai@localhost:5432/omniai"
    redis_url: str = "redis://localhost:6379/0"


settings = Settings()
