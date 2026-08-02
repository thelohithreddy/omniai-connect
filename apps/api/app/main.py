"""OmniAI Connect API entrypoint.

Foundation only — business features land in app/domains/ per docs/BACKEND_SPEC.md.
"""

from fastapi import FastAPI

from app.core.config import settings

app = FastAPI(
    title="OmniAI Connect API",
    version="0.1.0",
    docs_url="/docs" if settings.app_env != "production" else None,
)


@app.get("/health", tags=["ops"])
async def health() -> dict[str, str]:
    """Liveness probe. Extend with DB/Redis checks when those layers land."""
    return {"status": "ok", "env": settings.app_env}
