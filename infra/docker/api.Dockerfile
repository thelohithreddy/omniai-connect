# OmniAI Connect API — FastAPI on Python 3.11
#
# Three stages. `dev` and `prod` differ in exactly two ways — dev deps, and the server
# command — so what runs in production is otherwise byte-identical to what you develop
# against.

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # uv builds into this venv; putting it outside /app keeps it from being shadowed by
    # the bind mount docker-compose lays over /app in development.
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir uv==0.5.11

WORKDIR /app

# Dependency layer first: it changes far less often than source, so edits to app code
# reuse the cached install instead of re-resolving 61 packages.
COPY apps/api/pyproject.toml apps/api/uv.lock ./

# ---- dev ----------------------------------------------------------------------------
FROM base AS dev
RUN useradd --create-home appuser
# --frozen fails the build if uv.lock is stale rather than silently re-resolving to
# different versions. Reproducible builds are the whole point of committing a lockfile
# (P-59); `uv sync` without it would quietly defeat that.
RUN uv sync --frozen --no-install-project
# `COPY --chown` sets ownership as the layer is written. A trailing `chown -R` instead
# rewrites every touched file into a *new* layer — and chowning /opt/venv that way
# duplicates the entire virtualenv, roughly doubling the image. The venv stays root-owned
# and world-readable, which is all the app needs: it executes from it, never writes to it.
COPY --chown=appuser:appuser apps/api/ ./
USER appuser
EXPOSE 8000
# --reload watches the source bind mount. Development only: it forces a single worker
# and spawns a file-watcher, neither of which belongs in production.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ---- prod ---------------------------------------------------------------------------
FROM base AS prod
RUN useradd --create-home appuser
# --no-dev omits pytest/ruff/mypy: smaller image, smaller attack surface, and no test
# tooling sitting on a box that handles customer credentials.
RUN uv sync --frozen --no-install-project --no-dev
# See the dev stage: --chown avoids duplicating the virtualenv into an extra layer.
COPY --chown=appuser:appuser apps/api/ ./
USER appuser
EXPOSE 8000
# Uvicorn's own multi-process supervisor — no Gunicorn involved. `--workers` forks N
# worker processes for multi-core use; the supervisor forwards SIGTERM and waits, so
# in-flight requests drain on deploy instead of being severed.
# `exec` matters: it replaces the shell so uvicorn becomes PID 1 and receives SIGTERM
# directly. Without it the shell is PID 1, swallows the signal, and Docker SIGKILLs the
# container after its grace period — severing exactly the requests this is meant to drain.
# Worker count is env-driven: Railway sizing is a deploy concern, not an image concern.
ENV WEB_CONCURRENCY=2
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${WEB_CONCURRENCY} --no-server-header"]
