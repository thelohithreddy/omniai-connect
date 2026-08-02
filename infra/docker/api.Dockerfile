# OmniAI Connect API — FastAPI on Python 3.11
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_SYSTEM_PYTHON=1

RUN pip install --no-cache-dir uv

WORKDIR /app

COPY apps/api/pyproject.toml ./
RUN uv pip install --system -r pyproject.toml

COPY apps/api/ ./

# Non-root user — never run as root in production
RUN useradd --create-home appuser && chown -R appuser /app
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
