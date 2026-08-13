# OmniAI Connect — developer entrypoints
# `make help` lists everything.

.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

setup: ## Install all dependencies (JS + Python)
	pnpm install
	cd apps/api && uv sync

dev: ## Start full stack (db, redis, api, web) via Docker
	docker compose up --build

dev-web: ## Start frontend only
	pnpm --filter web dev

dev-api: ## Start backend only
	cd apps/api && uv run uvicorn app.main:app --reload --port 8000

lint: ## Lint everything
	pnpm lint
	cd apps/api && uv run ruff check .

format: ## Format everything
	pnpm format
	cd apps/api && uv run ruff format .

typecheck: ## Typecheck everything
	pnpm typecheck
	cd apps/api && uv run mypy app

test: ## Run all tests
	pnpm test
	cd apps/api && uv run pytest

migrate: ## Apply DB migrations (runs inside the api container against the compose db)
	docker compose exec api alembic upgrade head

migrate-down: ## Roll back one migration
	docker compose exec api alembic downgrade -1

migration: ## Create a new migration: make migration m="add users table"
	docker compose exec api alembic revision --autogenerate -m "$(m)"

seed: ## Create a local Workspace + API token (prints the token once)
	docker compose exec api python -m scripts.bootstrap_workspace $(if $(name),--name "$(name)",)

db-reset: ## Destroy and recreate the local database volume, then migrate
	docker compose down -v
	docker compose up -d db redis
	@echo "waiting for postgres…" && sleep 5
	docker compose up -d api
	@echo "waiting for api…" && sleep 8
	docker compose exec api alembic upgrade head

test-api: ## Run backend tests inside the container (needs the stack up)
	docker compose exec api pytest -q

clean: ## Remove build artifacts
	rm -rf apps/web/.next .turbo node_modules apps/api/.venv

.PHONY: help setup dev dev-web dev-api lint format typecheck test migrate migrate-down \
	migration seed db-reset test-api clean
