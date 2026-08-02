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

migrate: ## Apply DB migrations
	cd apps/api && uv run alembic upgrade head

migration: ## Create a new migration: make migration m="add users table"
	cd apps/api && uv run alembic revision --autogenerate -m "$(m)"

clean: ## Remove build artifacts
	rm -rf apps/web/.next .turbo node_modules apps/api/.venv

.PHONY: help setup dev dev-web dev-api lint format typecheck test migrate migration clean
