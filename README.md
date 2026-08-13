# OmniAI Connect

**Connect Any API. Use It From Any AI.**

OmniAI Connect is a universal AI integration platform: connect any API once (API key,
OAuth, JWT, Bearer, Basic auth, OpenAPI/Swagger, GraphQL, REST) and use it from every AI
surface — ChatGPT, Claude, Cursor, Copilot, agent frameworks, and automation platforms.
MCP is one interface; the platform is the product.

> 📖 Start here: [`docs/MASTER_PROJECT_BIBLE.md`](docs/MASTER_PROJECT_BIBLE.md) — the
> single source of truth for architecture, naming, and ways of working.

## Status

🏗️ **Foundation stage.** Project structure, documentation, CI/CD, and engineering
standards are in place. No business features yet — see [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Repository layout

```
apps/web        Next.js control plane (TypeScript, Tailwind, shadcn/ui)
apps/api        FastAPI modular monolith + Celery workers (Python 3.11)
packages/       Shared TS packages (types, config)
docs/           All project documentation
infra/docker/   Dockerfiles
scripts/        Developer utilities
.github/        CI workflows, PR/issue templates
```

## Quick start

Prereqs: Docker, Node 20+, pnpm 9, Python 3.11+, [uv](https://docs.astral.sh/uv/).

```bash
cp .env.example .env        # fill in local values
make dev                    # full stack via Docker (db, redis, api, web)
make migrate                # apply schema migrations
make seed                   # create a Workspace + API token (printed once)
```

Then call the API with the token it printed:

```bash
curl -H "Authorization: Bearer omc_…" http://localhost:8000/v1/workspaces/me
```

- Web: http://localhost:3000
- API: http://localhost:8000 (docs at /docs)

All commands: `make help`. `make db-reset` recreates the database volume from scratch —
needed after changing anything in `infra/docker/postgres-init/`, since Postgres runs those
scripts only when initialising an empty data directory.

> **Why two database roles?** The app connects as `omniai_app`, which is neither a
> superuser nor the owner of any table. Postgres exempts both from Row-Level Security, so
> connecting as either would silently disable tenant isolation while every policy still
> looked correct. Migrations run as the owner via `DATABASE_ADMIN_URL`.
> See [`docs/DATABASE_DESIGN.md`](docs/DATABASE_DESIGN.md) §6.

## Development

| Task | Command |
|---|---|
| Lint / format | `make lint` / `make format` |
| Typecheck | `make typecheck` |
| Tests | `make test` |
| New DB migration | `make migration m="describe change"` |

Branching, commit format, and review rules: [`docs/CODING_STANDARDS.md`](docs/CODING_STANDARDS.md).
API conventions: [`docs/API_GUIDELINES.md`](docs/API_GUIDELINES.md).
Security rules (read before touching credentials): [`docs/SECURITY.md`](docs/SECURITY.md).

## Documentation

Full index in the [Project Bible §9](docs/MASTER_PROJECT_BIBLE.md#9-documentation-index).
Engineering constitution: [`docs/ENGINEERING_PRINCIPLES.md`](docs/ENGINEERING_PRINCIPLES.md).
Current state and priorities: [`PROJECT_STATUS.md`](PROJECT_STATUS.md).
AI engineers (Claude Code, Cursor, etc.) start with [`CLAUDE.md`](CLAUDE.md) and [`AGENTS.md`](AGENTS.md).

## License

Proprietary — © 2026 OmniAI Connect. All rights reserved.
