# Contributing

1. Read `docs/MASTER_PROJECT_BIBLE.md` first — it is the source of truth.
2. Branch from `main`: `feat/<slug>`, `fix/<slug>`, `docs/<slug>`, `chore/<slug>`.
3. Follow `docs/CODING_STANDARDS.md` and Conventional Commits.
4. Definition of done: code + tests + docs + Alembic migration (if schema changed) +
   `docs/CHANGELOG.md` entry. Architectural choices get an ADR in `docs/DECISIONS.md`.
5. Open a PR against `main`; CI must be green; fill in the PR template.
6. Never commit secrets. `.env` is gitignored; every new variable goes into
   `.env.example` with a placeholder.
