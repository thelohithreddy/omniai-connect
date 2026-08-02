# Changelog

> Consistent with docs/MASTER_PROJECT_BIBLE.md.

All notable changes to OmniAI Connect are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every PR
that changes behavior adds an entry under **Unreleased** in the same PR (Bible §6.8);
entries move into a versioned section at release tag time (ADR-0005).

## [Unreleased]

## [0.1.0] - 2026-08-02

### Added

- Monorepo foundation: `apps/web` (Next.js control plane), `apps/api` (FastAPI modular
  monolith + Celery workers), `packages/types`, `packages/config` (Bible §8).
- Core documentation set: Master Project Bible, System Architecture, Decisions
  (ADR-0001–0007), Security, API Guidelines, Coding Standards, Changelog, Meeting Notes.
- Shared `ApiError` envelope contract in `@omniai/types`.
- Docker images for api and web under `infra/docker/`.
- CI pipeline (GitHub Actions): web lint/typecheck/build, api ruff/mypy/pytest,
  Gitleaks secret scan, Docker image builds.
- Engineering standards locked: uv for Python deps (ADR-0006), trunk-based branching
  with squash merges (ADR-0005), Conventional Commits.

### Notes

- Foundation release only — no business features. Product milestones begin at M1
  (see docs/ROADMAP.md).

[Unreleased]: https://github.com/omniai-connect/omniai-connect/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/omniai-connect/omniai-connect/releases/tag/v0.1.0
