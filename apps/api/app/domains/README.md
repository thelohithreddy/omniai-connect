# app/domains/

Each business domain lives in its own package here (connectors, credentials,
tools, runtime, billing, ...). Every domain follows the same internal layout:

```
domains/<name>/
├── router.py       # FastAPI routes (thin — no business logic)
├── service.py      # Business logic (framework-free)
├── repository.py   # DB access (SQLAlchemy, only layer that touches the DB)
├── models.py       # SQLAlchemy models
├── schemas.py      # Pydantic request/response schemas
└── events.py       # Domain events published to the event bus
```

Rules: routers call services, services call repositories. Never skip a layer.
See docs/BACKEND_SPEC.md and docs/CODING_STANDARDS.md.
