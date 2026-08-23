#!/usr/bin/env python3
"""Export the FastAPI OpenAPI document to `packages/types/openapi.json` (MC1.1, ADR-0044 D2).

The schema is committed as a **reviewable artifact** rather than fetched from a running server
at build time, and that is the whole point: it turns the backend↔frontend contract into
something a reviewer sees in a diff. A change to a response model shows up as a schema diff in
the same pull request that changes the Python, instead of surfacing later as a frontend type
that quietly disagrees with production.

It also makes drift detection deterministic in two independent steps
(`packages/types/package.json`):

1. re-export the schema from the app → the committed JSON must be unchanged, or the backend
   moved without the contract being refreshed;
2. re-generate types from the committed JSON → the committed types must be unchanged, or the
   contract moved without the types being refreshed.

This script **reads** the application and writes one JSON file. It imports `app.main` and calls
the public `app.openapi()`; it starts no server, opens no database connection, and changes no
API behaviour. Run it from the repository root, or inside the api container where the
application's dependencies are installed:

    docker compose exec -T api python /repo/scripts/export-openapi.py --stdout > packages/types/openapi.json

`--stdout` exists precisely for that container case, where the repository path inside the
container may differ from the path on the host.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The FastAPI application lives in apps/api; make it importable when this script is run from
# the repository root on a developer machine. Inside the api container `app` is already on the
# path and this simply adds a directory that does not exist, which is harmless.
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "apps" / "api"))

#: Where the committed contract lives. One location, referenced by the generator and by CI.
DEFAULT_OUTPUT = _REPO_ROOT / "packages" / "types" / "openapi.json"


def export() -> str:
    """Return the application's OpenAPI document as deterministic JSON.

    `sort_keys=True` is load-bearing for drift detection: FastAPI builds the document from
    dictionaries whose iteration order is stable in practice but not guaranteed across
    refactors, and an unordered dump would produce spurious diffs that train reviewers to
    ignore the gate. Trailing whitespace is stripped and a single newline is appended so the
    file round-trips through editors and `git diff --check` cleanly.
    """
    from app.main import app  # imported lazily so `--help` works without the app's dependencies

    document = app.openapi()
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Write to stdout instead of the default path (used from inside the container).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Destination file (default: {DEFAULT_OUTPUT}).",
    )
    args = parser.parse_args()

    rendered = export()
    if args.stdout:
        sys.stdout.write(rendered)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
