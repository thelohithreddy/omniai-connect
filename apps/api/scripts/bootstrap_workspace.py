"""Create a Workspace and issue its first API token.

Chicken-and-egg: until Better Auth lands (M1.2) there is no human identity, so nothing can
sign in to create the first Workspace. This script is that bootstrap, and nothing more.

It connects as the **admin** role deliberately. Creating the first Workspace is the one
operation with no tenant to scope to, so RLS would reject it as the app role — correctly.
That makes this a privileged path, which is why it refuses to run in production: an
unauthenticated workspace-minting endpoint reachable in prod is a backdoor, however
convenient. Deleted when the dashboard can do this properly.

    make seed
    make seed name="Acme Corp"
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import settings
from app.core.ids import new_id
from app.core.security import generate_token


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "workspace"


async def bootstrap(name: str, token_name: str) -> int:
    if settings.is_production:
        print("refusing to run with APP_ENV=production", file=sys.stderr)
        return 1

    engine = create_async_engine(settings.database_admin_url)
    workspace_id, slug = new_id(), slugify(name)
    token = generate_token()

    try:
        async with engine.begin() as conn:
            existing = await conn.scalar(
                text("SELECT id FROM workspaces WHERE slug = :slug"), {"slug": slug}
            )
            if existing:
                workspace_id = existing
                print(f"workspace '{slug}' already exists — issuing an additional token")
            else:
                await conn.execute(
                    text(
                        "INSERT INTO workspaces (id, name, slug, plan) "
                        "VALUES (:id, :name, :slug, 'free')"
                    ),
                    {"id": workspace_id, "name": name, "slug": slug},
                )

            await conn.execute(
                text(
                    "INSERT INTO api_tokens "
                    "(id, workspace_id, name, token_hash, token_prefix, scopes) "
                    "VALUES (:id, :ws, :name, :hash, :prefix, '[]'::jsonb)"
                ),
                {
                    "id": new_id(),
                    "ws": workspace_id,
                    "name": token_name,
                    "hash": token.token_hash,
                    "prefix": token.token_prefix,
                },
            )
    finally:
        await engine.dispose()

    # The only time this value is ever displayed. Only the SHA-256 digest was persisted,
    # so it cannot be recovered — losing it means issuing a new token.
    print(f"\n  workspace : {name}  ({slug})")
    print(f"  id        : {workspace_id}")
    print(f"  token     : {token.plaintext}")
    print("\n  Shown once. Store it now.\n")
    print(f'  curl -H "Authorization: Bearer {token.plaintext}" \\')
    print("       http://localhost:8000/v1/workspaces/me\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="Local Dev", help="Workspace display name")
    parser.add_argument("--token-name", default="local-dev", help="Label for the API token")
    args = parser.parse_args()
    return asyncio.run(bootstrap(args.name, args.token_name))


if __name__ == "__main__":
    raise SystemExit(main())
