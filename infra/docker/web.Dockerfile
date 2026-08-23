# OmniAI Connect Web — Next.js
FROM node:20-alpine AS base
RUN corepack enable
WORKDIR /repo

# ---- deps ----
FROM base AS deps
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/web/package.json apps/web/
COPY packages/types/package.json packages/types/
# --frozen-lockfile: reproducible builds are the point of committing a lockfile (P-59).
RUN pnpm install --frozen-lockfile

# ---- dev (used by docker-compose) ----
FROM deps AS dev
COPY . .
EXPOSE 3000
CMD ["pnpm", "--filter", "web", "dev"]

# ---- build ----
FROM deps AS build
COPY . .

# `NEXT_PUBLIC_*` values are compiled into the browser bundle, so they must exist at BUILD time,
# not merely at run time — providing one only via `docker run -e` is too late, and the variable
# would be `undefined` in the shipped JavaScript.
#
# It became mandatory in MC1.3: `(dashboard)` is the first route to transitively import the API
# client, and `lib/env.ts` validates `publicEnv` eagerly on purpose ("a missing app URL should
# fail the build, not the first request that needs it"). `next build` evaluates every route
# module to collect page data, so without this the image build fails with
# "Failed to collect configuration for /dashboard".
#
# The default is a placeholder that keeps CI and local image builds working. **Any real
# deployment must pass its own value** (`--build-arg NEXT_PUBLIC_APP_URL=https://…`), because
# whatever is set here is baked into the client bundle. It is a public URL, never a secret — no
# server-only variable belongs in this stage, and `getAuth()` stays deferred behind a function
# precisely so the build never demands a real secret or a reachable database.
ARG NEXT_PUBLIC_APP_URL=http://localhost:3000
ENV NEXT_PUBLIC_APP_URL=${NEXT_PUBLIC_APP_URL}

RUN pnpm --filter web build

# ---- production ----
FROM node:20-alpine AS prod
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /repo/apps/web/.next/standalone ./
COPY --from=build /repo/apps/web/.next/static ./apps/web/.next/static
USER node
EXPOSE 3000
CMD ["node", "apps/web/server.js"]
