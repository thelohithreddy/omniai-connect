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
