# Frontend Specification

> Consistent with docs/MASTER_PROJECT_BIBLE.md. Stack per Bible §7: Next.js (App
> Router), TypeScript, Tailwind, shadcn/ui, React Hook Form + Zod, Zustand, TanStack
> Table, Motion. Identity via Better Auth per ADR-0002.
>
> Version 1.0 · 2026-08-02

`apps/web` is the **Control Plane** (Bible §3, pillar 4): connect APIs, manage
Credentials and Connections, inspect Tool Call logs, manage Workspace and Members,
billing. It never executes Tool Calls itself — that is the Execution Runtime's job.

## 1. App Router structure

```
apps/web/src/
├── app/
│   ├── (marketing)/          # Public site: /, /pricing, /docs, /blog
│   ├── (auth)/               # /login, /signup, /invite — Better Auth flows
│   ├── (dashboard)/          # Authenticated control plane
│   │   ├── layout.tsx        # Workspace shell: nav, workspace switcher
│   │   ├── connectors/       # List, detail, "connect an API" wizard
│   │   ├── connections/      # Connection status, credential management
│   │   ├── tools/            # Tool browser, enable/disable, annotations
│   │   ├── logs/             # Tool Call audit log explorer
│   │   ├── interfaces/       # MCP URL + API token issuance/revocation
│   │   └── settings/         # Members, roles, billing, workspace
│   └── api/auth/[...all]/    # Better Auth handler (identity lives here, ADR-0002)
├── components/               # ui/ (shadcn), shared composites
├── lib/                      # api client, auth helpers, utils
└── stores/                   # Zustand stores (client state only)
```

Route groups keep marketing, auth, and dashboard in separate layout trees; the
`(dashboard)` layout resolves the session and active Workspace server-side and
redirects unauthenticated visitors before any page renders.

## 2. Server vs client components

- **Server components by default.** Pages, layouts, and data-bearing sections render
  on the server. `"use client"` appears only at the **leaves**: form controls,
  interactive tables, dialogs, the workspace switcher — components that own browser
  state or event handlers.
- A client component never fetches on mount what its parent server component could
  have passed as props. If a leaf needs data, the boundary is wrong — lift the fetch.

## 3. Data fetching

- **Reads:** server components call the FastAPI backend directly with the **typed
  client from `@omniai/types`** (generated from the API's OpenAPI schema — Bible
  tenet 5, schema-first), attaching the Better Auth session token server-side. No
  hand-written `fetch` with string URLs; a compile error, not a 404, catches a
  renamed endpoint.
- **Writes:** **server actions** wrap the same typed client for mutations (create
  Connector, revoke api token, invite Member), then `revalidatePath`/`revalidateTag`
  the affected reads. Server actions validate input with the shared Zod schema before
  calling the API — the API remains the authority; the action is a convenience layer,
  never a second source of business rules.
- **Client-side fetching** is the exception, reserved for genuinely live views (log
  tailing, ingestion progress) via a query cache with polling; same typed client.

## 4. State rules

- **Zustand only for cross-component *client* state**: active workspace selection,
  sidebar/layout preferences, multi-step wizard progress. Small stores, one concern
  each, in `src/stores/`.
- **Server state stays server-side** — in server components or the query cache. It is
  never copied into Zustand; a store that caches API responses is a bug (two sources
  of truth that will drift).
- Local component state (`useState`) for anything only one component cares about.
  URL search params — not stores — hold shareable view state (log filters, pagination).

## 5. Forms

- **React Hook Form + Zod** for every form; the Zod schema is the single validation
  source, shared with the server action that receives the submission.
- Schemas for API payloads come from `@omniai/types` and are extended (not redefined)
  for UI-only concerns. shadcn/ui `<Form>` primitives wire errors, labels, and
  aria-describedby automatically.
- Credential entry forms (API keys, client secrets) never persist values to stores,
  localStorage, or URL state, and submit directly to the API — credential plaintext
  never rests in the frontend (Bible tenet 2).

## 6. UI standards

- **shadcn/ui components + Tailwind utilities only. No ad-hoc CSS files**, no inline
  style objects, no CSS modules. New visual patterns become a shared component in
  `components/`, not a one-off class soup.
- Design tokens (colors, radii, spacing) live in the Tailwind config; hard-coded hex
  values are a review reject.
- **Motion** for transitions (page-level fades, dialog/list enter-exit). Animations
  respect `prefers-reduced-motion` and never gate task completion.
- **TanStack Table** for all logs and list views (Tool Call logs, Tools, Members,
  api tokens): server-driven pagination and sorting for high-volume tables (`tool_calls`
  is partitioned and huge — DATABASE_DESIGN.md), column visibility persisted per user.

## 7. Accessibility baseline

- Every interactive element is keyboard-reachable with a visible focus ring; dialogs
  and menus (via shadcn/Radix) trap and restore focus.
- Semantic HTML first; ARIA only where semantics fall short. Form fields always have
  bound labels; errors are announced via `aria-live`.
- Contrast meets WCAG 2.1 AA in both themes. Destructive actions (delete Connection,
  revoke Credential) require an explicit confirmation dialog naming the object.

## 8. Error and loading conventions

- Every `(dashboard)` route segment ships `loading.tsx` (skeletons matching final
  layout, not spinners) and `error.tsx` (friendly message + retry + `request_id` from
  the API error envelope for support).
- API errors surface the envelope's `message`; the `code` drives behavior (e.g.
  `quota_exceeded` → upgrade prompt). Raw upstream/tool output is rendered as inert
  preformatted text, never as HTML or markdown (prompt-injection hygiene,
  AI_RUNTIME.md §7).
- Mutations show optimistic UI only when rollback is trivial (toggles); otherwise
  pending state on the triggering control. All failures produce a toast plus inline
  context — silent failure is forbidden.

## 9. Environment variables

- **`NEXT_PUBLIC_` prefix only for values safe in the client bundle** (public API
  base URL, PostHog public key, app URL). Everything else — Better Auth secret,
  API-to-API signing secrets, Stripe keys — stays server-only and unprefixed.
- All env access goes through a single `src/lib/env.ts` that validates with Zod at
  boot (fail fast on misconfiguration); components never read `process.env` directly.
  Every variable appears in `.env.example` (Bible tenet 7).
