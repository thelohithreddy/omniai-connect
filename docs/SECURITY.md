# Security

> Consistent with docs/MASTER_PROJECT_BIBLE.md. Implements tenets §6.1–§6.3 and §6.7.
> Changes to anything in this document require review by both owners and, where
> architectural, an ADR in docs/DECISIONS.md.

Version 1.0 · 2026-08-02

---

## 1. Threat model summary

We are a credential custodian. Customers hand us the keys to their Stripe accounts, CRMs,
and internal APIs so that AI clients can call them. Our security posture starts from that
fact: **losing a Credential is a company-ending event** (Bible §6.2).

### 1.1 Assets

| Asset | Why it matters | Primary controls |
|---|---|---|
| Customer Credentials | Third-party API keys/OAuth tokens bound to Connections | Envelope encryption, runtime-only decryption, redaction (§2) |
| Tenant data | Connectors, Connections, Tools, Tool Call audit logs per Workspace | `workspace_id` scoping + Postgres RLS (§3) |
| Platform API tokens | Workspace-scoped machine tokens used by AI clients | Hashed at rest, scoped, revocable (§4) |
| Platform infrastructure secrets | DB URLs, master key, Stripe keys, JWKS secret | `.env` discipline + Gitleaks (§5) |

### 1.2 Adversaries

| Adversary | Capability assumed | Key defenses |
|---|---|---|
| **External attacker** | Scans, credential stuffing, exploits public endpoints | Better Auth hardening, rate limits, Cloudflare WAF, no secrets in responses |
| **Malicious tenant** | Valid account; probes for cross-tenant access, abuses egress | RLS + repository scoping, SSRF controls, per-workspace quotas |
| **Compromised AI client** | Holds a leaked workspace API token | Token scoping (one Workspace, least privilege), revocation, anomaly-visible audit log |
| **Prompt-injected agent** | Legitimate Interface, attacker-controlled instructions | Runtime is the only egress; Tools are the only actions; per-Connection allowlists; full Tool Call audit trail. The runtime never grants an agent capabilities beyond its Workspace's active Connections. |

Out of scope for v1 (tracked in RISKS.md): malicious insiders with production access
(two-person team; compensating control is audit logging and provider-side access logs),
and semantic prompt-injection filtering inside the AI client itself — we constrain blast
radius rather than promise detection.

## 2. Credential vault

Credentials are radioactive (Bible §6.2). The vault lives in the `credentials` domain and
is the only code allowed to touch plaintext secrets.

### 2.1 Envelope encryption

- **Cipher:** AES-256-GCM. Never hand-rolled — standard library/`cryptography` primitives
  only (Bible §10, "what we do NOT do").
- **Data keys:** one random 256-bit data key **per Credential**. The Credential's secret
  material is encrypted with its data key; the data key is then wrapped (encrypted) by the
  master key and stored alongside the ciphertext. Nonce is random per encryption and never
  reused with the same key; the GCM auth tag is stored and verified on every decrypt.
- **Master key (KEK):** environment-provided, and since M2.6 a **versioned keyring**:
  `CREDENTIAL_MASTER_KEY` is version 1 permanently (rows stamped `key_version = 1` were wrapped
  by it directly, so its meaning can never be reassigned) and `CREDENTIAL_MASTER_KEYS` supplies
  versions ≥ 2 as `version:base64key`. `CREDENTIAL_KEY_VERSION` selects which version seals *new*
  credentials; every version in the keyring still *decrypts*. Fail-closed on a missing, default,
  malformed, wrong-length, duplicated, or unknown-active version — the API refuses to boot rather
  than operate with a hole in the keyring. Migrates to a KMS (wrapping happens inside the KMS, key
  never leaves it) when we harden for Team/Enterprise; because only the *wrapped data keys* depend
  on the master key, that is a new `KeyProvider` implementation plus a re-wrap pass, with no schema
  change and no ciphertext rewrite.
- **Workspace keys (M2.6):** a data key is not wrapped by the KEK directly (except at version 1,
  see above). It is wrapped by a **per-workspace key derived with HKDF-Expand** (RFC 5869 — the
  Extract step is correctly skipped because the KEK is already a uniformly random 256-bit key),
  domain-separated by a fixed label, the key version, and the workspace UUID. The key is never
  stored and never logged; it is recomputed on demand. Effect: a wrapped data key from one
  workspace is cryptographically useless in another **even if the AAD check above it were
  bypassed**, so tenant isolation survives a bug in the application layer.

#### Key rotation runbook

Every wrapped data key records its KEK version. Rotation is **annual as routine, immediate on
compromise**, and runs in five ordered steps. Per-Credential data keys additionally rotate on
credential update.

1. **INTRODUCE** — add the new version to `CREDENTIAL_MASTER_KEYS` and set
   `CREDENTIAL_KEY_VERSION` to it. New credentials seal under it immediately; **the old version
   stays in the keyring**, so every existing credential keeps working. There is no cutover moment
   and no window in which live traffic fails.
2. **RE-WRAP** — the `vault-key-rotation-sweep` beat task discovers credentials below the target
   (`auth.pending_key_rotations`) and fans out one `rewrap_credential_key` task each, carrying
   **identifiers only**. Each re-wrap unwraps the data key under its own version and re-wraps it
   under the target, under a row lock. **The payload is never decrypted and never rewritten** —
   `ciphertext` and `nonce` are byte-identical afterwards — so an interrupted rotation cannot
   corrupt a secret. Target: complete within **24 hours**.
3. **PROVE COMPLETION** — `auth.count_credentials_below_key_version(target)` must return **0**.
   The database is the authority. Never conclude a rotation is complete because a timer elapsed,
   the scheduler reported success, or a batch appeared to finish. The sweep logs this number as
   `pending` on every tick, so it is answerable from logs.
4. **OVERLAP** — hold the old version in the keyring for at least **7 days** after the count
   reaches zero, as insurance against a straggler, a restored backup, or a replica lagging.
5. **RETIRE** — only now remove the old version from `CREDENTIAL_MASTER_KEYS`. Retiring while any
   row still depends on it makes that row **permanently unreadable**. If it happens anyway, the
   failure is loud and specific: `VaultKeyVersionError`, audited as `key_unavailable` rather than
   as tampering, because the two demand opposite responses — restore the key versus investigate an
   attack.

**Rollback.** Steps 1–2 are reversible at any time by lowering `CREDENTIAL_KEY_VERSION`; already
re-wrapped rows stay readable because their version remains in the keyring, and the sweep never
moves a row *down*. `CREDENTIAL_ROTATION_ENABLED=false` pauses re-wrapping without weakening any
sealed credential. The only irreversible step is 5, which is why 3 and 4 gate it.

#### Vault access audit (M2.6)

Every credential decrypt — success **and** each distinct failure — is recorded at the single
decrypt boundary as a structured log event (`vault.credential_opened` /
`vault.credential_open_failed`) carrying workspace, connection, credential, credential type, key
version, and a classified outcome, plus a **bounded** counter whose labels are drawn from closed
sets so cardinality cannot grow with tenants. No new table and no second audit ledger: the log
platform holds per-event detail, the counter holds the aggregate. The record itself never contains
plaintext, ciphertext, key material, or an exception body.

### 2.2 Decryption boundary

Plaintext exists **only inside the Execution Runtime**, in memory, for the duration of a
single Tool Call (Architecture §3.2: "credential decrypt (in-memory only)"). Rules:

1. No public API, adapter, Celery task outside the runtime, or repository method returns
   decrypted material. Schemas for Credential/Connection expose metadata only
   (type, last-four/fingerprint, created/rotated timestamps).
2. The decrypt function is private to the runtime package; importing it elsewhere fails
   code review by policy (import-linting later, per ADR-0001 consequences).
3. Decrypted values are injected into the outbound httpx request and dropped; they are
   never written to Redis, task payloads, or the audit log.

### 2.3 Redaction middleware

Defense-in-depth so a bug cannot leak a secret through observability:

- A structlog processor scrubs known secret fields (`authorization`, `api_key`, `token`,
  `secret`, `password`, plus registered per-Connector credential field names) from every
  log event before emission. It also scrubs `marker=value` patterns **inside strings**, because
  a secret echoed by an upstream API arrives as exception text where no key exists to match on;
  the processor therefore runs *after* `format_exc_info`, not before.
- **Every deployed process covers the stdlib logging tree too (M2.6).** structlog writes through
  `PrintLoggerFactory` and never touches stdlib, so records from libraries — Celery logging a
  failed task *with its arguments*, SQLAlchemy logging a statement, httpx, uvicorn — previously
  went out unscrubbed. Redaction is now installed at `Logger.makeRecord`, which is the only hook
  that sees the rendered message, the exception text, *and* `extra={...}` fields, and which covers
  loggers a library configures with `propagate = False`. `configure_logging()` installs it, and is
  called at import by the API and by `workers/celery_app.py` — the entry point for the **worker,
  worker-runtime, and scheduler** containers alike.
- **Reference identifiers survive redaction.** A key ending in `_id` whose value is a UUID is kept:
  `credential_id` contains "credential" and `api_token_id` contains "token", so the broad marker
  match was rendering audit records as *"someone opened «redacted»"*. Both conditions are required,
  so `token_id="sk-live-…"` is still redacted. A second, tiny **exact-name allowlist** covers
  fields that contain a marker but never hold a secret — currently only `credential_type`, a
  six-value discriminator that was otherwise emitted as «redacted», leaving an audit record that
  could not say what kind of credential was opened. Exact names rather than a suffix rule, so the
  carve-out cannot widen by accident.
- Sentry is **not deployed**; when it is, `before_send` must run the same scrubber over event
  payloads and breadcrumbs. Do not treat this bullet as coverage until that process exists.
- API response serialization goes through Pydantic schemas that simply do not contain
  secret fields — redaction is the backstop, omission is the design.
- Tool Call audit rows store request/response *metadata* (status, latency, sizes, tool,
  workspace) and sanitized payload snapshots with credential headers stripped.

### 2.4 M2 vault-hardening acceptance checklist (EC3, ADR-0041)

ROADMAP §65 makes *"security checklist in SECURITY.md for the vault is fully checked"* an M2 exit
criterion. Until ADR-0041 this document carried no such checklist, so the criterion named an
artifact that had never existed — an ambiguity ADR-0039 and PROJECT_STATUS had quietly resolved by
reporting only §65's second clause (the red-team pass). This section is the missing artifact. §65
itself is unchanged.

**Read this as an acceptance record, not a routine.** It records the state the vault reached at
M2.6 and the evidence that proved each item, **once**. It is deliberately *not* a recurring per-PR
list: `CLAUDE.md`'s "Security checklist" remains the authority for routine security review, and
nothing here replaces it. Every box is checked against evidence already in the repository — no box
is checked on intent. A future change to the vault (adopting a KMS, retiring version 1, adding a
credential type) re-opens the affected items and re-proves them in that PR.

- [x] **Envelope encryption (§2.1).** AES-256-GCM from `cryptography`, never hand-rolled; one
      random 256-bit data key per Credential; random nonce per encryption; auth tag verified on
      every decrypt. — `tests/unit/test_credential_vault.py::test_seal_then_unseal_round_trips`,
      `::test_two_seals_of_the_same_secret_differ_everywhere`,
      `::test_each_credential_gets_a_distinct_random_dek`, `::test_tampered_ciphertext_fails`,
      `::test_tampered_encrypted_dek_fails`.
- [x] **KEK and key-version handling (§2.1).** A versioned keyring, not a single env key:
      `CREDENTIAL_MASTER_KEY` is version 1 permanently, `CREDENTIAL_MASTER_KEYS` supplies versions
      ≥ 2, `CREDENTIAL_KEY_VERSION` selects the sealing version, and every version still decrypts.
      Boot fails closed on a missing, default, malformed, wrong-length, duplicated or unknown
      active version. — `::test_key_version_is_one`, `::test_an_invalid_master_key_is_rejected`,
      `::test_a_valid_master_key_is_accepted`, `::test_a_different_master_key_cannot_unseal`.
- [x] **HKDF-derived per-workspace wrapping keys (§2.1).** Data keys at version ≥ 2 are wrapped by
      a per-workspace key derived with HKDF-Expand (RFC 5869), domain-separated by a fixed label,
      the key version and the workspace UUID. The derived key is never stored and never logged. —
      `::test_derived_workspace_keys_are_deterministic_and_separated`,
      `::test_derived_keys_are_separated_by_key_version`,
      `::test_version_2_does_not_wrap_with_the_raw_kek`.
- [x] **AAD binding.** Every seal is bound to `workspace_id ‖ connection_id`; a payload moved
      between workspaces or connections fails to open. Proven *independently* of AAD as well: a
      wrapped data key from one workspace is useless in another **even when the AAD is made to
      match**, so tenant isolation survives an application-layer bug. —
      `::test_wrong_workspace_aad_fails`, `::test_wrong_connection_aad_fails`,
      `::test_a_wrapped_dek_is_useless_in_another_workspace_even_with_matching_aad`.
- [x] **Version 1 backward compatibility.** Rows written by M1 keep direct-KEK wrapping forever, so
      introducing the hierarchy arrived *as a rotation* rather than orphaning stored credentials. —
      `::test_version_1_ciphertext_written_by_m1_still_decrypts`,
      `::test_version_1_wraps_with_the_kek_itself_not_a_derived_key`.
- [x] **Key rotation (§2.1 runbook).** Re-wrap unwraps under the row's own version and re-wraps
      under the target under a row lock; **the payload is never decrypted and never rewritten** —
      `ciphertext` and `nonce` are byte-identical afterwards. Idempotent, tenant-scoped, and
      serialized under contention (2/4/8 workers, plus rotation racing a concurrent re-seal). —
      `tests/integration/test_vault_key_rotation.py::test_rotation_preserves_the_payload_and_the_secret`,
      `::test_the_credential_still_decrypts_after_rotation`,
      `::test_an_unrotated_credential_keeps_working_during_the_overlap`,
      `::test_rewrap_is_idempotent_across_repeated_runs`,
      `::test_rewrap_cannot_reach_another_tenants_credential`,
      `::test_concurrent_rewraps_produce_exactly_one_effective_rotation`,
      `::test_rotation_and_a_concurrent_reseal_cannot_orphan_the_ciphertext`.
- [x] **Retirement gating (§2.1 runbook steps 3–5).** A key version is retired only when the
      **database** reports `count_credentials_below_key_version(target) = 0` — never because a
      timer elapsed or a scheduler reported success — followed by a 7-day overlap. Both overlap
      readability and post-retirement fail-closed behaviour are proven. —
      `test_vault_key_rotation.py::test_the_retirement_gate_reaches_zero_only_when_the_work_is_done`,
      `test_credential_vault.py::test_both_versions_decrypt_during_the_overlap_window`,
      `::test_reading_a_row_whose_key_was_retired_fails_closed`,
      `::test_rewrap_to_an_unconfigured_version_fails_closed`.
- [x] **Vault access audit (§2.1).** Every decrypt — success **and** each distinct failure class —
      is recorded at the single decrypt boundary, with a retired key audited distinctly from
      tampering (the two demand opposite responses). The record carries no plaintext, ciphertext or
      key material, and the accompanying counter's labels are drawn from closed sets so cardinality
      cannot grow with tenants. — `tests/unit/test_vault_audit.py::test_a_successful_open_is_audited`,
      `::test_a_failed_open_is_audited_not_silently_dropped`,
      `::test_a_retired_key_is_audited_distinctly_from_tampering`,
      `::test_a_malformed_payload_is_audited`, `::test_the_audit_record_never_contains_the_secret`,
      `::test_the_audit_record_never_contains_ciphertext_or_key_material`,
      `::test_metric_cardinality_is_bounded_by_construction`,
      `::test_undeclared_metrics_and_labels_are_refused`.
- [x] **Credential plaintext boundary (§2.2).** The private recovery function is referenced by
      exactly two modules — `domains/credentials/vault.py` and `domains/runtime/secrets.py`.
      Rotation re-wraps; it does not unseal. Asserted by walking every `.py` file under `app/`, so
      a third module learning to decrypt fails the suite rather than review. —
      `tests/integration/test_vault_release_audit.py::test_the_decrypt_boundary_did_not_widen`.
- [x] **structlog redaction (§2.3).** Secret-named keys, nested structures, exception text and
      `marker=value` patterns inside free strings are scrubbed before emission. Both carve-outs are
      bounded: the `_id` exemption requires the value to be a UUID *and* the key to end `_id`, and
      the exact-name allowlist is exact names only, so neither can widen by accident. —
      `tests/unit/test_logging_redaction.py::test_secret_named_keys_are_redacted`,
      `::test_nested_structures_are_redacted`, `::test_exception_text_is_redacted`,
      `::test_secret_patterns_inside_free_text_are_redacted`,
      `::test_uuid_reference_ids_are_kept_so_the_audit_can_name_what_was_accessed`,
      `::test_an_id_shaped_key_holding_a_non_uuid_is_still_redacted`,
      `::test_secret_keys_that_are_not_ids_are_unaffected_by_the_exemption`,
      `tests/unit/test_vault_audit.py::test_the_rendered_audit_line_still_carries_no_secret`,
      `::test_a_secret_named_field_is_still_redacted_after_the_exemption`.
- [x] **stdlib logging redaction (§2.3).** Redaction is installed at `Logger.makeRecord` — the only
      hook that sees the rendered message, the exception text *and* `extra={...}`, and which covers
      loggers a library configures with `propagate = False`. Idempotent, and it does not rewrite
      reserved record attributes. — `test_logging_redaction.py::test_stdlib_message_is_redacted`,
      `::test_stdlib_percent_interpolation_is_redacted`, `::test_stdlib_traceback_is_redacted`,
      `::test_stdlib_extra_fields_are_redacted_by_key`, `::test_the_stdlib_hook_is_idempotent`,
      `::test_reserved_record_attributes_are_not_rewritten`.
- [x] **Coverage across every deployed process (§2.3).** `configure_logging()` is called at import
      by `app/main.py` (API) and by `app/workers/celery_app.py`, which is the entry point for the
      **worker, worker-runtime and scheduler** containers alike — so no deployed process logs
      through an unscrubbed stdlib tree. M2.6 found this gap empirically, observing `celery.worker`
      emit `api_key=…` before the fix; the stdlib tests above are its regression guard.
- [x] **Celery / task-payload secret discipline.** Task arguments are JSON at rest in the Redis
      broker, so key material in a signature would be a plaintext secret in Redis. Proven twice
      over: structurally (the task signature accepts identifiers only, and no `dek=`, `kek=`,
      `ciphertext=`, `plaintext=`, `secret=` or `master_key=` appears anywhere in the task module)
      and behaviourally (the sweep's real dispatch is captured and **every** argument must parse as
      a UUID). — `test_vault_release_audit.py::test_rotation_task_signatures_accept_only_identifiers`,
      `::test_the_sweep_enqueues_identifiers_and_nothing_else`.
- [x] **Deliberate red-team pass (§65 clause 2).** A canary secret is driven through a credential's
      **entire** life — sealed, executed, key-rotated, re-read — and then hunted everywhere it could
      plausibly have escaped: every column of every table (enumerated from `information_schema`, not
      a hand-written list that would go stale), the rendered structured-log stream, and the
      arguments handed to Celery. Zero hits, everywhere. —
      `test_vault_release_audit.py::test_no_plaintext_anywhere_after_a_full_lifecycle`.
- [x] **Positive control on the scanner.** A negative result is worthless without evidence the
      instrument works. The canary is planted in a real column, the sweep is required to find it,
      and it is then removed and the sweep required to come back clean — so `assert hits == []`
      cannot pass merely because the scan is broken. —
      `test_vault_release_audit.py::test_the_scan_would_actually_catch_a_leak`.

**Explicitly not covered by this acceptance**, and not to be read as checked:

- **Sentry** is not deployed. When it is, `before_send` must run the same scrubber over event
  payloads and breadcrumbs (§2.3). Do not treat that bullet as coverage until the process exists.
- **External KMS** (AWS/GCP/Azure, HSM) was ratified **out** of M2.6 (ADR-0039 A1). The
  `KeyProvider` seam exists so adopting one is a new implementation plus a re-wrap pass; that work
  re-opens the KEK and rotation items above.
- **Live Redis keyspace scanning.** Celery payload discipline is proven structurally and by
  capturing real dispatch (above), not by scanning a running broker's keys.

## 3. Tenant isolation

Per Bible §6.1 and ADR-0004:

- Every tenant table carries `workspace_id NOT NULL` (SQLAlchemy base mixin).
- The repository layer requires a workspace context to construct queries — there is no
  "query without a tenant" API to misuse (Architecture §4).
- **Postgres Row-Level Security** is enabled on tenant tables from M1 as defense-in-depth:
  the app sets the workspace context per transaction; RLS policies deny rows outside it.
  A repository bug then returns nothing rather than another tenant's data.
- Redis keys are namespaced `ws:{workspace_id}:…`; cache code never builds keys from
  user-supplied identifiers alone.
- Cross-tenant access attempts return `not_found` (never `forbidden`) so object existence
  is not an oracle.

## 4. Authentication and authorization

Two identity planes, per ADR-0002 — never mixed:

| Plane | Who | Mechanism |
|---|---|---|
| Human | Dashboard users | Better Auth in apps/web owns signup/login/sessions/social OAuth; FastAPI verifies the issued **EdDSA JWT** against Better Auth's published JWKS (`/api/auth/jwks`) and resolves a Member + Workspace context per request (ADR-0015). |
| Machine | AI clients, automation | Workspace-scoped API tokens issued by the API itself. Shown once at creation, stored hashed (never recoverable), revocable individually, and bound to exactly one Workspace. |

**Human JWT verification (ADR-0015).** The single composite resolver `get_workspace_context`
dispatches by credential shape: the `omc_` prefix takes the machine path, everything else
the human path, and neither falls through to the other. The human verifier:

- pins the algorithm allowlist to `("EdDSA",)` — `alg=none`, HMAC confusion, and every
  RSA/EC variant are refused before key material is touched (the token cannot choose its
  own algorithm), and the `PyJWK` key binding refuses a mismatched `alg` as a second gate;
- validates `iss` and `aud` against `BETTER_AUTH_URL`, so a token minted by any *other*
  Better Auth deployment does not authenticate here;
- requires `exp`, `iat`, `sub`, `iss`, `aud`; honors `nbf` when present; 30 s leeway;
- reads keys only from the configured JWKS URL — never from the token (`jku`/`x5u`/embedded
  keys are ignored) — through a bounded cache: 300 s TTL, single-flight refresh, one forced
  refresh per unknown `kid` behind a 30 s cooldown (amplification-bounded), stale-on-error,
  fail-closed when no keys have ever been fetched;
- uses the verified `sub` for one thing only — the membership lookup. **No JWT claim confers
  authorization**: role comes from the persisted Member row read under RLS, permissions from
  the matrix in §4.1. A claim-stuffed token (`role: owner`, `permissions: [...]`) moves
  nothing.

**Workspace is established, never asserted (ADR-0016).** A human's workspace is resolved
from persisted membership via `auth.resolve_member_workspaces` (a SECURITY DEFINER bootstrap
twin of `auth.resolve_api_token`, ADR-0008/0015), never trusted from a request. A human who
belongs to several Workspaces selects one with the **`X-Workspace-Id` header** — a
*selection signal* the server verifies against membership before binding. One membership
auto-binds; many require the header; a header naming a Workspace the caller is not a member
of, or a malformed/duplicate header, fails closed as the uniform 401 with no existence
oracle. A `workspace_id` in the query, body, or JWT is never authority; the role is always
re-resolved from the bound member row under RLS, so no request field sets role or identity.
`GET /v1/workspaces` lists only the caller's own memberships (id + display role), disclosing
no other tenant. Machine tokens ignore the header — their Workspace is the token's.

**Revocation.** A verified JWT is bearer-valid until `exp` (≤ 900 s); logout ends the Better
Auth session but cannot invalidate an outstanding JWT, and FastAPI never sees the session
(it cannot read the `identity` schema, ADR-0014). Immediate lockout is achieved by removing
the Member — authorization is the membership row, not the token, so removal takes effect on
the next request. Rotating `BETTER_AUTH_SECRET` invalidates all outstanding tokens within
one cache TTL.

**Uniform failure.** Every human-credential failure — malformed, bad signature, wrong
issuer/audience, expiry, unknown `kid`, JWKS outage, no membership, ambiguous membership —
returns the one 401 message; the reason goes to structured logs (event names only, never
token material). Authentication (401) and authorization (403) stay distinct (§4.2); a failed
cross-tenant read is the canonical 404, never a 403 existence oracle.

### 4.1 Role matrix

Roles attach to the **Member** (a user's membership in a Workspace, per Bible §4).

This table is the authoritative policy. It is transcribed row-for-row into
`apps/api/app/core/authz.py` as the `Permission` enum and `ROLE_PERMISSIONS` mapping —
one `Permission` per row, identical values. **If the two disagree, the code is wrong.**
Adding a capability means editing this table and that mapping in the same change (ADR-0009).

| Capability | Permission | owner | admin | member | viewer |
|---|---|:---:|:---:|:---:|:---:|
| Manage billing, delete Workspace | `workspace:manage` | ✅ | ❌ | ❌ | ❌ |
| Manage Members and roles | `members:manage` | ✅ | ✅ | ❌ | ❌ |
| Create/configure/delete Connectors | `connectors:manage` | ✅ | ✅ | ❌ | ❌ |
| Create/delete Connections, manage Credentials | `connections:manage` | ✅ | ✅ | ❌ | ❌ |
| Create/revoke workspace API tokens | `api_tokens:manage` | ✅ | ✅ | ❌ | ❌ |
| Execute Tool Calls, view Tools and own logs | `tools:execute` | ✅ | ✅ | ✅ | ❌ |
| View full audit log | `audit:read` | ✅ | ✅ | ❌ | ❌ |

**`viewer` currently holds nothing, and that is an open question rather than a decision.**
The role is storable — DATABASE_DESIGN.md §3 puts it in the `members.role` CHECK domain —
but it has never appeared in this table, and PRD.md FR-CP-1 lists only owner/admin/member.
Granting it "read everything" would be inventing policy, and read access to the audit log
or to Tool Calls is exactly the kind of grant that should be decided deliberately rather
than inferred from a role's name. Deny-by-default is therefore the only consistent answer
until this table gains real `viewer` values or the role is removed from the domain. Both
are changes to canonical documents.

**Deny by default, at runtime.** An unmapped role holds nothing; an unknown permission is
held by nobody, **including owner**; a malformed value is refused outright. There is no
wildcard and no permissive fallback.

Note the distinction from the authoring rule that "an unlisted capability requires owner":
that is guidance for choosing column values when adding a *new row to this table*, not a
runtime behaviour. Applied at runtime it would mean a typo in a permission name silently
grants an owner access to something nobody defined — the exact failure deny-by-default
exists to prevent.

**Policy is separate from enforcement.** `authz.py` answers `(role, permission) → allow |
deny` as a pure function with no database, cache, network, or request involved, which is
what lets the whole security model be reviewed as one table in source control. Resolving
an authenticated request into a Role and refusing it when the answer is deny is the
enforcement layer's job, and it lives in the service layer (not in adapters — adapters are
thin, Bible §6.4).

### 4.2 Request authorization boundary

Enforcement lives in `apps/api/app/core/authorization.py`. An endpoint declares the
permission it needs; the caller never does:

```python
@router.delete("/members/{member_id}")
async def remove(
    ctx: Annotated[WorkspaceContext, Depends(require_permission(Permission.MEMBERS_MANAGE))],
): ...
```

The requirement is captured in a closure when the route is defined, so it is absent from
the request signature and cannot be supplied, overridden, or guessed. A caller can
influence *whether* they satisfy a requirement, never *which* one applies.

Order of evaluation, enforced by dependency composition rather than convention:

| Step | Establishes | Failure |
|---|---|---|
| Authentication | the caller (Bearer token → `WorkspaceContext`) | **401** `unauthorized` |
| Tenant binding | `SET LOCAL app.workspace_id`, RLS armed | — |
| Membership resolution | the Member row *in this workspace* | deny |
| Role | read from the persisted row, never the request | deny |
| Policy (§4.1) | `is_allowed(role, permission)` | **403** `forbidden` |

**401 and 403 stay distinct.** Failing to authenticate is not the same as authenticating
and lacking a capability, and collapsing them destroys the caller's ability to tell a bad
credential from an insufficient one.

**Authorization follows the active tenant, not the identity's strongest membership.** A
user who is an owner in workspace A and a viewer in workspace B holds viewer's permissions
when authenticated against B. This needs no comparison in the authorization code: the
membership lookup is workspace-scoped by construction and RLS is armed on the same
transaction, so A's row is simply unreachable from B's context.

**Every denial is identical.** One message, no permission name, no workspace id, no
statement of whether a membership exists elsewhere — otherwise a 403 becomes a
membership-enumeration primitive.

**Machine identity holds no permissions.** ADR-0002's two identity planes are never mixed:
API tokens are machine credentials and do not map to a Member (DATABASE_DESIGN.md §3), so
they resolve no role and every check denies. Treating a token as its workspace's owner, or
as the member who created it, would be a confused deputy. Machine authorization is the
token's own `scopes` field — a separate mechanism, not yet enforced.

### 4.3 Member management

`GET /v1/members`, `PATCH /v1/members/{id}` and `DELETE /v1/members/{id}` require
`members:manage`, so only an `owner` or `admin` may read the roster or change it.

- **A role change binds on the target's very next request.** Authorization reads the role
  from the persisted row every time (§4.2), so a demotion takes effect immediately — there
  is no cached role and nothing to invalidate.
- **No role-transition rules are enforced**, and none are invented: whether an admin may
  re-role an owner, and whether the last owner may be demoted or removed, are open
  questions §4.1 does not answer. Recorded rather than decided.
- **A machine token cannot read or change the roster.** Listing members is reconnaissance,
  re-roling one is escalation, and removing one is denial of service; machine identity
  resolves to no membership (ADR-0002), so all three deny.
- **A Member from another Workspace is byte-identical to one that never existed** (`404`,
  §3) on both mutating endpoints, so the API is not an existence oracle for other tenants.
- **Removing a Member does not revoke the API tokens they created.** Those are
  workspace-owned credentials; the composite FK clears provenance with
  `ON DELETE SET NULL` and revocation stays a separate, explicit act (§4.5).
- The response exposes `id`, `user_id`, `role` and `created_at` only — never `workspace_id`
  or `invited_by`.

### 4.4 API token issuance

`POST /v1/api-tokens` requires `api_tokens:manage`, so only an `owner` or `admin` may mint
a machine credential. Three properties hold at that endpoint:

- **The plaintext is emitted exactly once**, in the 201 response, with
  `Cache-Control: no-store` (RFC 6749 §5.1). Only the SHA-256 digest and a 12-character
  display prefix are persisted; nothing in the system can reconstruct the secret, and a
  lost token must be reissued.
- **Provenance is taken from the authenticated Member**, never the request body. The
  creation schema forbids unknown fields, so an attempt to supply `created_by_member_id`,
  `scopes`, or a chosen `token` is a `400 validation_error` rather than a silent no-op.
- **A token cannot mint another token.** Machine identity resolves to no membership
  (ADR-0002), so a leaked credential is denied `api_tokens:manage` and cannot issue a
  successor that would survive revoking the original. This is a deliberate consequence of
  the two identity planes. Since M1.3-B/C, token issuance is available to **human** members
  holding `api_tokens:manage` (owner/admin) — authenticated by JWT, scoped by
  `X-Workspace-Id`, and recorded with the creating member's id — alongside the bootstrap
  script that seeds a workspace's first token before any Member exists.

Tokens are currently issued **unscoped** (`scopes = []`). A scope vocabulary is not yet
defined (ADR-0010) — and `[]` is the deny-by-default
value, not a placeholder meaning "everything".

### 4.5 API token listing

`GET /v1/api-tokens` requires `api_tokens:manage` — the same capability as issuance, because
no separate read capability exists in §4.1 and inventing one would widen the policy without
a decision. It is treated as an information-disclosure boundary:

- **Metadata only.** The response carries `token_prefix` — the public fragment that lets a
  human recognise a credential, as GitHub shows `ghp_…` — and never the secret or its
  SHA-256 digest. The read model has no field able to hold either, so this is a property of
  the schema rather than of a filter someone must remember to apply.
- **A machine token cannot enumerate the Workspace's credentials.** Reconnaissance is how a
  stolen credential is used well: knowing how many tokens exist, what they are named, and
  which are already revoked tells an attacker which to impersonate and when they would be
  noticed. Machine identity resolves to no membership (ADR-0002), so the boundary that stops
  a token minting another also stops it reading the list.
- **A denial discloses nothing** — no count, ids, prefixes, names, workspace id, or the name
  of the permission required. Echoing the required permission would let a prober map the
  API's authorization surface endpoint by endpoint.
- **The tenant comes from the authenticated context.** No query, path, body, or header field
  names a Workspace, and the pagination cursor carries a position rather than an authority
  (ADR-0011), so a forged cursor cannot cross a tenant boundary.

### 4.6 API token revocation

`DELETE /v1/api-tokens/{id}` requires `api_tokens:manage` and returns 204.

- **Effective immediately.** `revoked_at` is set and the single existing resolver
  (`get_workspace_context`) rejects the token on its next use — there is no cache to expire
  and no second validity mechanism. MCP_RUNTIME.md §5: revoking "severs every client using
  it immediately". A request that authenticated *before* the revocation committed completes
  normally; revocation binds every request that begins after the commit.
- **A state transition, not a row deletion.** The row survives with `revoked_at` set and
  stays visible in listings, which is what lets an incident review establish that a
  credential existed and when it stopped working. (`credentials` are different — §3 of
  DATABASE_DESIGN.md deletes those rows outright.)
- **Idempotent**, preserving the *first* `revoked_at`. Revocation is what an operator
  reaches for mid-incident, often through a retry or a script run twice; an error on the
  second attempt would imply the credential is somehow still live at the moment certainty
  matters most. Preserving the original timestamp keeps the audit trail honest — an
  unconditional overwrite would record the retry instead of the incident.
- **One-way.** There is no un-revoke operation, so a compromised credential cannot be
  restored (ADR-0012).
- **A machine token cannot revoke anything, including itself.** Otherwise a stolen
  credential could cut off every *other* token in the Workspace — including the operator's
  — turning a compromise into a denial of service during the response to it.
- **Cross-tenant targets answer `not_found`, identically to an id that never existed**
  (§3), so the endpoint cannot be used to probe which token ids are real elsewhere.
  Creating a token grants no authority over it: `created_by_member_id` is provenance, and
  authority comes from the role matrix alone.

### 4.7 Invitation issuance and acceptance

Invitations let an `owner`/`admin` add a person to a Workspace by email; the recipient
accepts with a verified Better Auth identity and becomes a Member (ADR-0017). The invitation
is a temporary membership-establishment mechanism — the resulting membership row is the only
authority, and the permanent chain (verified `sub` → `members.user_id` → persisted role →
RBAC → RLS) is unchanged.

- **Creating, listing, and cancelling require `members:manage`**, the same capability as
  member management (§4.3), with the workspace taken from `X-Workspace-Id`. No new permission
  and no endpoint-local role check. A machine token cannot invite: machine identity resolves
  to no membership (ADR-0002), so it is denied like every other `members:manage` action.
- **The role is server-set at creation and the recipient never sees or chooses it.** The
  creation schema forbids unknown fields, so supplying `invited_by`, `token`, or `status` is a
  `400 validation_error`, not a silent no-op. Role validity is checked against the canonical
  domain; *which* roles an inviter may assign is the same role-transition question §4.1 leaves
  open, deliberately not narrowed here.
- **Acceptance is the one narrow, explicitly-authorized exception to the claim-distrust rule**
  (ADR-0015; ADR-0017 §3). It requires a verified JWT whose **provider-verified** email
  (`email_verified = true`) equals the invitation's `invited_email`, both lower-cased. The
  email is used *only* to bind the invitation to the accepting identity — never for role,
  permission, workspace, or member identity. `members.user_id` is always the verified `sub`.
  **An unverified email can never accept**, so signing up under a victim's address without
  proving control of it gains nothing.
- **The token is a 256-bit secret; only its SHA-256 digest is stored.** The raw token exists
  only in the delivered email and in-flight during acceptance — never logged, persisted, or
  returned. Resolution is by hash through the `auth.resolve_invitation` SECURITY DEFINER
  bootstrap: an accepting user has no workspace yet, so the lookup that discovers it runs
  pre-RLS (DATABASE_DESIGN.md §6); everything after runs under the bound workspace's RLS.
- **Single-use and atomic.** Acceptance is one transaction: resolve → bind workspace → create
  membership → consume under `WHERE status = 'pending'`. Two concurrent acceptances serialize
  on the row lock, so exactly one consumes it, and the `(workspace_id, user_id)` membership
  unique constraint makes a second membership impossible; any failure rolls the whole thing
  back, leaving the invitation unconsumed. Expiry (7 days) is server-enforced.
- **Already a member → `409`, and the invitation is not consumed.** The existing membership
  stays authoritative and its role is never silently changed.
- **No enumeration oracle.** A bad, expired, cancelled, consumed, foreign, or wrong-email
  acceptance all return one uniform `404` — nothing reveals whether an invitation exists, for
  whom, or in which workspace. The create/list/cancel surfaces disclose only the caller's own
  tenant; a cross-tenant invitation id is byte-identical to one that never existed (§3).
- **Delivery is a first-party control-plane call.** The invitation email goes through Resend —
  platform mail sent by the API, not tenant egress through the Execution Runtime, the same
  class as the JWKS fetch (§6 permits first-party calls). The Resend key, the raw token, and
  the invite URL never appear in logs.

### 4.8 Human session and JWT lifecycle (ADR-0018)

The human plane is Better Auth (session + cookie) in the web tier and a short-lived EdDSA JWT
at the API; the two are distinct credentials with distinct lifetimes. M1.3-G pins the boundary
between them.

- **The API is `Authorization: Bearer`-only.** It never reads the Better Auth session cookie,
  so a stolen cookie is inert against the API and the machine/human planes cannot be confused.
  A cookie presented alone is a `401` (missing credential); a cookie value smuggled into the
  Bearer slot is neither an `omc_` token nor a JWT and fails the uniform human `401`.
- **A duplicate `Authorization` header is refused, fail-closed.** Two credential headers are
  never silently resolved to the first — the same rule §4.2 / ADR-0016 §3 apply to
  `X-Workspace-Id`. Ambiguity denies.
- **JWT lifetime is 900 s (15 min).** The verifier enforces `exp` (plus issuer/audience/EdDSA);
  nothing extends it.
- **Logout revokes the session, not outstanding JWTs.** Sign-out deletes the Better Auth
  session row and clears the session cookies, so **no new JWT can be minted** afterward — but an
  **already-issued JWT stays valid on the API until its `exp`** (≤ 15 min). This is the
  deliberate, documented consequence of a stateless verifier that holds no session state and
  cannot read the `identity` schema (ADR-0014): there is **no immediate JWT revocation**. The
  short TTL bounds the replay window. This boundary is claimed here *only because it is
  empirically tested*, not assumed.
- **Immediate lockout is Member removal.** Removing the membership denies the caller on their
  very next request (the role is read from the row every time, §4.2). That is the fast lever;
  JWT expiry is the slow one.
- **Break-glass (all sessions at once).** To invalidate *every* outstanding JWT before its exp,
  an operator removes the signing key from `identity.jwks`; propagation is bounded by the 300 s
  JWKS cache TTL. Rotating `BETTER_AUTH_SECRET` alone breaks *signing*, not verification, so it
  is **not** a revocation lever. This is an operator action, not an application feature.
- **Session fixation is resisted:** no cookie is set before authentication and each login mints
  a fresh session token.
- **CORS/CSRF posture.** The API configures no CORS (it is server-to-server; a Bearer API has no
  cookie for a foreign origin to abuse, and browsers cannot cross-origin-read it). Better Auth's
  own Origin check defends its cookie-authenticated endpoints. Both depend on a deployment origin
  topology that is **not yet decided** — see ADR-0018 for that and the other deferred lifecycle
  decisions (immediate revocation, rate limiting, security headers, session-lifetime cap,
  password reset, account disable/delete, social OAuth). None are silently defaulted.

## 5. Secrets handling rules

1. Secrets live in `.env` files (local) and platform secret stores (Railway/Vercel) —
   never in code, config committed to git, or CI logs (Bible §6.7).
2. `.env.example` is the contract: **every** variable the app reads appears there with a
   placeholder and a one-line comment. Adding a config value without updating
   `.env.example` fails review.
3. **Gitleaks runs in CI** on every push/PR (see .github/workflows/ci.yml `security` job,
   full history via `fetch-depth: 0`). A hit blocks merge; the leaked value is rotated
   even if the commit never merged.
4. Rotation runbook (stub, expand at M1): identify secret → generate replacement →
   update platform secret store → redeploy → verify → revoke old value → note in
   MEETING_NOTES.md. `CREDENTIAL_MASTER_KEY` follows the re-wrap procedure in §2.1.

## 6. Outbound-call security (SSRF and abuse)

The Execution Runtime is the only egress (Bible §6.3), which concentrates SSRF defense in
one place:

- **Private ranges blocked by default:** outbound targets are resolved and checked before
  connect; RFC 1918, loopback, link-local (169.254.0.0/16, incl. cloud metadata endpoints),
  and unique-local/loopback IPv6 are rejected. Resolution and validation happen at connect
  time to defeat DNS rebinding; redirects are re-validated per hop.
- **Per-workspace egress allowlist:** a Connection declares its base URL(s) at creation;
  the runtime refuses requests outside the Connection's allowed hosts. Workspaces may
  further restrict egress (Enterprise control).
- **Response caps:** response size limit (default 10 MB, configurable per Connector) and
  timeout (default 30s, per Architecture §7) — streamed with early abort, protecting the
  runtime from decompression bombs and slow-loris upstreams.
- Rate limits and quotas checked in Redis before every call; circuit breaker per
  Connection; quota checks **fail closed** if Redis is unavailable (Architecture §7).

## 7. Dependency and supply chain

- Lockfiles are mandatory and committed: `pnpm-lock.yaml` (web) and `uv.lock` (api,
  ADR-0006). CI installs from lockfiles once bootstrap churn ends.
- Dependabot enabled for npm, pip (uv), Docker base images, and GitHub Actions; security
  updates merged within the review SLA (CODING_STANDARDS.md).
- GitHub Actions are version-pinned today (`@v4`/`@v5`); we move to full commit-SHA
  pinning before handling production credentials in CI.
- Docker images build from `infra/docker/` with slim official base images; no `latest`
  tags in deploy manifests.

## 8. Incident response and responsible disclosure

Basics, sized for a two-person team; formalized before GA:

1. **Detect:** Sentry alerts, Better Stack uptime, Gitleaks hits, anomalous Tool Call
   patterns in the audit log.
2. **Triage:** severity call by whoever is on point; anything touching Credentials or
   tenant isolation is automatically SEV-1.
3. **Contain:** revoke affected API tokens/Credentials, rotate platform secrets (§5.4),
   disable affected Connections. The runtime-only egress means containment has one choke
   point.
4. **Notify:** affected Workspaces within 72 hours for confirmed data exposure.
5. **Learn:** blameless write-up in MEETING_NOTES.md; permanent fixes tracked; RISKS.md
   updated.

**Responsible disclosure:** report vulnerabilities to **security@omniaiconnect.com**.
We acknowledge within 48 hours, do not pursue good-faith researchers, and credit fixes
publicly if desired. A `security.txt` ships with the marketing site at launch.

## 9. Compliance path

SOC 2 is deliberately deferred, but the design keeps it cheap when Team/Enterprise demand
arrives:

- **Audit log from day one** — every Tool Call is audit-logged (Bible §4), giving us the
  activity-trail evidence auditors ask for without retrofitting.
- **Least privilege** — role matrix (§4.1), workspace-scoped tokens, runtime-only
  decryption map directly to access-control criteria.
- **Single egress** — one choke point to document and monitor instead of N services.
- **Managed providers** (Neon, Upstash, Vercel, Railway, Cloudflare, Stripe) carry their
  own SOC 2 reports we can inherit in vendor review.
- Remaining gap when we start: formal policies, background checks, and a KMS-backed
  master key (§2.1) — all scoped, none architectural.
