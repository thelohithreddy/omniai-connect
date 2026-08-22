"""Connection Health failure notifications (M2.10, ROADMAP §58; architecture ratified in ADR-0041).

One notification service behind two triggers, and nothing else in the repository sends mail about a
Connection:

- an ordinary health check that finds the Connection unusable (`POST /v1/connections/{id}/test`);
- the OAuth refresh worker exhausting its retry budget, which is the only failure in the system
  that happens with no human present.

Both converge here. Neither has its own email code path, its own Redis key space, or its own idea
of what counts as a failure — a second implementation is how two triggers drift into two products.

Three boundaries this package does not cross:

- **No identity.** Recipients are never resolved from `identity.user`; ADR-0014 keeps that
  unreachable in both directions. The destination is the address an owner typed, stored on the
  Workspace row (ADR-0041 §5). The ratified recipient contract is *"the Workspace's declared
  notification destination"* — explicitly **not** "Owners and Admins" (ADR-0041 §6).
- **No health authority.** Nothing here reads, writes, or influences a Connection's health. A
  failed send, an unreachable Redis, or a dead provider leaves the verdict and its timestamp
  exactly as the Runtime left them.
- **No secrets.** Credentials are never decrypted here, never enter a Celery argument, never enter
  a Redis key or value, and never enter an email body.

Delivery is best-effort by construction. The bus is at-most-once (ADR-0023), so a crash between
COMMIT and dispatch loses a notification; Redis dedup is not durable, so a flush may permit one
duplicate. Both are accepted for M2 (ADR-0041 §8/§9). Durable exactly-once delivery is
`webhooks_outbox`, which is M3.
"""
