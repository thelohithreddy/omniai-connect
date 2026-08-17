"""Audit Log Viewer — a read-only, tenant-isolated view of the Tool Call ledger (M1-Audit-v1).

The Execution Runtime writes one immutable `tool_calls` row per Tool Call (AI_RUNTIME §2 stage 7);
this domain is the authorized *read* surface over that ledger (PRD FR-CP-3 / UJ-5). It reuses the
existing `tool_calls` table — it does not duplicate it, does not create a second audit system, and
cannot mutate it (the app role holds no UPDATE/DELETE grant on `tool_calls`, and this domain issues
only SELECTs). It exposes redacted metadata only; it never touches a Credential, a decrypt path, or
the execution pipeline.
"""
