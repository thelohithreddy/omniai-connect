"""Vault-access audit and the bounded decrypt metric (M2.6 ratified A2, ADR-0039). No DB.

A2 ratified logs + metrics and explicitly **no** new table and no second audit ledger, so the
audit's correctness is entirely a question of what the boundary emits. Two properties are tested
here and nothing else pretends to cover them:

1. **Completeness** — every call at the single decrypt boundary is recorded, success *and* each
   distinct failure. An audit that only records successes is worse than none: it reads as a
   complete history while omitting exactly the events an investigation needs.
2. **Safety** — the record itself carries no secret. An audit trail that leaks the thing it audits
   converts one incident into two.
"""

from __future__ import annotations

import json
import uuid

import pytest
import structlog

from app.core import metrics
from app.core.logging import configure_logging
from app.domains.credentials import vault
from app.domains.credentials.models import CREDENTIAL_TYPES, Credential
from app.domains.credentials.vault import VaultDecryptError, VaultKeyVersionError
from app.domains.runtime import secrets as secrets_module
from app.domains.runtime.secrets import open_credential_secret

WS = uuid.uuid4()
CONN = uuid.uuid4()

SECRET_VALUE = "M2_6_AUDIT_CANARY_value"  # noqa: S105 (synthetic test secret)


def _credential(plaintext: bytes, *, credential_type: str = "api_key") -> Credential:
    sealed = vault.seal(plaintext, workspace_id=WS, connection_id=CONN)
    return Credential(
        id=uuid.uuid4(),
        workspace_id=WS,
        connection_id=CONN,
        credential_type=credential_type,
        ciphertext=sealed.ciphertext,
        encrypted_dek=sealed.encrypted_dek,
        nonce=sealed.nonce,
        key_version=sealed.key_version,
    )


@pytest.fixture(autouse=True)
def _clean_metrics() -> None:
    metrics.reset()
    yield
    metrics.reset()


@pytest.fixture
def audit_logs(monkeypatch: pytest.MonkeyPatch):
    """Capture emitted events without depending on structlog's logger cache.

    structlog's own testing helper swaps the processor chain, which does nothing for a logger that
    was already bound and cached — and `configure_logging` sets `cache_logger_on_first_use=True`
    deliberately (see conftest). So these assertions passed when the module ran alone and failed in
    a full run, purely on whether some earlier test had already opened a credential. Reconfiguring
    with caching off removes the ordering dependence instead of papering over it.
    """
    captured: list[dict] = []

    def capture(_logger, _method, event_dict):
        captured.append(dict(event_dict))
        return event_dict

    structlog.configure(
        processors=[capture],
        wrapper_class=structlog.make_filtering_bound_logger(10),
        logger_factory=structlog.ReturnLoggerFactory(),
        cache_logger_on_first_use=False,
    )
    # Reconfiguring is not enough on its own: `secrets.log` is a module-level lazy proxy and
    # `cache_logger_on_first_use=True` means it binds its processors once, on first use, and keeps
    # them. If any earlier test opened a credential, that proxy is already bound to the production
    # chain and would ignore the capture entirely — which is exactly how these assertions passed
    # alone and failed in a full run. Swapping in a fresh, unbound proxy is what makes the capture
    # actually observe the boundary; monkeypatch restores the original afterwards.
    monkeypatch.setattr(secrets_module, "log", structlog.get_logger("m26-audit-capture"))
    try:
        yield captured
    finally:
        configure_logging()


# ------------------------------------------------------------------ completeness


def test_a_successful_open_is_audited(audit_logs) -> None:
    credential = _credential(json.dumps({"value": SECRET_VALUE}).encode())
    open_credential_secret(credential, workspace_id=WS, connection_id=CONN)
    events = [entry for entry in audit_logs if entry["event"] == "vault.credential_opened"]
    assert len(events) == 1
    assert events[0]["outcome"] == "ok"
    assert events[0]["workspace_id"] == str(WS)
    assert events[0]["credential_id"] == str(credential.id)
    assert events[0]["key_version"] == credential.key_version


def test_a_failed_open_is_audited_not_silently_dropped(audit_logs) -> None:
    """The event an investigation actually needs: someone tried to open a credential and could
    not. If only successes were recorded, a workspace-transplant attempt would leave no trace."""
    credential = _credential(json.dumps({"value": SECRET_VALUE}).encode())
    with pytest.raises(VaultDecryptError):
        open_credential_secret(credential, workspace_id=uuid.uuid4(), connection_id=CONN)
    events = [entry for entry in audit_logs if entry["event"] == "vault.credential_open_failed"]
    assert len(events) == 1
    assert events[0]["outcome"] == "decrypt_failed"


def test_a_retired_key_is_audited_distinctly_from_tampering(
    monkeypatch: pytest.MonkeyPatch, audit_logs
) -> None:
    """`key_unavailable` and `decrypt_failed` demand opposite operator responses — restore the key
    versus investigate an attack. Collapsing them into one outcome would send the on-call engineer
    hunting for an intruder during a botched rotation."""
    import base64
    import os

    def _key() -> str:
        return base64.b64encode(os.urandom(32)).decode()

    from pydantic import SecretStr

    monkeypatch.setattr(vault.settings, "credential_master_key", SecretStr(_key()))
    monkeypatch.setattr(vault.settings, "credential_master_keys", SecretStr(f"2:{_key()}"))
    monkeypatch.setattr(vault.settings, "credential_key_version", 2)
    credential = _credential(json.dumps({"value": SECRET_VALUE}).encode())
    monkeypatch.setattr(vault.settings, "credential_master_keys", SecretStr(""))
    monkeypatch.setattr(vault.settings, "credential_key_version", 1)

    with pytest.raises(VaultKeyVersionError):
        open_credential_secret(credential, workspace_id=WS, connection_id=CONN)
    events = [entry for entry in audit_logs if entry["event"] == "vault.credential_open_failed"]
    assert [entry["outcome"] for entry in events] == ["key_unavailable"]


def test_a_malformed_payload_is_audited(audit_logs) -> None:
    credential = _credential(b"this is not json")
    with pytest.raises(VaultDecryptError):
        open_credential_secret(credential, workspace_id=WS, connection_id=CONN)
    assert [e["outcome"] for e in audit_logs if "outcome" in e] == ["malformed"]


# ------------------------------------------------------------------ safety (no secret in audit)


def test_the_audit_record_never_contains_the_secret(audit_logs) -> None:
    """The whole audit payload is serialized and searched for the plaintext. An audit trail that
    leaks the credential it audits turns one incident into two."""
    credential = _credential(json.dumps({"value": SECRET_VALUE}).encode())
    open_credential_secret(credential, workspace_id=WS, connection_id=CONN)
    rendered = json.dumps(audit_logs, default=str)
    assert SECRET_VALUE not in rendered


def test_the_audit_record_never_contains_ciphertext_or_key_material(audit_logs) -> None:
    credential = _credential(json.dumps({"value": SECRET_VALUE}).encode())
    open_credential_secret(credential, workspace_id=WS, connection_id=CONN)
    rendered = json.dumps(audit_logs, default=str)
    for material in (credential.ciphertext, credential.encrypted_dek, credential.nonce):
        assert material.hex() not in rendered
        assert str(material) not in rendered


# ------------------------------------------------------------------ the bounded metric


def test_every_open_increments_the_counter() -> None:
    credential = _credential(json.dumps({"value": SECRET_VALUE}).encode())
    open_credential_secret(credential, workspace_id=WS, connection_id=CONN)
    open_credential_secret(credential, workspace_id=WS, connection_id=CONN)
    key = ("vault.credential_opens", (("credential_type", "api_key"), ("outcome", "ok")))
    assert metrics.snapshot()[key] == 2


def test_failures_increment_a_distinct_series() -> None:
    credential = _credential(json.dumps({"value": SECRET_VALUE}).encode())
    with pytest.raises(VaultDecryptError):
        open_credential_secret(credential, workspace_id=uuid.uuid4(), connection_id=CONN)
    outcomes = {labels[1][1] for (_, labels) in metrics.snapshot()}
    assert outcomes == {"decrypt_failed"}


def test_metric_cardinality_is_bounded_by_construction() -> None:
    """The property that keeps a counter from becoming an outage. Every label value the decrypt
    boundary can produce is drawn from a closed set, so the series count has a hard ceiling —
    6 credential types × 4 outcomes. An id-shaped label would be unbounded and is refused."""
    for credential_type in CREDENTIAL_TYPES:
        for outcome in ("ok", "decrypt_failed", "key_unavailable", "malformed"):
            metrics.increment(
                "vault.credential_opens", credential_type=credential_type, outcome=outcome
            )
    assert len(metrics.snapshot()) == len(CREDENTIAL_TYPES) * 4

    with pytest.raises(ValueError):  # a workspace id would be one series per tenant, forever
        metrics.increment("vault.credential_opens", credential_type=str(uuid.uuid4()), outcome="ok")


def test_undeclared_metrics_and_labels_are_refused() -> None:
    with pytest.raises(ValueError):
        metrics.increment("vault.not_declared", outcome="ok")
    with pytest.raises(ValueError):
        metrics.increment("vault.credential_opens", outcome="ok")  # missing a declared label
    with pytest.raises(ValueError):
        metrics.increment(
            "vault.credential_opens", credential_type="api_key", outcome="ok", extra="x"
        )


def test_the_snapshot_cannot_be_mutated_by_a_caller() -> None:
    metrics.increment("vault.credential_opens", credential_type="api_key", outcome="ok")
    snapshot = metrics.snapshot()
    with pytest.raises(TypeError):
        snapshot[("x", ())] = 1  # type: ignore[index]


# ======================================= rendered-output audit (added by the M2.6 release audit)
#
# Every test above inspects the event dict *before* the processor chain runs. That is a blind
# spot: `configure_logging` installs a redaction processor that rewrites the event on its way
# out, so an assertion made upstream of it can pass while production emits something different.
# It did exactly that — `credential_type` matched the "credential" marker and shipped as
# «redacted», leaving an audit that could not say what kind of credential was opened.
#
# These tests therefore assert on the **rendered JSON line**, which is what an operator and an
# incident responder actually get.


def _render_open(credential: Credential) -> dict:
    """Open a credential through the real production logging chain and return the emitted JSON."""
    import contextlib
    import io

    configure_logging()
    # A fresh proxy, because `cache_logger_on_first_use=True` means the module-level logger keeps
    # whatever chain it first bound to. In production it binds once, to the production chain; in a
    # test run an earlier test has already bound it, so without this the rendered output would be
    # whatever renderer happened to be installed first.
    original = secrets_module.log
    secrets_module.log = structlog.get_logger("m26-audit-render")
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            open_credential_secret(credential, workspace_id=WS, connection_id=CONN)
    finally:
        secrets_module.log = original
    lines = [ln for ln in buffer.getvalue().splitlines() if "credential_opened" in ln]
    assert lines, "no audit line was emitted — the assertion below would be vacuous"
    return json.loads(lines[-1])


@pytest.mark.parametrize("app_env", ["production", "staging"])
def test_the_rendered_audit_line_identifies_what_was_opened(
    monkeypatch: pytest.MonkeyPatch, app_env: str
) -> None:
    """The audit must survive its own redactor. Asserted in both JSON-rendering environments."""
    from app.core import logging as logging_module

    monkeypatch.setattr(logging_module.settings, "app_env", app_env)
    credential = _credential(json.dumps({"value": SECRET_VALUE}).encode())
    event = _render_open(credential)

    assert event["credential_type"] == "api_key", event
    assert event["credential_id"] == str(credential.id), event
    assert event["workspace_id"] == str(WS), event
    assert event["key_version"] == credential.key_version, event
    assert event["outcome"] == "ok", event
    configure_logging()


def test_the_rendered_audit_line_still_carries_no_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exemption must not have opened a hole: the rendered line is searched for the plaintext
    and for every ciphertext component."""
    from app.core import logging as logging_module

    monkeypatch.setattr(logging_module.settings, "app_env", "production")
    credential = _credential(json.dumps({"value": SECRET_VALUE}).encode())
    raw = json.dumps(_render_open(credential))
    assert SECRET_VALUE not in raw
    for material in (credential.ciphertext, credential.encrypted_dek, credential.nonce):
        assert material.hex() not in raw
    configure_logging()


def test_a_secret_named_field_is_still_redacted_after_the_exemption() -> None:
    """The allowlist is exact-name. Anything else matching a marker still redacts."""
    from app.core.logging import REDACTED, redact_secrets

    out = redact_secrets(
        None,
        "info",
        {"credential_type": "oauth2", "credential": "sk-live-LEAK", "api_key": "sk-live-LEAK"},
    )
    assert out["credential_type"] == "oauth2"
    assert out["credential"] == REDACTED
    assert out["api_key"] == REDACTED
