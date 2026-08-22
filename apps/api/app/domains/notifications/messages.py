"""Rendering the notification email. Pure, allowlisted, and hostile to its own inputs.

Everything in a notification body is either a constant defined here or a value drawn from a closed
set. Exactly one variable is free text — the Connection's name, which a user typed — and it is HTML
-escaped, because a Connection called `<img src=x onerror=...>` would otherwise be rendered by the
recipient's mail client. The name is also length-capped: the column allows 120 characters, and a
subject line is not the place to discover that.

What can never appear here, per ADR-0041 and SECURITY.md §2.2: credentials in any form, an
`Authorization` header, an access or refresh token, an API key, a provider response body, an
exception string or traceback, or a URL supplied by a third party. The failure is described by the
Runtime's **stable error code** — an enumerated token — never by a provider's message, which is
attacker-influenced text that may itself contain a leaked secret.
"""

from __future__ import annotations

from html import escape

from app.domains.notifications.classification import NotificationEvent

#: Connection names are `String(120)`; a subject line gets a tighter budget than the column does.
_NAME_LIMIT = 80

#: Human-readable, non-secret summaries of the two notifiable failures. Closed set: the caller
#: passes a `NotificationEvent`, so no free text can reach a heading.
_HEADLINE: dict[NotificationEvent, str] = {
    NotificationEvent.UNHEALTHY: "is failing health checks",
    NotificationEvent.NEEDS_REAUTH: "needs to be reconnected",
}

_EXPLANATION: dict[NotificationEvent, str] = {
    NotificationEvent.UNHEALTHY: (
        "A health check ran against this Connection and the provider did not respond "
        "successfully. Tool Calls using this Connection are likely to fail until it recovers."
    ),
    NotificationEvent.NEEDS_REAUTH: (
        "This Connection's OAuth authorization has expired and automatic refresh has been "
        "exhausted. It cannot be recovered automatically — someone needs to reconnect it."
    ),
}

_REMEDIATION: dict[NotificationEvent, str] = {
    NotificationEvent.UNHEALTHY: (
        "Check whether the provider is reachable and whether the Connection's credential is "
        "still valid, then run the Connection test again."
    ),
    NotificationEvent.NEEDS_REAUTH: (
        "Re-authorize the Connection to restore access. No credential was lost; the stored "
        "authorization simply can no longer be refreshed."
    ),
}


def _display_name(raw: str) -> str:
    """Escape and bound a user-supplied Connection name for safe inclusion in an email."""
    trimmed = raw.strip()[:_NAME_LIMIT]
    # Escape after truncation so a cut can never land inside an entity and produce broken markup.
    return escape(trimmed) if trimmed else "(unnamed Connection)"


def subject(*, connection_name: str, event: NotificationEvent) -> str:
    """The subject line. Escaped for the same reason the body is: some clients render it."""
    return f"[OmniAI Connect] Connection “{_display_name(connection_name)}” {_HEADLINE[event]}"


def html_body(*, connection_name: str, event: NotificationEvent, reason_code: str | None) -> str:
    """The message body.

    `reason_code` is the Runtime's stable, enumerated error code (`upstream_error`, `timeout`,
    `ssrf_blocked`, …) or None. It is rendered through the same escaper as everything else — not
    because an enumerated token needs escaping today, but because the one place a future
    non-enumerated value could leak in should already be closed.
    """
    name = _display_name(connection_name)
    code_line = (
        f'<p style="color:#666">Reported reason: <code>{escape(reason_code)}</code></p>'
        if reason_code
        else ""
    )
    return (
        "<div>"
        f"<p>The Connection <strong>“{name}”</strong> {_HEADLINE[event]}.</p>"
        f"<p>{_EXPLANATION[event]}</p>"
        f"{code_line}"
        f"<p>{_REMEDIATION[event]}</p>"
        "<hr>"
        '<p style="color:#666;font-size:12px">'
        "You are receiving this because this address is set as your Workspace's notification "
        "destination in OmniAI Connect. An owner can change or remove it in workspace settings."
        "</p>"
        "</div>"
    )


__all__ = ["html_body", "subject"]
