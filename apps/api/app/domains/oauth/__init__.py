"""OAuth 2.0 authorization-code flow (M2.5, ADR-0038).

Owns the browser-mediated dance and nothing else: provider configuration is the connectors
domain's (`connectors/oauth_config.py`), token *storage* is the credentials domain's (the vault
seals every token set), execution is the Runtime's, and the Connection lifecycle stays with its
own domain's events. This package contributes the one piece none of them own — the single-use,
tenant-bound `oauth_states` row that makes an unauthenticated provider redirect safe to trust.

Founder-ratified scope (D1–D5): backend owns the flow and the callback; `authorization_code` +
PKCE S256 + refresh tokens only; refresh failure transitions the Connection to `error` and emits
`connection.deactivated` (no `webhooks_outbox` here — that belongs to Connection Health).
"""
