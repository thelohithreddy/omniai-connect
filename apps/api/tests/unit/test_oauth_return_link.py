"""The OAuth callback's return link (MC1.5, ADR-0044 D1).

D1 adds one thing to an already-audited terminal page: a link back to the control plane. The
security property it must not break is the one the page was built around — **the callback is not an
oracle and not a redirect surface**.

So these tests are mostly about what the link is *not*. It is a server constant built from
`settings.next_public_app_url` and nothing else: not from `code`, not from `state`, not from any
query parameter. That is what keeps open-redirect structurally impossible here rather than merely
guarded, and it is why the href must be byte-identical on success and failure — a link that varied
would leak which outcome occurred to anyone who could see the markup but not the status code.
"""

from __future__ import annotations

import re

import pytest

from app.core.config import settings
from app.domains.oauth.router import _failure_html, _return_link, _success_html

HREF = re.compile(r'href="([^"]*)"')


def _hrefs(html: str) -> list[str]:
    return HREF.findall(html)


def test_the_link_is_the_configured_app_url_and_nothing_else() -> None:
    """A server constant, so no attacker-influencable value can reach it."""
    assert _return_link() == f"{settings.next_public_app_url.rstrip('/')}/connections"


def test_success_and_failure_carry_a_byte_identical_link() -> None:
    """A link that differed by outcome would disclose the outcome independently of the status code.

    The pages differ — one says authorized, the other says failed — but the *href* must not.
    """
    assert _hrefs(_success_html()) == _hrefs(_failure_html())
    assert len(_hrefs(_success_html())) == 1


def test_the_link_does_not_vary_with_any_provider_parameter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Anti-reflection: the renderers take no request input at all.

    `_success_html` and `_failure_html` accept no arguments, so there is no parameter for `code`,
    `state` or an error description to travel through. This asserts the property rather than
    trusting the signature.
    """
    hostile = "https://evil.example/steal?a=1"
    monkeypatch.setattr(settings, "next_public_app_url", "https://app.omniai.example")

    for html in (_success_html(), _failure_html()):
        assert hostile not in html
        assert "evil.example" not in html
        assert _hrefs(html) == ["https://app.omniai.example/connections"]


def test_a_trailing_slash_in_configuration_does_not_double_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "next_public_app_url", "https://app.omniai.example/")
    assert _return_link() == "https://app.omniai.example/connections"


def test_a_configured_url_is_escaped_before_it_reaches_markup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Belt and braces.

    The value is operator-set rather than attacker-set, so this is not the primary control — but a
    configuration string still has no business being interpolated into HTML unescaped, and a
    misconfiguration should not become markup injection on an unauthenticated page.
    """
    monkeypatch.setattr(settings, "next_public_app_url", 'https://a.example/"><script>x</script>')

    for html in (_success_html(), _failure_html()):
        assert "<script>" not in html
        assert "&lt;script&gt;" in html or "&quot;" in html


def test_the_page_still_discloses_nothing_about_the_failure() -> None:
    """The uniform-failure property D1 must preserve.

    The failure page names no state, no connection, no workspace and no provider detail — only that
    the link is invalid or expired, which is true of every failure mode alike.
    """
    failure = _failure_html()

    for forbidden in ("state", "connection_id", "workspace", "token", "code=", "traceback"):
        assert forbidden not in failure.lower(), f"the failure page disclosed {forbidden!r}"


def test_both_pages_stay_noindex() -> None:
    """An unauthenticated terminal page must not enter a search index."""
    for html in (_success_html(), _failure_html()):
        assert 'name="robots" content="noindex"' in html
