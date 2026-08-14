"""Structural guarantees about token issuance that need no database.

These assert *shapes*, not behaviour: that persistence has no parameter capable of
accepting a secret, and that the objects carrying a secret cannot render it. Both are
properties a reviewer would otherwise have to re-derive by reading, and both are exactly
the kind of thing a well-meant refactor removes without noticing.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect

from app.core import security
from app.core.security import TOKEN_PREFIX, GeneratedToken, generate_token
from app.domains.workspaces.repository import ApiTokenRepository
from app.domains.workspaces.schemas import ApiTokenCreate, ApiTokenRead
from app.domains.workspaces.service import IssuedApiToken


def test_persistence_has_no_parameter_that_accepts_a_plaintext() -> None:
    """A comment saying "pass the hash" is a convention; a signature without a plaintext
    parameter is a guarantee. Storing a usable credential is not a mistake this codebase
    can make, and this fails if someone adds a convenience `plaintext=` argument."""
    params = set(ApiTokenRepository.create.__annotations__)

    assert "token_hash" in params
    assert {"plaintext", "token", "secret", "password"} & params == set()
    # `workspace_id` is likewise absent: the tenant comes from the context (M1.2-B).
    assert "workspace_id" not in params


def test_the_read_schema_has_no_field_that_could_carry_a_secret() -> None:
    """`ApiTokenRead` is what every list/detail response returns. It must be incapable of
    emitting a credential even if one were somehow attached to the ORM object."""
    fields = set(ApiTokenRead.model_fields)

    assert {"token", "plaintext", "token_hash", "secret"} & fields == set()
    assert "token_prefix" in fields


def test_creation_schema_forbids_server_owned_fields() -> None:
    """Pydantic's default is to ignore unknown keys, which would silently accept a client's
    `created_by_member_id` and return 201 as though it were honoured."""
    assert ApiTokenCreate.model_config.get("extra") == "forbid"
    assert set(ApiTokenCreate.model_fields) == {"name"}


def test_objects_holding_a_plaintext_do_not_render_it() -> None:
    """structlog calls `repr()` on non-primitive values, so a default dataclass repr turns
    `log.info("issued", result=x)` into a credential disclosure. Both carriers exclude the
    field, so reaching the secret requires naming `.plaintext` deliberately."""
    generated = generate_token()

    for text in (repr(generated), str(generated), f"{generated}"):
        assert generated.plaintext not in text

    for carrier in (GeneratedToken, IssuedApiToken):
        plaintext_field = next(f for f in dataclasses.fields(carrier) if f.name == "plaintext")
        assert plaintext_field.repr is False, f"{carrier.__name__}.plaintext is in its repr"


def test_secrets_are_minted_from_the_cryptographic_generator() -> None:
    """Asserted structurally, because randomness quality is not observable in a test.

    `random.choice` and `secrets.choice` produce output that is indistinguishable to any
    assertion this suite could make — both are unique per call, both look like noise — yet
    the Mersenne Twister is fully reconstructible from ~624 observed outputs, which for an
    issuance endpoint means an attacker who mints a few tokens can predict everyone else's.
    Nothing behavioural catches that substitution, so the guarantee has to be pinned to the
    call itself: the AST of `generate_token` must invoke `secrets`, and the module must not
    import `random` at all.
    """
    source = inspect.getsource(security)
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(a.name != "random" for a in node.names), "`random` imported in security.py"
        if isinstance(node, ast.ImportFrom):
            assert node.module != "random", "`random` imported in security.py"

    generator = next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "generate_token"
    )
    called = {
        ast.unparse(n.func)
        for n in ast.walk(generator)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert "secrets.token_urlsafe" in called, f"generate_token no longer uses secrets: {called}"


def test_the_secret_carries_at_least_128_bits_of_entropy() -> None:
    """A floor on entropy, not an exact-length assertion.

    Tokens are unguessable only while the search space is: at 32 bytes a brute-force is
    astronomically infeasible, at 4 bytes it is a few billion attempts — trivial for an
    endpoint an attacker can hammer. Length is the observable proxy, and the bound is set
    at 128 bits so shortening the secret toward guessability fails here rather than
    silently shipping. `token_urlsafe(n)` yields ceil(4n/3) base64url characters, each
    carrying 6 bits.
    """
    body = generate_token().plaintext.removeprefix(TOKEN_PREFIX)

    assert len(body) * 6 >= 128, f"token entropy collapsed to ~{len(body) * 6} bits"
    assert len({generate_token().plaintext for _ in range(200)}) == 200
