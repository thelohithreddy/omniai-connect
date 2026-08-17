"""ObjectStore configuration resolution — fail closed, TLS in prod, no secret leakage (B0.5).

No network. Proves that storage configuration is validated explicitly: incomplete config fails
closed naming (not valuing) the gap, production must speak TLS, local/CI may use plaintext MinIO,
and the secret is never exposed by an error or a config repr.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.core.object_store import (
    ObjectStoreConfig,
    StorageConfigError,
    resolve_object_store_config,
)

SECRET = "super-secret-access-key-value"  # noqa: S105 (a test fixture value, not a real secret)


def _settings(**over: object) -> Settings:
    base: dict[str, object] = {
        "app_env": "development",
        "r2_endpoint": "http://minio:9000",
        "r2_bucket": "omniai-dev",
        "r2_access_key_id": "minioadmin",
        "r2_secret_access_key": SecretStr(SECRET),
        "r2_region": "auto",
    }
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


def test_a_complete_local_config_resolves() -> None:
    cfg = resolve_object_store_config(_settings())
    assert isinstance(cfg, ObjectStoreConfig)
    assert cfg.endpoint_url == "http://minio:9000"
    assert cfg.bucket == "omniai-dev"


@pytest.mark.parametrize(
    "missing",
    [
        {"r2_endpoint": ""},
        {"r2_bucket": ""},
        {"r2_access_key_id": ""},
        {"r2_secret_access_key": SecretStr("")},
    ],
)
def test_incomplete_config_fails_closed(missing: dict[str, object]) -> None:
    with pytest.raises(StorageConfigError):
        resolve_object_store_config(_settings(**missing))


def test_a_config_error_names_the_missing_setting_but_never_its_value() -> None:
    # The secret is a REAL value here and only the bucket is missing, so an error that dumped the
    # settings would leak the live secret — the message must name the gap, never the values.
    with pytest.raises(StorageConfigError) as exc:
        resolve_object_store_config(_settings(r2_bucket=""))
    message = str(exc.value)
    assert "R2_BUCKET" in message
    assert SECRET not in message  # the live secret is never surfaced
    assert "minioadmin" not in message  # nor the access key id


def test_production_requires_a_tls_endpoint() -> None:
    """Production must not speak plaintext, and must never silently accept a MinIO http endpoint."""
    with pytest.raises(StorageConfigError):
        resolve_object_store_config(
            _settings(app_env="production", r2_endpoint="http://minio:9000")
        )


def test_production_accepts_an_https_endpoint() -> None:
    cfg = resolve_object_store_config(
        _settings(
            app_env="production",
            r2_endpoint="https://acct.r2.cloudflarestorage.com",
        )
    )
    assert cfg.endpoint_url.startswith("https://")


def test_local_may_use_a_plaintext_minio_endpoint() -> None:
    cfg = resolve_object_store_config(_settings(app_env="development"))
    assert cfg.endpoint_url == "http://minio:9000"


def test_the_resolved_config_repr_does_not_leak_the_secret() -> None:
    cfg = resolve_object_store_config(_settings())
    assert SECRET not in repr(cfg)
    assert SECRET not in str(cfg)
