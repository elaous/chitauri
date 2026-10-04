"""Exercises PostgresConfigStore against a real, disposable Postgres database.

Uses a separate `<configured db>_test` database (created and dropped around
the test run) rather than the dev database `DATABASE_URL` points at, so
running tests never touches data managed by `alembic upgrade head` /
`scripts/seed_config.py`. Skipped automatically if Postgres isn't reachable
or the test account can't create databases.
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db import Base
from app.settings import settings
from app.storage.base import ConfigValidationError, VerifiedBootKeyData
from app.storage.postgres_store import PostgresConfigStore

SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA2 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def _with_db_name(url: str, db_name: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=f"/{db_name}"))


@pytest.fixture
async def pg_store():
    base_url = settings.database_url
    db_name = (urlsplit(base_url).path.lstrip("/") or "graphene_attest") + "_test"
    admin_url = _with_db_name(base_url, "postgres")

    admin_engine = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        async with admin_engine.connect() as conn:
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
            await conn.execute(text(f'CREATE DATABASE "{db_name}"'))
    except Exception as e:
        pytest.skip(f"Postgres not reachable/usable at {admin_url}: {e}")
    finally:
        await admin_engine.dispose()

    test_url = _with_db_name(base_url, db_name)
    engine = create_async_engine(test_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with session_maker() as session:
        yield PostgresConfigStore(session)

    await engine.dispose()

    admin_engine2 = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
    async with admin_engine2.connect() as conn:
        await conn.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
    await admin_engine2.dispose()


async def test_upsert_and_get_os_profile(pg_store):
    await pg_store.upsert_os_profile(
        os_id="grapheneos",
        display_name="GrapheneOS",
        expected_verified_boot_state="SelfSigned",
    )
    profile = await pg_store.get_os_profile("grapheneos")
    assert profile is not None
    assert profile.display_name == "GrapheneOS"
    assert profile.verified_boot_keys == []

    assert await pg_store.get_os_profile("nonexistent") is None


async def test_add_verified_boot_keys_dedupes(pg_store):
    await pg_store.upsert_os_profile(
        os_id="grapheneos",
        display_name="GrapheneOS",
        expected_verified_boot_state="SelfSigned",
    )
    keys = [
        VerifiedBootKeyData(verified_boot_key_sha256=SHA),
        VerifiedBootKeyData(verified_boot_key_sha256=SHA),
        VerifiedBootKeyData(verified_boot_key_sha256=SHA2),
    ]
    added = await pg_store.add_verified_boot_keys("grapheneos", keys)
    assert added == 2

    # re-adding the same keys should add nothing
    added_again = await pg_store.add_verified_boot_keys("grapheneos", keys)
    assert added_again == 0

    profile = await pg_store.get_os_profile("grapheneos")
    assert len(profile.verified_boot_keys) == 2


async def test_add_verified_boot_keys_unknown_os_id_raises(pg_store):
    with pytest.raises(ConfigValidationError):
        await pg_store.add_verified_boot_keys(
            "nonexistent", [VerifiedBootKeyData(verified_boot_key_sha256=SHA)]
        )


async def test_policy_roundtrip(pg_store):
    await pg_store.set_policy_value("max_patch_age_days", "90")
    await pg_store.set_policy_value("min_security_level", "TrustedEnvironment")
    policy = await pg_store.get_policy()
    assert policy == {"max_patch_age_days": 90, "min_security_level": "TrustedEnvironment"}

    await pg_store.set_policy_value("max_patch_age_days", "60")
    policy = await pg_store.get_policy()
    assert policy["max_patch_age_days"] == 60
