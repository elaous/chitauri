"""DynamoDBConfigStore tests against moto-mocked DynamoDB."""
from __future__ import annotations

import pytest

from app.storage.base import ConfigValidationError, VerifiedBootKeyData

moto = pytest.importorskip("moto")

SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA2 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
PREFIX = "test_"


@pytest.fixture
def dynamodb_store():
    with moto.mock_aws():
        import boto3

        from app.storage.dynamodb_store import DynamoDBConfigStore

        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(
            TableName=f"{PREFIX}os_profiles",
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        client.create_table(
            TableName=f"{PREFIX}policy_settings",
            KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield DynamoDBConfigStore(table_prefix=PREFIX, region_name="us-east-1")


async def test_upsert_and_get_os_profile(dynamodb_store):
    await dynamodb_store.upsert_os_profile(
        os_id="grapheneos",
        display_name="GrapheneOS",
        expected_verified_boot_state="SelfSigned",
    )
    profile = await dynamodb_store.get_os_profile("grapheneos")
    assert profile is not None
    assert profile.display_name == "GrapheneOS"
    assert profile.verified_boot_keys == []
    assert await dynamodb_store.get_os_profile("nonexistent") is None


async def test_add_verified_boot_keys_dedupes(dynamodb_store):
    await dynamodb_store.upsert_os_profile(
        os_id="grapheneos",
        display_name="GrapheneOS",
        expected_verified_boot_state="SelfSigned",
    )
    keys = [
        VerifiedBootKeyData(verified_boot_key_sha256=SHA),
        VerifiedBootKeyData(verified_boot_key_sha256=SHA),
        VerifiedBootKeyData(verified_boot_key_sha256=SHA2),
    ]
    added = await dynamodb_store.add_verified_boot_keys("grapheneos", keys)
    assert added == 2

    added_again = await dynamodb_store.add_verified_boot_keys("grapheneos", keys)
    assert added_again == 0

    profile = await dynamodb_store.get_os_profile("grapheneos")
    assert len(profile.verified_boot_keys) == 2


async def test_add_verified_boot_keys_unknown_os_id_raises(dynamodb_store):
    with pytest.raises(ConfigValidationError):
        await dynamodb_store.add_verified_boot_keys(
            "nonexistent", [VerifiedBootKeyData(verified_boot_key_sha256=SHA)]
        )


async def test_policy_roundtrip(dynamodb_store):
    await dynamodb_store.set_policy_value("max_patch_age_days", "90")
    await dynamodb_store.set_policy_value("min_security_level", "TrustedEnvironment")
    policy = await dynamodb_store.get_policy()
    assert policy == {"max_patch_age_days": 90, "min_security_level": "TrustedEnvironment"}


async def test_list_os_profiles(dynamodb_store):
    await dynamodb_store.upsert_os_profile(
        os_id="grapheneos",
        display_name="GrapheneOS",
        expected_verified_boot_state="SelfSigned",
    )
    await dynamodb_store.upsert_os_profile(
        os_id="stock_android",
        display_name="Stock Android",
        expected_verified_boot_state="Verified",
    )
    profiles = await dynamodb_store.list_os_profiles()
    assert {p.id for p in profiles} == {"grapheneos", "stock_android"}
