"""ConfigStore backed by DynamoDB.

Schema (two tables, created by `scripts/create_dynamodb_tables.py`):

  {prefix}os_profiles
    id (PK, S)             e.g. "grapheneos"
    display_name (S)
    expected_verified_boot_state (S)
    require_device_locked (BOOL)
    verified_boot_keys (L[M{device, release, verified_boot_key_sha256}])

  {prefix}policy_settings
    key (PK, S)
    value (S)

boto3 is synchronous; each call is offloaded to a worker thread via
`asyncio.to_thread` so the rest of the app can stay async without pulling in
aiobotocore. For this service's call volume (admin-side config reads/writes,
not the hot `/verify` path data itself) that's a fine trade-off.
"""
from __future__ import annotations

import asyncio
from functools import partial
from typing import Any

import boto3

from app.storage.base import ConfigValidationError, OSProfileData, VerifiedBootKeyData

_POLICY_TYPES: dict[str, type] = {
    "max_patch_age_days": int,
    "min_security_level": str,
}


def _item_to_profile_data(item: dict[str, Any]) -> OSProfileData:
    return OSProfileData(
        id=item["id"],
        display_name=item["display_name"],
        expected_verified_boot_state=item["expected_verified_boot_state"],
        require_device_locked=bool(item.get("require_device_locked", True)),
        verified_boot_keys=[
            VerifiedBootKeyData(
                device=key.get("device"),
                release=key.get("release"),
                verified_boot_key_sha256=key["verified_boot_key_sha256"],
            )
            for key in item.get("verified_boot_keys", [])
        ],
    )


class DynamoDBConfigStore:
    """ConfigStore backed by DynamoDB (via boto3, run off the event loop)."""

    def __init__(
        self,
        *,
        table_prefix: str,
        region_name: str | None = None,
        endpoint_url: str | None = None,
    ) -> None:
        resource = boto3.resource(
            "dynamodb", region_name=region_name, endpoint_url=endpoint_url
        )
        self._os_profiles = resource.Table(f"{table_prefix}os_profiles")
        self._policy_settings = resource.Table(f"{table_prefix}policy_settings")

    async def _run(self, func, *args, **kwargs):
        return await asyncio.to_thread(partial(func, *args, **kwargs))

    async def get_os_profile(self, os_id: str) -> OSProfileData | None:
        resp = await self._run(self._os_profiles.get_item, Key={"id": os_id})
        item = resp.get("Item")
        return _item_to_profile_data(item) if item else None

    async def list_os_profiles(self) -> list[OSProfileData]:
        resp = await self._run(self._os_profiles.scan)
        return [_item_to_profile_data(item) for item in resp.get("Items", [])]

    async def upsert_os_profile(
        self,
        *,
        os_id: str,
        display_name: str,
        expected_verified_boot_state: str,
        require_device_locked: bool = True,
    ) -> None:
        existing = await self._run(self._os_profiles.get_item, Key={"id": os_id})
        verified_boot_keys = existing.get("Item", {}).get("verified_boot_keys", [])
        await self._run(
            self._os_profiles.put_item,
            Item={
                "id": os_id,
                "display_name": display_name,
                "expected_verified_boot_state": expected_verified_boot_state,
                "require_device_locked": require_device_locked,
                "verified_boot_keys": verified_boot_keys,
            },
        )

    async def add_verified_boot_keys(
        self, os_id: str, keys: list[VerifiedBootKeyData]
    ) -> int:
        resp = await self._run(self._os_profiles.get_item, Key={"id": os_id})
        item = resp.get("Item")
        if item is None:
            raise ConfigValidationError(f"Unknown os_id {os_id!r}")

        current = item.get("verified_boot_keys", [])
        existing_hashes = {k["verified_boot_key_sha256"] for k in current}

        added = 0
        for key in keys:
            if key.verified_boot_key_sha256 in existing_hashes:
                continue
            current.append(
                {
                    "device": key.device,
                    "release": key.release,
                    "verified_boot_key_sha256": key.verified_boot_key_sha256,
                }
            )
            existing_hashes.add(key.verified_boot_key_sha256)
            added += 1

        if added:
            await self._run(
                self._os_profiles.update_item,
                Key={"id": os_id},
                UpdateExpression="SET verified_boot_keys = :keys",
                ExpressionAttributeValues={":keys": current},
            )
        return added

    async def get_policy(self) -> dict[str, str]:
        resp = await self._run(self._policy_settings.scan)
        policy: dict[str, str] = {}
        for item in resp.get("Items", []):
            cast = _POLICY_TYPES.get(item["key"], str)
            policy[item["key"]] = cast(item["value"])
        return policy

    async def set_policy_value(self, key: str, value: str) -> None:
        await self._run(
            self._policy_settings.put_item, Item={"key": key, "value": value}
        )

    async def close(self) -> None:
        pass
