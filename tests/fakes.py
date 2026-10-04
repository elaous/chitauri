"""In-memory ConfigStore for exercising app.main/app.admin without a real
Postgres/DynamoDB backend."""
from __future__ import annotations

from app.storage.base import ConfigValidationError, OSProfileData, VerifiedBootKeyData


class InMemoryConfigStore:
    def __init__(self) -> None:
        self.profiles: dict[str, OSProfileData] = {}
        self.policy: dict[str, str] = {}

    async def get_os_profile(self, os_id: str) -> OSProfileData | None:
        return self.profiles.get(os_id)

    async def list_os_profiles(self) -> list[OSProfileData]:
        return list(self.profiles.values())

    async def upsert_os_profile(
        self,
        *,
        os_id: str,
        display_name: str,
        expected_verified_boot_state: str,
        require_device_locked: bool = True,
    ) -> None:
        existing = self.profiles.get(os_id)
        self.profiles[os_id] = OSProfileData(
            id=os_id,
            display_name=display_name,
            expected_verified_boot_state=expected_verified_boot_state,
            require_device_locked=require_device_locked,
            verified_boot_keys=existing.verified_boot_keys if existing else [],
        )

    async def add_verified_boot_keys(
        self, os_id: str, keys: list[VerifiedBootKeyData]
    ) -> int:
        profile = self.profiles.get(os_id)
        if profile is None:
            raise ConfigValidationError(f"Unknown os_id {os_id!r}")
        existing_hashes = {k.verified_boot_key_sha256 for k in profile.verified_boot_keys}
        added = 0
        for key in keys:
            if key.verified_boot_key_sha256 in existing_hashes:
                continue
            profile.verified_boot_keys.append(key)
            existing_hashes.add(key.verified_boot_key_sha256)
            added += 1
        return added

    async def get_policy(self) -> dict[str, str]:
        return dict(self.policy)

    async def set_policy_value(self, key: str, value: str) -> None:
        self.policy[key] = value

    async def close(self) -> None:
        pass
