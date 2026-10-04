from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db_models import OSProfile, PolicySetting, VerifiedBootKey
from app.storage.base import POLICY_TYPES, ConfigValidationError, OSProfileData, VerifiedBootKeyData


def _to_profile_data(profile: OSProfile) -> OSProfileData:
    return OSProfileData(
        id=profile.id,
        display_name=profile.display_name,
        expected_verified_boot_state=profile.expected_verified_boot_state,
        require_device_locked=profile.require_device_locked,
        verified_boot_keys=[
            VerifiedBootKeyData(
                device=key.device,
                release=key.release,
                verified_boot_key_sha256=key.verified_boot_key_sha256,
            )
            for key in profile.verified_boot_keys
        ],
    )


class PostgresConfigStore:
    """ConfigStore backed by Postgres via SQLAlchemy (asyncpg)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_os_profile(self, os_id: str) -> OSProfileData | None:
        stmt = (
            select(OSProfile)
            .options(selectinload(OSProfile.verified_boot_keys))
            .where(OSProfile.id == os_id)
        )
        profile = (await self._session.execute(stmt)).scalar_one_or_none()
        return _to_profile_data(profile) if profile is not None else None

    async def list_os_profiles(self) -> list[OSProfileData]:
        stmt = select(OSProfile).options(selectinload(OSProfile.verified_boot_keys))
        profiles = (await self._session.execute(stmt)).scalars().all()
        return [_to_profile_data(p) for p in profiles]

    async def upsert_os_profile(
        self,
        *,
        os_id: str,
        display_name: str,
        expected_verified_boot_state: str,
        require_device_locked: bool = True,
    ) -> None:
        profile = await self._session.get(OSProfile, os_id)
        if profile is None:
            profile = OSProfile(id=os_id)
            self._session.add(profile)
        profile.display_name = display_name
        profile.expected_verified_boot_state = expected_verified_boot_state
        profile.require_device_locked = require_device_locked
        await self._session.commit()

    async def add_verified_boot_keys(
        self, os_id: str, keys: list[VerifiedBootKeyData]
    ) -> int:
        profile = await self._session.get(OSProfile, os_id)
        if profile is None:
            raise ConfigValidationError(f"Unknown os_id {os_id!r}")

        existing = {
            row[0]
            for row in (
                await self._session.execute(
                    select(VerifiedBootKey.verified_boot_key_sha256).where(
                        VerifiedBootKey.os_profile_id == os_id
                    )
                )
            ).all()
        }

        added = 0
        for key in keys:
            if key.verified_boot_key_sha256 in existing:
                continue
            self._session.add(
                VerifiedBootKey(
                    os_profile_id=os_id,
                    device=key.device,
                    release=key.release,
                    verified_boot_key_sha256=key.verified_boot_key_sha256,
                )
            )
            existing.add(key.verified_boot_key_sha256)
            added += 1

        await self._session.commit()
        return added

    async def get_policy(self) -> dict[str, str]:
        rows = (await self._session.execute(select(PolicySetting))).scalars().all()
        policy: dict[str, str] = {}
        for row in rows:
            cast = POLICY_TYPES.get(row.key, str)
            policy[row.key] = cast(row.value)
        return policy

    async def set_policy_value(self, key: str, value: str) -> None:
        setting = await self._session.get(PolicySetting, key)
        if setting is None:
            setting = PolicySetting(key=key, value=value)
            self._session.add(setting)
        else:
            setting.value = value
        await self._session.commit()

    async def close(self) -> None:
        await self._session.close()
