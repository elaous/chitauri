"""Loads the allowlist / policy config from Postgres (see app/db_models.py).

Previously this read config/allowlist.yaml directly; that file is now only
used as seed data for `scripts/seed_config.py`.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db_models import OSProfile, PolicySetting

# Google's published hardware attestation revocation status list.
# See https://security.googleblog.com/2019/09/trust-but-verify-attestation-with.html
GOOGLE_REVOCATION_LIST_URL = "https://android.googleapis.com/attestation/status"

# Known policy keys and how to coerce their stored (string) value.
_POLICY_TYPES: dict[str, type] = {
    "max_patch_age_days": int,
    "min_security_level": str,
}


async def get_os_profile(db: AsyncSession, os_id: str) -> dict | None:
    stmt = (
        select(OSProfile)
        .options(selectinload(OSProfile.verified_boot_keys))
        .where(OSProfile.id == os_id)
    )
    profile = (await db.execute(stmt)).scalar_one_or_none()
    if profile is None:
        return None
    return {
        "id": profile.id,
        "display_name": profile.display_name,
        "expected_verified_boot_state": profile.expected_verified_boot_state,
        "require_device_locked": profile.require_device_locked,
        "verified_boot_keys": [
            {
                "device": key.device,
                "release": key.release,
                "verified_boot_key_sha256": key.verified_boot_key_sha256,
            }
            for key in profile.verified_boot_keys
        ],
    }


async def get_policy(db: AsyncSession) -> dict:
    rows = (await db.execute(select(PolicySetting))).scalars().all()
    policy: dict = {}
    for row in rows:
        cast = _POLICY_TYPES.get(row.key, str)
        policy[row.key] = cast(row.value)
    return policy
