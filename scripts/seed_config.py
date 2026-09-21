"""One-time / re-runnable import of config/allowlist.yaml into Postgres.

Config used to live only in that YAML file; it's now kept in the
os_profiles / verified_boot_keys / policy_settings tables (see
app/db_models.py) so it can be edited without a deploy. Run this after
`alembic upgrade head` to bootstrap a fresh database, or to re-sync the DB
from the YAML file after hand-editing it.

    uv run python scripts/seed_config.py
"""
from __future__ import annotations

import asyncio
import pathlib

import yaml

from app.db import SessionLocal
from app.db_models import OSProfile, PolicySetting, VerifiedBootKey

YAML_PATH = pathlib.Path(__file__).resolve().parent.parent / "config" / "allowlist.yaml"


async def seed() -> None:
    with open(YAML_PATH, "r") as f:
        cfg = yaml.safe_load(f)

    async with SessionLocal() as db:
        for entry in cfg.get("os_allowlist", []):
            profile = await db.get(OSProfile, entry["id"])
            if profile is None:
                profile = OSProfile(id=entry["id"])
                db.add(profile)
            profile.display_name = entry["display_name"]
            profile.expected_verified_boot_state = entry["expected_verified_boot_state"]
            profile.require_device_locked = entry.get("require_device_locked", True)

            await db.flush()

            for key in entry.get("verified_boot_keys") or []:
                existing = await db.execute(
                    VerifiedBootKey.__table__.select().where(
                        VerifiedBootKey.os_profile_id == profile.id,
                        VerifiedBootKey.verified_boot_key_sha256 == key["verified_boot_key_sha256"],
                    )
                )
                if existing.first() is not None:
                    continue
                db.add(
                    VerifiedBootKey(
                        os_profile_id=profile.id,
                        device=key.get("device"),
                        release=key.get("release"),
                        verified_boot_key_sha256=key["verified_boot_key_sha256"],
                    )
                )

        for key, value in (cfg.get("policy") or {}).items():
            setting = await db.get(PolicySetting, key)
            if setting is None:
                setting = PolicySetting(key=key, value=str(value))
                db.add(setting)
            else:
                setting.value = str(value)

        await db.commit()

    print(f"Seeded config from {YAML_PATH}")


if __name__ == "__main__":
    asyncio.run(seed())
