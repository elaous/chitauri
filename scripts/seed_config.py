"""One-time / re-runnable import of config/allowlist.yaml into the configured
ConfigStore (Postgres or DynamoDB, via app.settings.storage_backend).

Config used to live only in that YAML file; it's now kept in whichever
backend is configured (see app/storage/). Run this after provisioning the
backend's schema (`alembic upgrade head` for Postgres,
`scripts/create_dynamodb_tables.py` for DynamoDB) to bootstrap it, or to
re-sync it from the YAML file after hand-editing it.

    uv run python scripts/seed_config.py
"""
from __future__ import annotations

import asyncio
import pathlib

import yaml

from app.storage import VerifiedBootKeyData, get_store

YAML_PATH = pathlib.Path(__file__).resolve().parent.parent / "config" / "allowlist.yaml"


async def seed() -> None:
    with open(YAML_PATH, "r") as f:
        cfg = yaml.safe_load(f)

    async for store in get_store():
        for entry in cfg.get("os_allowlist", []):
            await store.upsert_os_profile(
                os_id=entry["id"],
                display_name=entry["display_name"],
                expected_verified_boot_state=entry["expected_verified_boot_state"],
                require_device_locked=entry.get("require_device_locked", True),
            )

            keys = [
                VerifiedBootKeyData(
                    device=key.get("device"),
                    release=key.get("release"),
                    verified_boot_key_sha256=key["verified_boot_key_sha256"],
                )
                for key in (entry.get("verified_boot_keys") or [])
            ]
            if keys:
                await store.add_verified_boot_keys(entry["id"], keys)

        for key, value in (cfg.get("policy") or {}).items():
            await store.set_policy_value(key, str(value))

    print(f"Seeded config from {YAML_PATH}")


if __name__ == "__main__":
    asyncio.run(seed())
