"""Storage-backend-agnostic shapes and interface for the config store.

The allowlist/policy config can be persisted in different backends (see
`postgres_store.py`, `dynamodb_store.py`). Everything above this module
(app/main.py, app/admin.py) talks only to the `ConfigStore` interface, so
swapping backends doesn't touch request handling.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

# Known policy keys and how to coerce their stored (string) value. Shared by
# every ConfigStore backend so they stay in sync.
POLICY_TYPES: dict[str, type] = {
    "max_patch_age_days": int,
    "min_security_level": str,
}


class ConfigValidationError(ValueError):
    """Raised when data handed to a ConfigStore fails basic shape/format checks."""


@dataclass
class VerifiedBootKeyData:
    verified_boot_key_sha256: str
    device: str | None = None
    release: str | None = None

    def __post_init__(self) -> None:
        normalized = self.verified_boot_key_sha256.strip().lower()
        if not SHA256_HEX_RE.match(normalized):
            raise ConfigValidationError(
                f"verified_boot_key_sha256 must be 64 lowercase hex chars, "
                f"got {self.verified_boot_key_sha256!r}"
            )
        self.verified_boot_key_sha256 = normalized


@dataclass
class OSProfileData:
    id: str
    display_name: str
    expected_verified_boot_state: str
    require_device_locked: bool = True
    verified_boot_keys: list[VerifiedBootKeyData] = field(default_factory=list)


@runtime_checkable
class ConfigStore(Protocol):
    """Backend-agnostic interface for reading/writing the allowlist + policy config."""

    async def get_os_profile(self, os_id: str) -> OSProfileData | None:
        ...

    async def list_os_profiles(self) -> list[OSProfileData]:
        ...

    async def upsert_os_profile(
        self,
        *,
        os_id: str,
        display_name: str,
        expected_verified_boot_state: str,
        require_device_locked: bool = True,
    ) -> None:
        ...

    async def add_verified_boot_keys(
        self, os_id: str, keys: list[VerifiedBootKeyData]
    ) -> int:
        """Insert `keys` for `os_id`, de-duplicating by hash. Returns the
        number of keys actually added (an unknown os_id is an error)."""
        ...

    async def get_policy(self) -> dict[str, str]:
        ...

    async def set_policy_value(self, key: str, value: str) -> None:
        ...

    async def close(self) -> None:
        ...
