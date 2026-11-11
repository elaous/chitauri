"""Backend-agnostic shapes and interface for the config store."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

# Known policy keys and their value types.
POLICY_TYPES: dict[str, type] = {
    "max_patch_age_days": int,
    "min_security_level": str,
}


class ConfigValidationError(ValueError):
    """Raised on malformed ConfigStore input."""


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
    """Storage interface for allowlist and policy config."""

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
        """De-duplicates by hash. Returns count added; unknown os_id errors."""
        ...

    async def get_policy(self) -> dict[str, str]:
        ...

    async def set_policy_value(self, key: str, value: str) -> None:
        ...

    async def close(self) -> None:
        ...
