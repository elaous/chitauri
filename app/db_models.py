"""ORM models for the allowlist and policy config tables."""
from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class OSProfile(Base):
    __tablename__ = "os_profiles"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    expected_verified_boot_state: Mapped[str] = mapped_column(String, nullable=False)
    require_device_locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    verified_boot_keys: Mapped[list[VerifiedBootKey]] = relationship(
        back_populates="os_profile", cascade="all, delete-orphan"
    )


class VerifiedBootKey(Base):
    __tablename__ = "verified_boot_keys"
    __table_args__ = (
        UniqueConstraint("os_profile_id", "verified_boot_key_sha256", name="uq_os_profile_key"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    os_profile_id: Mapped[str] = mapped_column(ForeignKey("os_profiles.id"), nullable=False)
    device: Mapped[str | None] = mapped_column(String, nullable=True)
    release: Mapped[str | None] = mapped_column(String, nullable=True)
    verified_boot_key_sha256: Mapped[str] = mapped_column(String, nullable=False)

    os_profile: Mapped[OSProfile] = relationship(back_populates="verified_boot_keys")


class PolicySetting(Base):
    __tablename__ = "policy_settings"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(String, nullable=False)
