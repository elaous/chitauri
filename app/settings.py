"""Runtime settings, loaded from environment variables (or a .env file)."""
from __future__ import annotations

from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_ADMIN_API_KEY_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    storage_backend: Literal["postgres", "dynamodb"] = "postgres"

    database_url: str = "postgresql+asyncpg://graphene_attest:graphene_attest@localhost:5432/graphene_attest"

    dynamodb_table_prefix: str = "graphene_attest_"
    dynamodb_region: str | None = None
    # Local DynamoDB only; leave unset in AWS.
    dynamodb_endpoint_url: str | None = None

    # Empty disables the /admin/* endpoints.
    admin_api_key: str | None = None
    admin_import_max_rows: int = 10_000
    admin_import_max_file_bytes: int = 10_000_000

    # Per-client-IP limit, "<count>/<period>" (limits syntax).
    rate_limit_nonce: str = "20/minute"
    rate_limit_verify: str = "20/minute"
    rate_limit_admin: str = "30/minute"

    @field_validator("admin_api_key")
    @classmethod
    def _admin_api_key_long_enough(cls, value: str | None) -> str | None:
        if value and len(value) < MIN_ADMIN_API_KEY_LENGTH:
            raise ValueError(
                f"ADMIN_API_KEY must be at least {MIN_ADMIN_API_KEY_LENGTH} characters"
            )
        return value


settings = Settings()
