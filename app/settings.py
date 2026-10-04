"""Runtime settings, loaded from environment variables (or a .env file)."""
from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Which ConfigStore adapter to use for the allowlist/policy config.
    storage_backend: Literal["postgres", "dynamodb"] = "postgres"

    # --- Postgres backend ---
    database_url: str = "postgresql+asyncpg://graphene_attest:graphene_attest@localhost:5432/graphene_attest"

    # --- DynamoDB backend ---
    dynamodb_table_prefix: str = "graphene_attest_"
    dynamodb_region: str | None = None
    # Only set for local dev against DynamoDB Local / moto; leave unset in AWS.
    dynamodb_endpoint_url: str | None = None

    # --- Admin import API (app/admin.py) ---
    # Required (non-empty) to enable the /admin/* endpoints at all.
    admin_api_key: str | None = None
    admin_import_max_rows: int = 10_000
    admin_import_max_file_bytes: int = 10_000_000

    # --- Rate limiting (app/rate_limit.py) ---
    # Per-client-IP, "<count>/<period>" as accepted by the `limits` library
    # (e.g. "20/minute", "5/second"). /nonce and /verify are public and
    # unauthenticated, so rate limiting them is the main abuse control.
    # /admin/* is also limited despite requiring an API key, as defense in
    # depth against a leaked/guessed key.
    rate_limit_nonce: str = "20/minute"
    rate_limit_verify: str = "20/minute"
    rate_limit_admin: str = "30/minute"


settings = Settings()
