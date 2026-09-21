"""Runtime settings, loaded from environment variables (or a .env file)."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://graphene_attest:graphene_attest@localhost:5432/graphene_attest"


settings = Settings()
