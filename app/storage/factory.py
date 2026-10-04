from __future__ import annotations

from collections.abc import AsyncIterator

from app.db import SessionLocal
from app.settings import settings
from app.storage.base import ConfigStore


async def get_store() -> AsyncIterator[ConfigStore]:
    """FastAPI dependency yielding a ConfigStore for the configured backend."""
    if settings.storage_backend == "dynamodb":
        from app.storage.dynamodb_store import DynamoDBConfigStore

        store = DynamoDBConfigStore(
            table_prefix=settings.dynamodb_table_prefix,
            region_name=settings.dynamodb_region,
            endpoint_url=settings.dynamodb_endpoint_url,
        )
        try:
            yield store
        finally:
            await store.close()
    else:
        from app.storage.postgres_store import PostgresConfigStore

        async with SessionLocal() as session:
            store = PostgresConfigStore(session)
            try:
                yield store
            finally:
                await store.close()
