"""Creates the DynamoDB tables used by DynamoDBConfigStore (app/storage/dynamodb_store.py).

Safe to re-run: skips tables that already exist. Useful both against real
AWS and against DynamoDB Local / moto for development.

    uv run python scripts/create_dynamodb_tables.py
"""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from app.settings import settings


def _create_table_if_missing(client, *, name: str, key_name: str) -> None:
    try:
        client.describe_table(TableName=name)
        print(f"{name}: already exists")
        return
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

    client.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": key_name, "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": key_name, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    client.get_waiter("table_exists").wait(TableName=name)
    print(f"{name}: created")


def main() -> None:
    client = boto3.client(
        "dynamodb",
        region_name=settings.dynamodb_region,
        endpoint_url=settings.dynamodb_endpoint_url,
    )
    prefix = settings.dynamodb_table_prefix
    _create_table_if_missing(client, name=f"{prefix}os_profiles", key_name="id")
    _create_table_if_missing(client, name=f"{prefix}policy_settings", key_name="key")


if __name__ == "__main__":
    main()
