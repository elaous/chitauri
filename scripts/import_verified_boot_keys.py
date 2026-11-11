"""CLI for inserting verified-boot keys directly into the ConfigStore."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from app.import_utils import group_by_os_id, parse_csv_rows, parse_json_rows
from app.storage import ConfigValidationError, VerifiedBootKeyData, get_store


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--json-file", help="Path to a JSON file (array of records)")
    p.add_argument("--csv-file", help="Path to a CSV file")
    p.add_argument("--os-id", help="os_id — required for a single record, or as a CSV default")
    p.add_argument("--sha256", help="verified_boot_key_sha256 for a single record")
    p.add_argument("--device", help="device, for a single record")
    p.add_argument("--release", help="release, for a single record")
    return p.parse_args()


async def _run(args: argparse.Namespace) -> int:
    if sum(bool(x) for x in (args.json_file, args.csv_file, args.sha256)) != 1:
        print(
            "Pass exactly one of: --json-file, --csv-file, or --sha256 (single record)",
            file=sys.stderr,
        )
        return 2

    if args.json_file:
        with open(args.json_file) as f:
            records = json.load(f)
        rows = parse_json_rows(records, default_os_id=args.os_id)
    elif args.csv_file:
        with open(args.csv_file) as f:
            rows = parse_csv_rows(f.read(), default_os_id=args.os_id)
    else:
        if not args.os_id:
            print("--os-id is required with --sha256", file=sys.stderr)
            return 2
        rows = [
            (
                args.os_id,
                VerifiedBootKeyData(
                    verified_boot_key_sha256=args.sha256,
                    device=args.device,
                    release=args.release,
                ),
            )
        ]

    grouped = group_by_os_id(rows)
    async for store in get_store():
        for os_id, keys in grouped.items():
            added = await store.add_verified_boot_keys(os_id, keys)
            print(f"{os_id}: added {added}/{len(keys)}")
    return 0


def main() -> None:
    args = _parse_args()
    try:
        sys.exit(asyncio.run(_run(args)))
    except ConfigValidationError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
