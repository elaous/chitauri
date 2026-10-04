"""Regenerates docs/openapi.json from the live FastAPI app.

    uv run python scripts/export_openapi.py
"""
from __future__ import annotations

import json
import pathlib

from app.main import app

OUT_PATH = pathlib.Path(__file__).resolve().parent.parent / "docs" / "openapi.json"


def main() -> None:
    schema = app.openapi()
    OUT_PATH.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
