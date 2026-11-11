# Contributing to graphene-attest

Thanks for considering a contribution. This project is early-stage and the
most valuable contributions right now are:

- **Real attestation test vectors** from actual GrapheneOS (or other
  AOSP-based OS) devices — see `tests/test_attestation.py` for how to add a
  fixture.
- **Allowlist entries**: verified `verifiedBootKey` SHA-256 hashes for
  specific OS + device + release combinations, with a citation to where you
  independently verified the hash (see `config/allowlist.yaml` and
  `docs/API.md#importing-allowlist-data`).
- Chain validation hardening (`app/chain.py` is an intentionally minimal
  stub — see the TODOs at the top of that file).
- Bug reports and fixes against real device output.

## Development setup

```bash
uv sync --group dev
docker compose up -d postgres
uv run alembic upgrade head
uv run python scripts/seed_config.py
uv run pytest -q
```

See `README.md` for the full setup and `docs/API.md` for the API reference.

## Before opening a PR

- Run `uv run ruff check .` and make sure it is clean; CI runs it on every
  pull request and on `main`.
- Run `uv run pytest -q` and make sure it passes. Postgres-backed tests are
  skipped unless a database is reachable (`docker compose up -d postgres`).
- CI runs only the tests related to your changed files on pull requests, via
  `scripts/run_targeted_tests.py`; the full suite runs on `main` and nightly.
  Run `python3 scripts/run_targeted_tests.py --dry-run <files>` to preview.
- If you changed `app/db_models.py`, generate a migration:
  `uv run alembic revision --autogenerate -m "..."` and commit it.
- If you changed the API surface, regenerate the schema:
  `uv run python scripts/export_openapi.py`.
- Keep allowlist changes (`config/allowlist.yaml`) separate from code
  changes where possible, and cite your source for any new
  `verified_boot_key_sha256` entry.

## Security-sensitive changes

This project verifies device integrity for things like banking and
government apps — mistakes here have real consequences. If you're changing
`app/attestation.py`, `app/chain.py`, `app/revocation.py`, or anything under
`app/storage/` or `app/admin.py`, please call that out explicitly in your
PR description, and see `SECURITY.md` if you believe you've found a
vulnerability rather than a bug.

## Code style

- Python 3.11+, type hints throughout.
- No new dependencies without a good reason — this is meant to be a small,
  auditable service.
- Prefer small, reviewable PRs over large ones.

## License

By contributing, you agree that your contributions will be licensed under
the project's Apache License, Version 2.0 (see `LICENSE`).
