"""Run only the tests related to a list of changed files.

Usage: run_targeted_tests.py [--base REF] [--dry-run] [FILE ...]
Without FILE arguments, changed files come from `git diff --name-only REF...HEAD`.
"""

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

FULL_SUITE_EXACT = {
    "pyproject.toml",
    "uv.lock",
    "alembic.ini",
    "app/__init__.py",
    "app/main.py",
    "app/settings.py",
    "app/constants.py",
    "app/models.py",
    "app/db.py",
    "app/db_models.py",
    "app/rate_limit.py",
    "app/chain.py",
    "app/revocation.py",
    "app/admin.py",
    "app/import_utils.py",
    "app/storage/__init__.py",
    "app/storage/base.py",
    "app/storage/factory.py",
    "tests/conftest.py",
    "tests/fakes.py",
}
FULL_SUITE_PREFIXES = ("config/", "migrations/", ".github/")
FULL_SUITE_EXACT.add("scripts/run_targeted_tests.py")
IGNORED_PREFIXES = ("docs/",)
IGNORED_SUFFIXES = (".md",)

EXPLICIT_MAP = {
    "app/attestation.py": ["tests/test_attestation.py", "tests/test_verify_device_locked.py"],
    "app/storage/dynamodb_store.py": ["tests/test_storage_dynamodb.py"],
    "app/storage/postgres_store.py": ["tests/test_storage_postgres.py"],
    "scripts/import_verified_boot_keys.py": ["tests/test_import_utils.py"],
}


def changed_files(base):
    out = subprocess.run(
        ["git", "diff", "--name-only", "-z", f"{base}...HEAD"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [name for name in out.split("\0") if name]


def is_test_module(path):
    name = Path(path).name
    return path.startswith("tests/") and name.startswith("test_") and name.endswith(".py")


def select_tests(files):
    """Return None for the full suite, else a sorted list of test files."""
    selected = set()
    for path in files:
        if path in FULL_SUITE_EXACT or path.startswith(FULL_SUITE_PREFIXES):
            return None
        if path.startswith(IGNORED_PREFIXES) or path.endswith(IGNORED_SUFFIXES):
            continue
        if is_test_module(path) and path.count("/") == 1:
            if (REPO_ROOT / path).exists():
                selected.add(path)
        elif path in EXPLICIT_MAP:
            selected.update(EXPLICIT_MAP[path])
        elif path.startswith("app/") and path.endswith(".py") and path.count("/") == 1:
            candidate = f"tests/test_{Path(path).stem}.py"
            if not (REPO_ROOT / candidate).exists():
                return None
            selected.add(candidate)
        else:
            return None
    return sorted(t for t in selected if (REPO_ROOT / t).exists())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="origin/main")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args()

    files = args.files or changed_files(args.base)
    tests = select_tests(files)

    if tests is None:
        print("Shared or config files changed: running full suite")
        command = ["uv", "run", "pytest", "-q"]
    elif not tests:
        print("No related tests for changed files: nothing to run")
        return 0
    else:
        print("Running targeted tests: " + " ".join(tests))
        command = ["uv", "run", "pytest", "-q", *tests]

    if args.dry_run:
        print("Command: " + " ".join(command))
        return 0
    return subprocess.run(command, cwd=REPO_ROOT).returncode


if __name__ == "__main__":
    sys.exit(main())
