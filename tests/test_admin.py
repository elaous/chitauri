import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.storage import OSProfileData, get_store
from tests.fakes import InMemoryConfigStore

SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA2 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


@pytest.fixture
def store() -> InMemoryConfigStore:
    s = InMemoryConfigStore()
    s.profiles["grapheneos"] = OSProfileData(
        id="grapheneos",
        display_name="GrapheneOS",
        expected_verified_boot_state="SelfSigned",
    )
    return s


@pytest.fixture
def client(store, monkeypatch):
    monkeypatch.setattr("app.settings.settings.admin_api_key", "test-admin-key")

    async def _override():
        yield store

    app.dependency_overrides[get_store] = _override
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_store, None)


AUTH = {"X-Admin-Api-Key": "test-admin-key"}


def test_admin_disabled_without_api_key(store, monkeypatch):
    monkeypatch.setattr("app.settings.settings.admin_api_key", None)

    async def _override():
        yield store

    app.dependency_overrides[get_store] = _override
    try:
        client = TestClient(app)
        resp = client.post(
            "/admin/verified-boot-keys",
            headers={"X-Admin-Api-Key": "anything"},
            json={"os_id": "grapheneos", "verified_boot_key_sha256": SHA},
        )
        assert resp.status_code == 503
    finally:
        app.dependency_overrides.pop(get_store, None)


def test_admin_rejects_wrong_key(client):
    resp = client.post(
        "/admin/verified-boot-keys",
        headers={"X-Admin-Api-Key": "wrong"},
        json={"os_id": "grapheneos", "verified_boot_key_sha256": SHA},
    )
    assert resp.status_code == 401


def test_admin_rejects_missing_key(client):
    resp = client.post(
        "/admin/verified-boot-keys",
        json={"os_id": "grapheneos", "verified_boot_key_sha256": SHA},
    )
    assert resp.status_code == 422


def test_single_json_insert(client, store):
    resp = client.post(
        "/admin/verified-boot-keys",
        headers=AUTH,
        json={"os_id": "grapheneos", "device": "Pixel 8", "verified_boot_key_sha256": SHA},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"received": 1, "added": 1, "by_os_id": {"grapheneos": 1}}
    assert len(store.profiles["grapheneos"].verified_boot_keys) == 1


def test_single_json_insert_unknown_os_id(client):
    resp = client.post(
        "/admin/verified-boot-keys",
        headers=AUTH,
        json={"os_id": "nonexistent", "verified_boot_key_sha256": SHA},
    )
    assert resp.status_code == 400


def test_bulk_json_insert_dedupes(client, store):
    resp = client.post(
        "/admin/verified-boot-keys/bulk",
        headers=AUTH,
        json=[
            {"os_id": "grapheneos", "verified_boot_key_sha256": SHA},
            {"os_id": "grapheneos", "verified_boot_key_sha256": SHA},
            {"os_id": "grapheneos", "verified_boot_key_sha256": SHA2},
        ],
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["received"] == 3
    assert body["added"] == 2
    assert len(store.profiles["grapheneos"].verified_boot_keys) == 2


def test_bulk_json_insert_enforces_row_limit(client, monkeypatch):
    monkeypatch.setattr("app.settings.settings.admin_import_max_rows", 1)
    resp = client.post(
        "/admin/verified-boot-keys/bulk",
        headers=AUTH,
        json=[
            {"os_id": "grapheneos", "verified_boot_key_sha256": SHA},
            {"os_id": "grapheneos", "verified_boot_key_sha256": SHA2},
        ],
    )
    assert resp.status_code == 413


def test_csv_bulk_import(client, store):
    csv_text = f"os_id,device,release,verified_boot_key_sha256\ngrapheneos,Pixel 8,2026.09.01,{SHA}\n"
    resp = client.post(
        "/admin/verified-boot-keys/import",
        headers=AUTH,
        files={"file": ("keys.csv", csv_text, "text/csv")},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["added"] == 1
    key = store.profiles["grapheneos"].verified_boot_keys[0]
    assert key.device == "Pixel 8"


def test_csv_bulk_import_default_os_id(client, store):
    csv_text = f"device,release,verified_boot_key_sha256\nPixel 8,2026.09.01,{SHA}\n"
    resp = client.post(
        "/admin/verified-boot-keys/import?default_os_id=grapheneos",
        headers=AUTH,
        files={"file": ("keys.csv", csv_text, "text/csv")},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["by_os_id"] == {"grapheneos": 1}


def test_csv_single_row_import(client, store):
    csv_text = f"os_id,device,release,verified_boot_key_sha256\ngrapheneos,Pixel 9,2026.09.01,{SHA}"
    resp = client.post(
        "/admin/verified-boot-keys/import/row",
        headers={**AUTH, "Content-Type": "text/csv"},
        content=csv_text,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"received": 1, "added": 1, "by_os_id": {"grapheneos": 1}}


def test_csv_single_row_import_rejects_multiple_rows(client):
    csv_text = (
        "os_id,device,release,verified_boot_key_sha256\n"
        f"grapheneos,Pixel 8,2026.09.01,{SHA}\n"
        f"grapheneos,Pixel 9,2026.09.01,{SHA2}\n"
    )
    resp = client.post(
        "/admin/verified-boot-keys/import/row",
        headers=AUTH,
        content=csv_text,
    )
    assert resp.status_code == 400


def test_upsert_os_profile(client, store):
    resp = client.post(
        "/admin/os-profiles",
        headers=AUTH,
        json={
            "id": "calyxos",
            "display_name": "CalyxOS",
            "expected_verified_boot_state": "SelfSigned",
        },
    )
    assert resp.status_code == 200, resp.text
    assert "calyxos" in store.profiles
