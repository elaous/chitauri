"""Verifies slowapi rejects requests over the configured limit."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.settings import settings


def test_nonce_rate_limit_enforced():
    limit_count = int(settings.rate_limit_nonce.split("/", 1)[0])
    client = TestClient(app)

    for _ in range(limit_count):
        resp = client.post("/nonce")
        assert resp.status_code == 200

    resp = client.post("/nonce")
    assert resp.status_code == 429


def test_admin_rate_limit_enforced(monkeypatch):
    monkeypatch.setattr("app.settings.settings.admin_api_key", "test-admin-key")
    limit_count = int(settings.rate_limit_admin.split("/", 1)[0])
    client = TestClient(app)
    headers = {"X-Admin-Api-Key": "wrong"}

    for _ in range(limit_count):
        resp = client.post(
            "/admin/verified-boot-keys",
            headers=headers,
            json={"os_id": "x", "verified_boot_key_sha256": "0" * 64},
        )
        assert resp.status_code == 401

    resp = client.post(
        "/admin/verified-boot-keys",
        headers=headers,
        json={"os_id": "x", "verified_boot_key_sha256": "0" * 64},
    )
    assert resp.status_code == 429
