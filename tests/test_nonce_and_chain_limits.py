from __future__ import annotations

import base64
import time

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.main import app
from app.storage import OSProfileData, get_store
from tests.fakes import InMemoryConfigStore


@pytest.fixture(autouse=True)
def _clean_nonces():
    main._issued_nonces.clear()
    yield
    main._issued_nonces.clear()


@pytest.fixture
def client():
    store = InMemoryConfigStore()
    store.profiles["grapheneos"] = OSProfileData(
        id="grapheneos", display_name="GrapheneOS", expected_verified_boot_state="SelfSigned"
    )

    async def _override():
        yield store

    app.dependency_overrides[get_store] = _override
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_store, None)


def test_issue_purges_expired_nonces(client):
    main._issued_nonces["old"] = time.time() - main._NONCE_TTL_SECONDS - 1
    main._issued_nonces["fresh"] = time.time()
    client.post("/nonce")
    assert "old" not in main._issued_nonces
    assert "fresh" in main._issued_nonces


def test_nonce_store_is_capped_and_drops_oldest(client, monkeypatch):
    monkeypatch.setattr(main, "_MAX_OUTSTANDING_NONCES", 3)
    nonces = [client.post("/nonce").json()["nonce"] for _ in range(5)]
    assert len(main._issued_nonces) == 3
    assert set(main._issued_nonces) == set(nonces[-3:])


def _verify(client, certs):
    nonce = client.post("/nonce").json()["nonce"]
    return client.post(
        "/verify",
        json={"nonce": nonce, "claimed_os": "grapheneos", "cert_chain_b64": certs},
    )


def test_chain_too_long_rejected(client):
    cert = base64.b64encode(b"x").decode()
    resp = _verify(client, [cert] * (main.MAX_CERT_CHAIN_LENGTH + 1))
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Certificate chain too long"


def test_oversized_cert_rejected(client):
    resp = _verify(client, ["A" * (main.MAX_CERT_B64_LENGTH + 1)])
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Certificate too large"


@pytest.mark.parametrize("bad", ["!!!not base64!!!", base64.b64encode(b"not a cert").decode()])
def test_malformed_cert_returns_generic_error(client, bad):
    resp = _verify(client, [bad])
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid certificate chain"
