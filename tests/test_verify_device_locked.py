"""Regression: /verify must honor require_device_locked=False."""
from __future__ import annotations

import base64
import hashlib

from fastapi.testclient import TestClient

import app.main as main
from app.attestation import ParsedAttestation
from app.chain import ChainValidationResult
from app.main import app
from app.storage import OSProfileData, VerifiedBootKeyData, get_store
from tests.fakes import InMemoryConfigStore

VERIFIED_BOOT_KEY = b"\x01" * 32
VERIFIED_BOOT_KEY_SHA256 = hashlib.sha256(VERIFIED_BOOT_KEY).hexdigest()


def _fake_parsed(*, challenge: str, device_locked: bool | None) -> ParsedAttestation:
    return ParsedAttestation(
        attestation_security_level=1,  # TrustedEnvironment
        challenge=challenge.encode(),
        device_locked=device_locked,
        verified_boot_state=1,  # SelfSigned
        verified_boot_key=VERIFIED_BOOT_KEY,
        verified_boot_hash=b"\x00" * 32,
        os_patch_level=20260901,
        os_version=140000,
    )


def _client_with(monkeypatch, *, require_device_locked: bool) -> TestClient:
    store = InMemoryConfigStore()
    store.profiles["grapheneos"] = OSProfileData(
        id="grapheneos",
        display_name="GrapheneOS",
        expected_verified_boot_state="SelfSigned",
        require_device_locked=require_device_locked,
        verified_boot_keys=[VerifiedBootKeyData(verified_boot_key_sha256=VERIFIED_BOOT_KEY_SHA256)],
    )

    async def _override():
        yield store

    app.dependency_overrides[get_store] = _override

    monkeypatch.setattr(
        main, "validate_chain", lambda certs, roots: ChainValidationResult(valid=True, reasons=[])
    )
    monkeypatch.setattr(main.x509, "load_der_x509_certificate", lambda data: object())

    return TestClient(app)


def _teardown():
    app.dependency_overrides.pop(get_store, None)


def _verify_with_fake_cert(
    client: TestClient, monkeypatch, *, device_locked: bool | None
) -> dict:
    nonce = client.post("/nonce").json()["nonce"]
    monkeypatch.setattr(
        main,
        "parse_leaf_certificate",
        lambda der: _fake_parsed(challenge=nonce, device_locked=device_locked),
    )
    resp = client.post(
        "/verify",
        json={
            "nonce": nonce,
            "claimed_os": "grapheneos",
            "cert_chain_b64": [base64.b64encode(b"irrelevant").decode()],
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_unlocked_device_fails_when_profile_requires_locked(monkeypatch):
    client = _client_with(monkeypatch, require_device_locked=True)
    try:
        body = _verify_with_fake_cert(client, monkeypatch, device_locked=False)
        assert "Bootloader is not locked" in body["deviceAttestation"]["reasons"]
        assert body["deviceAttestation"]["verdict"] == "fail"
    finally:
        _teardown()


def test_unlocked_device_passes_when_profile_does_not_require_locked(monkeypatch):
    client = _client_with(monkeypatch, require_device_locked=False)
    try:
        body = _verify_with_fake_cert(client, monkeypatch, device_locked=False)
        assert body["deviceAttestation"]["verdict"] == "pass"
        assert body["deviceAttestation"]["reasons"] == []
        assert "MEETS_DEVICE_INTEGRITY" in body["deviceIntegrity"]["deviceRecognitionVerdict"]
    finally:
        _teardown()


def test_locked_device_passes_when_profile_requires_locked(monkeypatch):
    client = _client_with(monkeypatch, require_device_locked=True)
    try:
        body = _verify_with_fake_cert(client, monkeypatch, device_locked=True)
        assert body["deviceAttestation"]["verdict"] == "pass"
        assert body["deviceAttestation"]["reasons"] == []
    finally:
        _teardown()
