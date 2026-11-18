from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.attestation import ParsedAttestation
from app.chain import ChainValidationResult
from app.main import app
from app.storage import OSProfileData, VerifiedBootKeyData, get_store
from tests.fakes import InMemoryConfigStore

BOOT_KEY = b"\x01" * 32
LEVELS = {"Software": 0, "TrustedEnvironment": 1, "StrongBox": 2}


def _parsed(nonce: str, level: int) -> ParsedAttestation:
    return ParsedAttestation(
        attestation_security_level=level,
        challenge=nonce.encode(),
        device_locked=True,
        verified_boot_state=1,
        verified_boot_key=BOOT_KEY,
        verified_boot_hash=b"\x00" * 32,
        os_patch_level=20260901,
        os_version=140000,
    )


def _verify(monkeypatch, *, level: int, policy: dict) -> dict:
    store = InMemoryConfigStore()
    store.profiles["grapheneos"] = OSProfileData(
        id="grapheneos",
        display_name="GrapheneOS",
        expected_verified_boot_state="SelfSigned",
        verified_boot_keys=[
            VerifiedBootKeyData(verified_boot_key_sha256=hashlib.sha256(BOOT_KEY).hexdigest())
        ],
    )
    store.policy.update(policy)

    async def _override():
        yield store

    app.dependency_overrides[get_store] = _override
    monkeypatch.setattr(
        main, "validate_chain", lambda certs, roots: ChainValidationResult(valid=True, reasons=[])
    )
    monkeypatch.setattr(main.x509, "load_der_x509_certificate", lambda data: object())
    try:
        client = TestClient(app)
        nonce = client.post("/nonce").json()["nonce"]
        monkeypatch.setattr(main, "parse_leaf_certificate", lambda der: _parsed(nonce, level))
        resp = client.post(
            "/verify",
            json={
                "nonce": nonce,
                "claimed_os": "grapheneos",
                "cert_chain_b64": [base64.b64encode(b"x").decode()],
            },
        )
        assert resp.status_code == 200, resp.text
        return resp.json()
    finally:
        app.dependency_overrides.pop(get_store, None)


@pytest.mark.parametrize("minimum", LEVELS)
@pytest.mark.parametrize("level", LEVELS)
def test_security_level_matrix(monkeypatch, level, minimum):
    body = _verify(monkeypatch, level=LEVELS[level], policy={"min_security_level": minimum})
    rejected = any("Security level too low" in r for r in body["deviceAttestation"]["reasons"])
    assert rejected == (LEVELS[level] < LEVELS[minimum])


def test_default_minimum_is_trusted_environment(monkeypatch):
    software = _verify(monkeypatch, level=0, policy={})
    tee = _verify(monkeypatch, level=1, policy={})
    assert "Security level too low: Software" in software["deviceAttestation"]["reasons"]
    assert tee["deviceAttestation"]["reasons"] == []


def test_unknown_minimum_fails_closed(monkeypatch):
    body = _verify(monkeypatch, level=2, policy={"min_security_level": "Bogus"})
    assert body["deviceAttestation"]["verdict"] == "fail"


def test_unknown_device_level_is_rejected(monkeypatch):
    body = _verify(monkeypatch, level=9, policy={"min_security_level": "Software"})
    assert body["deviceAttestation"]["verdict"] == "fail"
