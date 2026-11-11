"""Synthetic KeyDescription round-trip tests. Not real device data."""
import pathlib

import pytest
from pyasn1.codec.der.encoder import encode as der_encode

from app.attestation import (
    AuthorizationList,
    KeyDescription,
    parse_leaf_certificate,
)

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "leaf.der"


def _tagged_field(container_cls, field_name: str):
    """Clone the tagged template; re-tagging a populated value resets it."""
    return container_cls().componentType[field_name].asn1Object.clone()


def build_synthetic_key_description(
    *,
    challenge: bytes,
    security_level: int,
    device_locked: bool,
    verified_boot_state: int,
    verified_boot_key: bytes,
    os_patch_level: int,
) -> bytes:
    rot = _tagged_field(AuthorizationList, "rootOfTrust")
    rot["verifiedBootKey"] = verified_boot_key
    rot["deviceLocked"] = device_locked
    rot["verifiedBootState"] = verified_boot_state
    rot["verifiedBootHash"] = b"\x00" * 32

    patch = _tagged_field(AuthorizationList, "osPatchLevel").clone(value=os_patch_level)

    tee = AuthorizationList()
    tee["rootOfTrust"] = rot
    tee["osPatchLevel"] = patch

    kd = KeyDescription()
    kd["attestationVersion"] = 300
    kd["attestationSecurityLevel"] = security_level
    kd["keymasterVersion"] = 300
    kd["keymasterSecurityLevel"] = security_level
    kd["attestationChallenge"] = challenge
    kd["uniqueId"] = b""
    kd["softwareEnforced"] = AuthorizationList()
    kd["teeEnforced"] = tee

    return der_encode(kd)


def test_schema_imports():
    from app.attestation import KeyDescription  # noqa: F401


def test_synthetic_round_trip():
    encoded = build_synthetic_key_description(
        challenge=b"test-nonce-123",
        security_level=1,  # TrustedEnvironment
        device_locked=True,
        verified_boot_state=1,  # SelfSigned (expected for GrapheneOS)
        verified_boot_key=b"\x01" * 32,
        os_patch_level=20260901,
    )

    from pyasn1.codec.der.decoder import decode as der_decode

    decoded, rest = der_decode(encoded, asn1Spec=KeyDescription())
    assert rest == b""
    assert bytes(decoded["attestationChallenge"]) == b"test-nonce-123"

    tee = decoded["teeEnforced"]
    assert tee["rootOfTrust"].isValue
    rot = tee["rootOfTrust"]
    assert bool(rot["deviceLocked"]) is True
    assert int(rot["verifiedBootState"]) == 1
    assert bytes(rot["verifiedBootKey"]) == b"\x01" * 32
    assert tee["osPatchLevel"].isValue
    assert int(tee["osPatchLevel"]) == 20260901


@pytest.mark.skipif(not FIXTURE.exists(), reason="No real attestation fixture yet")
def test_parse_real_fixture():
    der_bytes = FIXTURE.read_bytes()
    parsed = parse_leaf_certificate(der_bytes)
    assert parsed.attestation_security_level in (1, 2)  # TEE or StrongBox
    assert parsed.device_locked is True
