"""
Tests the ASN.1 schema/decoder against a SYNTHETIC KeyDescription structure
(not a real device certificate — see the note on real fixtures below).

pyasn1 pitfall this file works around: `.subtype(explicitTag=...)` on an
already-*populated* value resets its content instead of re-tagging it. The
fix used below is to clone the field's own tagged schema template (taken
straight from the parent Sequence's componentType) and populate that clone,
which preserves both the tag and the content. This only matters for
constructing synthetic test values — real certificate parsing only decodes,
via `der_decode(..., asn1Spec=KeyDescription())`, and never hits this.

To test against a REAL device certificate instead of this synthetic one:
  1. Run a small Android app (or reference GrapheneOS's Auditor source) that
     calls KeyGenParameterSpec.Builder(...).setAttestationChallenge(...) and
     exports the resulting certificate chain.
  2. Save the leaf cert as DER bytes into tests/fixtures/leaf.der
  3. Un-skip test_parse_real_fixture below.
"""
import pathlib

import pytest
from pyasn1.codec.der.encoder import encode as der_encode

from app.attestation import (
    AttestationParseError,
    AuthorizationList,
    KeyDescription,
    RootOfTrust,
    parse_leaf_certificate,
)

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "leaf.der"


def _tagged_field(container_cls, field_name: str):
    """Return a fresh, correctly-tagged, empty instance for `field_name` on
    `container_cls`, ready to populate — see module docstring."""
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
