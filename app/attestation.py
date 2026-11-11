"""Android Key Attestation extension parser. Unvalidated against real devices."""
from __future__ import annotations

from dataclasses import dataclass

from cryptography import x509
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.type import char, constraint, namedtype, tag, univ

ATTESTATION_EXTENSION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

_CTX = tag.tagClassContext
_CONS = tag.tagFormatConstructed


def _explicit(tag_number: int):
    return tag.Tag(_CTX, _CONS, tag_number)


class VerifiedBootState:
    VERIFIED = 0
    SELF_SIGNED = 1
    UNVERIFIED = 2
    FAILED = 3

    NAMES = {
        VERIFIED: "Verified",
        SELF_SIGNED: "SelfSigned",
        UNVERIFIED: "Unverified",
        FAILED: "Failed",
    }


class SecurityLevel:
    SOFTWARE = 0
    TRUSTED_ENVIRONMENT = 1
    STRONGBOX = 2

    NAMES = {
        SOFTWARE: "Software",
        TRUSTED_ENVIRONMENT: "TrustedEnvironment",
        STRONGBOX: "StrongBox",
    }


class RootOfTrust(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("verifiedBootKey", univ.OctetString()),
        namedtype.NamedType("deviceLocked", univ.Boolean()),
        namedtype.NamedType("verifiedBootState", univ.Integer()),
        namedtype.OptionalNamedType("verifiedBootHash", univ.OctetString()),
    )


def _opt(name: str, tag_number: int, component=None):
    """Optional explicitly-tagged field. Call .subtype() only on untouched templates."""
    component = component if component is not None else univ.Integer()
    return namedtype.OptionalNamedType(
        name, component.subtype(explicitTag=_explicit(tag_number))
    )


class AuthorizationList(univ.Sequence):
    # Tag numbers per the Android attestation schema.
    componentType = namedtype.NamedTypes(
        _opt("purpose", 1, univ.SetOf(componentType=univ.Integer())),
        _opt("algorithm", 2),
        _opt("keySize", 3),
        _opt("digest", 5, univ.SetOf(componentType=univ.Integer())),
        _opt("padding", 6, univ.SetOf(componentType=univ.Integer())),
        _opt("ecCurve", 10),
        _opt("rsaPublicExponent", 200),
        _opt("mgfDigest", 203, univ.SetOf(componentType=univ.Integer())),
        _opt("rollbackResistance", 303, univ.Null()),
        _opt("earlyBootOnly", 305, univ.Null()),
        _opt("activeDateTime", 400),
        _opt("originationExpireDateTime", 401),
        _opt("usageExpireDateTime", 402),
        _opt("usageCountLimit", 405),
        _opt("noAuthRequired", 503, univ.Null()),
        _opt("userAuthType", 504),
        _opt("authTimeout", 505),
        _opt("allowWhileOnBody", 506, univ.Null()),
        _opt("trustedUserPresenceRequired", 507, univ.Null()),
        _opt("trustedConfirmationRequired", 508, univ.Null()),
        _opt("unlockedDeviceRequired", 509, univ.Null()),
        _opt("creationDateTime", 701),
        _opt("origin", 702),
        _opt("rootOfTrust", 704, RootOfTrust()),
        _opt("osVersion", 705),
        _opt("osPatchLevel", 706),
        _opt("attestationApplicationId", 709, univ.OctetString()),
        _opt("attestationIdBrand", 710, univ.OctetString()),
        _opt("attestationIdDevice", 711, univ.OctetString()),
        _opt("attestationIdProduct", 712, univ.OctetString()),
        _opt("attestationIdSerial", 713, univ.OctetString()),
        _opt("attestationIdImei", 714, univ.OctetString()),
        _opt("attestationIdMeid", 715, univ.OctetString()),
        _opt("attestationIdManufacturer", 716, univ.OctetString()),
        _opt("attestationIdModel", 717, univ.OctetString()),
        _opt("vendorPatchLevel", 718),
        _opt("bootPatchLevel", 719),
        _opt("deviceUniqueAttestation", 720, univ.Null()),
    )


class KeyDescription(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("attestationVersion", univ.Integer()),
        namedtype.NamedType("attestationSecurityLevel", univ.Integer()),
        namedtype.NamedType("keymasterVersion", univ.Integer()),
        namedtype.NamedType("keymasterSecurityLevel", univ.Integer()),
        namedtype.NamedType("attestationChallenge", univ.OctetString()),
        namedtype.NamedType("uniqueId", univ.OctetString()),
        namedtype.NamedType("softwareEnforced", AuthorizationList()),
        namedtype.NamedType("teeEnforced", AuthorizationList()),
    )


@dataclass
class ParsedAttestation:
    attestation_security_level: int
    challenge: bytes
    device_locked: bool | None
    verified_boot_state: int | None
    verified_boot_key: bytes | None
    verified_boot_hash: bytes | None
    os_patch_level: int | None
    os_version: int | None

    @property
    def security_level_name(self) -> str:
        return SecurityLevel.NAMES.get(self.attestation_security_level, "Unknown")

    @property
    def verified_boot_state_name(self) -> str | None:
        if self.verified_boot_state is None:
            return None
        return VerifiedBootState.NAMES.get(self.verified_boot_state, "Unknown")


class AttestationParseError(Exception):
    pass


def parse_leaf_certificate(der_bytes: bytes) -> ParsedAttestation:
    cert = x509.load_der_x509_certificate(der_bytes)

    try:
        ext = cert.extensions.get_extension_for_oid(ATTESTATION_EXTENSION_OID)
    except x509.ExtensionNotFound as e:
        raise AttestationParseError(
            "Certificate has no attestation extension — not a Key Attestation cert"
        ) from e

    raw = ext.value.value  # OCTET STRING containing the DER-encoded KeyDescription

    try:
        key_desc, _ = der_decode(raw, asn1Spec=KeyDescription())
    except Exception as e:  # pyasn1 raises various error types
        raise AttestationParseError(f"Failed to decode attestation extension: {e}") from e

    tee = key_desc["teeEnforced"]
    root_of_trust = tee["rootOfTrust"] if tee["rootOfTrust"].isValue else None

    device_locked = None
    verified_boot_state = None
    verified_boot_key = None
    verified_boot_hash = None

    if root_of_trust is not None:
        rot = root_of_trust
        device_locked = bool(rot["deviceLocked"])
        verified_boot_state = int(rot["verifiedBootState"])
        verified_boot_key = bytes(rot["verifiedBootKey"])
        if rot["verifiedBootHash"].isValue:
            verified_boot_hash = bytes(rot["verifiedBootHash"])

    os_patch_level = int(tee["osPatchLevel"]) if tee["osPatchLevel"].isValue else None
    os_version = int(tee["osVersion"]) if tee["osVersion"].isValue else None

    return ParsedAttestation(
        attestation_security_level=int(key_desc["attestationSecurityLevel"]),
        challenge=bytes(key_desc["attestationChallenge"]),
        device_locked=device_locked,
        verified_boot_state=verified_boot_state,
        verified_boot_key=verified_boot_key,
        verified_boot_hash=verified_boot_hash,
        os_patch_level=os_patch_level,
        os_version=os_version,
    )
