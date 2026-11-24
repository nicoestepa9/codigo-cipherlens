"""X.509 Certificate analyzer."""

import ssl
import socket
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from .cloud_network import PinnedTarget, open_target_connection


@dataclass
class CertificateInfo:
    """Parsed certificate information."""

    subject: dict = field(default_factory=dict)
    issuer: dict = field(default_factory=dict)
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    is_expired: bool = False
    days_until_expiry: int = 0
    san: list[str] = field(default_factory=list)
    key_type: str = ""
    key_size: int = 0
    signature_algorithm: str = ""
    fingerprint_sha256: str = ""
    fingerprint_sha1: str = ""
    is_self_signed: bool = False
    ocsp_must_staple: bool = False
    certificate_policies: list[str] = field(default_factory=list)
    basic_constraints: str = ""
    key_usage: list[str] = field(default_factory=list)
    extended_key_usage: list[str] = field(default_factory=list)
    ca_issuers: list[str] = field(default_factory=list)
    ocsp_responders: list[str] = field(default_factory=list)
    crl_distribution_points: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_name(name) -> dict:
    """Parse an x509 Name object into a dict."""
    result = {}
    for attr in name:
        oid_map = {
            NameOID.COMMON_NAME: "CN",
            NameOID.ORGANIZATION_NAME: "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.COUNTRY_NAME: "C",
            NameOID.STATE_OR_PROVINCE_NAME: "ST",
            NameOID.LOCALITY_NAME: "L",
            NameOID.EMAIL_ADDRESS: "email",
            NameOID.SERIAL_NUMBER: "serialNumber",
            NameOID.TITLE: "title",
            NameOID.SURNAME: "surname",
            NameOID.GIVEN_NAME: "givenName",
            NameOID.PSEUDONYM: "pseudonym",
            NameOID.GENERATION_QUALIFIER: "generationQualifier",
        }
        key = oid_map.get(attr.oid, attr.oid.dotted_string)
        result[key] = attr.value
    return result


def _parse_extensions(cert: x509.Certificate) -> dict:
    """Parse certificate extensions."""
    info = {}

    # Subject Alternative Names
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        if san_ext:
            info["san"] = san_ext.value.get_values_for_type(x509.DNSName)
            info["san_ip"] = san_ext.value.get_values_for_type(x509.IPAddress)
            info["san_uri"] = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
            info["san_email"] = san_ext.value.get_values_for_type(x509.RFC822Name)
    except x509.ExtensionNotFound:
        pass

    # Key Usage
    try:
        ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if ku_ext:
            ku = ku_ext.value
            info["key_usage"] = [
                name for name, flag in [
                    ("digitalSignature", ku.digital_signature),
                    ("keyEncipherment", ku.key_encipherment),
                    ("dataEncipherment", ku.data_encipherment),
                    ("keyAgreement", ku.key_agreement),
                    ("keyCertSign", ku.key_cert_sign),
                    ("cRLSign", ku.crl_sign),
                ] if flag
            ]
            try:
                if ku.encipher_only:
                    info["key_usage"].append("encipherOnly")
                if ku.decipher_only:
                    info["key_usage"].append("decipherOnly")
            except Exception:
                pass
    except x509.ExtensionNotFound:
        pass

    # Extended Key Usage
    try:
        eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if eku_ext:
            info["extended_key_usage"] = [
                _oid_name(oid) for oid in eku_ext.value
            ]
    except x509.ExtensionNotFound:
        pass

    # Basic Constraints
    try:
        bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc_ext:
            info["basic_constraints"] = f"CA={bc_ext.value.ca}, pathLen={bc_ext.value.path_length}"
    except x509.ExtensionNotFound:
        pass

    # OCSP Must-Staple
    try:
        info["ocsp_must_staple"] = bool(
            cert.extensions.get_extension_for_class(x509.TLSFeature)
        )
    except x509.ExtensionNotFound:
        info["ocsp_must_staple"] = False

    # Authority Information Access (CA issuers + OCSP)
    try:
        aia_ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        if aia_ext:
            info["ca_issuers"] = [
                desc.access_location.value for desc in aia_ext.value
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
            ]
            info["ocsp_responders"] = [
                desc.access_location.value for desc in aia_ext.value
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP
            ]
    except x509.ExtensionNotFound:
        pass

    # CRL Distribution Points
    try:
        crl_ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        if crl_ext:
            info["crl_distribution_points"] = [
                dp.full_name[0].value for dp in crl_ext.value
                if dp.full_name
            ]
    except x509.ExtensionNotFound:
        pass

    return info


def _oid_name(oid) -> str:
    """Convert an OID to a human-readable name."""
    oid_map = {
        ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth",
        ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth",
        ExtendedKeyUsageOID.CODE_SIGNING: "codeSigning",
        ExtendedKeyUsageOID.EMAIL_PROTECTION: "emailProtection",
        ExtendedKeyUsageOID.TIME_STAMPING: "timeStamping",
        ExtendedKeyUsageOID.OCSP_SIGNING: "ocspSigning",
    }
    return oid_map.get(oid, oid.dotted_string)


def _detect_key_info(cert: x509.Certificate) -> tuple[str, int]:
    """Detect key type and size."""
    pubkey = cert.public_key()
    if isinstance(pubkey, rsa.RSAPublicKey):
        return "RSA", pubkey.key_size
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        return f"EC ({pubkey.curve.name})", pubkey.key_size
    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    elif isinstance(pubkey, ed448.Ed448PublicKey):
        return "Ed448", 448
    elif isinstance(pubkey, dsa.DSAPublicKey):
        return "DSA", pubkey.key_size
    return "Unknown", 0


def analyze_certificate_from_der(der_data: bytes) -> CertificateInfo:
    """Analyze a DER-encoded certificate."""
    cert = x509.load_der_x509_certificate(der_data)
    return _parse_cert(cert)


def analyze_certificate_from_pem(pem_data: bytes) -> CertificateInfo:
    """Analyze a PEM-encoded certificate."""
    cert = x509.load_pem_x509_certificate(pem_data)
    return _parse_cert(cert)


def _parse_cert(cert: x509.Certificate) -> CertificateInfo:
    """Parse a cryptography Certificate object into CertificateInfo."""
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    days_left = (not_after - now).days

    info = CertificateInfo(
        subject=_parse_name(cert.subject),
        issuer=_parse_name(cert.issuer),
        serial_number=format(cert.serial_number, "X"),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=not_after.isoformat(),
        is_expired=now > not_after,
        days_until_expiry=days_left,
    )

    # Key info
    key_type, key_size = _detect_key_info(cert)
    info.key_type = key_type
    info.key_size = key_size

    # Signature algorithm
    info.signature_algorithm = cert.signature_algorithm_oid._name

    # Fingerprints
    info.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex(":")
    info.fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex(":")

    # Self-signed check
    info.is_self_signed = cert.issuer == cert.subject

    # Extensions
    ext_info = _parse_extensions(cert)
    info.san = [
        *ext_info.get("san", []),
        *(str(address) for address in ext_info.get("san_ip", [])),
    ]
    info.basic_constraints = ext_info.get("basic_constraints", "")
    info.key_usage = ext_info.get("key_usage", [])
    info.extended_key_usage = ext_info.get("extended_key_usage", [])
    info.ocsp_must_staple = ext_info.get("ocsp_must_staple", False)
    info.ca_issuers = ext_info.get("ca_issuers", [])
    info.ocsp_responders = ext_info.get("ocsp_responders", [])
    info.crl_distribution_points = ext_info.get("crl_distribution_points", [])

    return info


def fetch_certificate_chain(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    *,
    pinned_target: PinnedTarget | None = None,
) -> list[CertificateInfo]:
    """Connect to a server and fetch the full certificate chain."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    chain = []
    try:
        raw_sock = open_target_connection(
            host, port, timeout, pinned_target=pinned_target
        )
        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=host)

        # Try full chain first
        der_certs = ssl_sock.getpeercert_chain()
        if der_certs:
            for der in der_certs:
                try:
                    info = analyze_certificate_from_der(der)
                    chain.append(info)
                except Exception:
                    pass

        # Fallback: if no chain, try to get the leaf cert via getpeercert
        if not chain:
            peer_cert = ssl_sock.getpeercert(binary_form=True)
            if peer_cert:
                try:
                    info = analyze_certificate_from_der(peer_cert)
                    chain.append(info)
                except Exception:
                    pass

        ssl_sock.close()
        raw_sock.close()
    except Exception:
        pass

    return chain


def validate_hostname(cert_info: CertificateInfo, hostname: str) -> bool:
    """Check if the certificate's SAN or CN matches the given hostname."""
    # Check SAN first (preferred)
    for san in cert_info.san:
        if san.startswith("*."):
            # Wildcard match
            suffix = san[1:]  # .example.com
            if hostname.endswith(suffix) and "." not in hostname.replace(suffix, ""):
                return True
        elif san == hostname:
            return True

    # Fallback to CN
    cn = cert_info.subject.get("CN", "")
    if cn.startswith("*."):
        suffix = cn[1:]
        if hostname.endswith(suffix) and "." not in hostname.replace(suffix, ""):
            return True
    elif cn == hostname:
        return True

    return False


def get_chain_validation_info(chain: list[CertificateInfo]) -> dict:
    """Analyze the certificate chain for common issues."""
    issues = []
    warnings = []

    if not chain:
        issues.append("No certificate chain received")
        return {"issues": issues, "warnings": warnings, "valid": False}

    leaf = chain[0]

    # Check expiry
    if leaf.is_expired:
        issues.append(f"Certificate EXPIRED on {leaf.not_after}")

    # Check self-signed leaf
    if leaf.is_self_signed and len(chain) == 1:
        issues.append("Certificate is self-signed (no CA chain)")

    # Check weak key
    if leaf.key_type == "RSA" and leaf.key_size < 2048:
        issues.append(f"Weak RSA key: {leaf.key_size} bits (minimum 2048)")
    elif leaf.key_type == "EC" and leaf.key_size < 256:
        issues.append(f"Weak EC key: {leaf.key_size} bits (minimum 256)")

    # Check SHA-1 signature
    if "sha1" in leaf.signature_algorithm.lower():
        issues.append("Certificate uses SHA-1 signature algorithm (insecure)")

    # Check near expiry (30 days)
    if 0 < leaf.days_until_expiry <= 30:
        warnings.append(f"Certificate expires in {leaf.days_until_expiry} days")

    # Check chain length
    if len(chain) == 1:
        warnings.append("Certificate chain has only 1 certificate (no intermediate)")

    return {
        "issues": issues,
        "warnings": warnings,
        "valid": len(issues) == 0,
    }
