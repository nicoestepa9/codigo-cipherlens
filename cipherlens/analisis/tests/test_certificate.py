"""Tests for certificate module."""

from tls_analyzer.certificate import CertificateInfo, validate_hostname


def test_validate_hostname_exact_match():
    cert = CertificateInfo(subject={"CN": "example.com"}, san=["example.com"])
    assert validate_hostname(cert, "example.com") is True


def test_validate_hostname_san_match():
    cert = CertificateInfo(subject={"CN": "other.com"}, san=["example.com", "other.com"])
    assert validate_hostname(cert, "example.com") is True


def test_validate_hostname_wildcard():
    cert = CertificateInfo(subject={"CN": "*.example.com"}, san=["*.example.com"])
    assert validate_hostname(cert, "sub.example.com") is True
    assert validate_hostname(cert, "deep.sub.example.com") is False


def test_validate_hostname_no_match():
    cert = CertificateInfo(subject={"CN": "other.com"}, san=["other.com"])
    assert validate_hostname(cert, "example.com") is False


def test_certificate_info_to_dict():
    cert = CertificateInfo(
        subject={"CN": "test.com"},
        issuer={"CN": "Test CA"},
        serial_number="ABCD",
    )
    d = cert.to_dict()
    assert d["subject"]["CN"] == "test.com"
    assert d["issuer"]["CN"] == "Test CA"
