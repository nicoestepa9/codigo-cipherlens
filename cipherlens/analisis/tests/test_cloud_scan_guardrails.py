"""Regressions for public-only cloud destinations and DNS pinning."""

import socket

import pytest

from tls_analyzer.cloud_network import (
    NonPublicTargetError,
    PinnedTarget,
    is_public_address,
    open_target_connection,
    parse_scan_target,
    resolve_target_addresses,
    validate_public_address,
)


@pytest.mark.parametrize(
    "address",
    [
        "10.1.2.3",
        "172.16.4.5",
        "192.168.1.2",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "240.0.0.1",
        "0.0.0.1",
        "192.0.2.1",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
    ],
)
def test_non_public_ipv4_ipv6_and_mapped_addresses_are_rejected(address):
    assert not is_public_address(address)
    with pytest.raises(NonPublicTargetError):
        validate_public_address(address)


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_globally_routable_addresses_are_accepted(address):
    assert is_public_address(address)
    assert validate_public_address(address) == address


def test_parse_scan_target_supports_url_host_port_and_bracketed_ipv6():
    assert parse_scan_target("https://example.test:8443/") == (
        "example.test",
        8443,
    )
    assert parse_scan_target("[2606:4700:4700::1111]:443") == (
        "2606:4700:4700::1111",
        443,
    )
    assert parse_scan_target("example.test", 9443) == ("example.test", 9443)


@pytest.mark.parametrize(
    ("target", "default_port"),
    [
        ("example.test:0", None),
        ("https://example.test:0/", None),
        ("example.test", 0),
        ("example.test", 65536),
        ("example.test:65536", None),
    ],
)
def test_parse_scan_target_rejects_invalid_ports(target, default_port):
    with pytest.raises(NonPublicTargetError, match="puerto"):
        parse_scan_target(target, default_port)


def test_dns_resolution_rejects_if_any_answer_is_not_public():
    calls = []

    def resolver(host, port, family, socktype):
        calls.append(host)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0)),
        ]

    with pytest.raises(NonPublicTargetError, match="agente"):
        resolve_target_addresses("mixed.example", resolver=resolver)
    assert calls == ["mixed.example"]


def test_dns_rebinding_cannot_change_the_pinned_connection(monkeypatch):
    resolution_calls = []
    connect_addresses = []

    def resolver(host, port, family, socktype):
        resolution_calls.append(host)
        address = "8.8.8.8" if len(resolution_calls) == 1 else "127.0.0.1"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)),
        ]

    class FakeSocket:
        pass

    def fake_create_connection(address, timeout):
        connect_addresses.append(address[0])
        return FakeSocket()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    resolved = resolve_target_addresses("rebinding.example", resolver=resolver)
    connection = open_target_connection(
        "rebinding.example",
        443,
        1.0,
        pinned_target=PinnedTarget(resolved[0]),
    )

    assert isinstance(connection, FakeSocket)
    assert resolution_calls == ["rebinding.example"]
    assert connect_addresses == ["8.8.8.8"]


def test_pinned_connection_revalidates_destination_at_connect_time(monkeypatch):
    connected = []
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda address, timeout: connected.append(address[0]),
    )
    with pytest.raises(NonPublicTargetError):
        open_target_connection(
            "public-name.example",
            443,
            1,
            pinned_target=PinnedTarget("169.254.169.254"),
        )
    assert connected == []
