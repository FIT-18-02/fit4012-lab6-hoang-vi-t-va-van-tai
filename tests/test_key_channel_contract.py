import pytest

from aes_socket_utils import (
    build_key_packet,
    parse_key_packet,
)

# =========================
# Key Channel Tests
# =========================

def test_key_channel_contract_aes_128():
    """
    Test AES-128 key channel packet.

    Packet format:
    [key_length][key][iv]
    """

    key = b"a" * 16
    iv = b"b" * 16

    packet = build_key_packet(
        key,
        iv,
    )

    # First 4 bytes = key length
    assert packet[:4] == (
        16
    ).to_bytes(4, "big")

    # AES key
    assert packet[4:20] == key

    # AES IV
    assert packet[20:36] == iv

    # Parse packet
    parsed_key, parsed_iv = parse_key_packet(
        packet
    )

    assert parsed_key == key
    assert parsed_iv == iv


def test_key_channel_contract_aes_256():
    """
    Test AES-256 key channel packet.
    """

    key = b"a" * 32
    iv = b"b" * 16

    packet = build_key_packet(
        key,
        iv,
    )

    # First 4 bytes = key length
    assert packet[:4] == (
        32
    ).to_bytes(4, "big")

    parsed_key, parsed_iv = parse_key_packet(
        packet
    )

    assert parsed_key == key
    assert parsed_iv == iv


def test_invalid_key_size_should_fail():
    """
    Invalid AES key size should fail.
    """

    with pytest.raises(ValueError):
        build_key_packet(
            b"short",
            b"b" * 16,
        )


def test_invalid_iv_size_should_fail():
    """
    Invalid IV size should fail.
    """

    with pytest.raises(ValueError):
        build_key_packet(
            b"a" * 16,
            b"short",
        )


def test_invalid_key_packet_should_fail():
    """
    Invalid packet format should fail.
    """

    invalid_packet = b"\x00\x00\x00\x10abc"

    with pytest.raises(ValueError):
        parse_key_packet(
            invalid_packet
        )


def test_wrong_key_length_in_header():
    """
    Wrong key length in packet header.
    """

    key = b"a" * 16
    iv = b"b" * 16

    # Fake header = 32
    packet = (
        (32).to_bytes(4, "big")
        + key
        + iv
    )

    with pytest.raises(ValueError):
        parse_key_packet(
            packet
        )


def test_packet_total_size():
    """
    Total packet size check.
    """

    key = b"a" * 16
    iv = b"b" * 16

    packet = build_key_packet(
        key,
        iv,
    )

    # 4-byte header + 16-byte key + 16-byte IV
    assert len(packet) == 36
