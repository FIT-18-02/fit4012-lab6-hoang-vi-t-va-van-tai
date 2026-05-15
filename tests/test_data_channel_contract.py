import pytest

from aes_socket_utils import (
    build_data_packet,
    parse_length_header,
)

# =========================
# Data Channel Tests
# =========================

def test_data_channel_contract():
    """
    Test data channel packet format.

    Packet structure:
    [ciphertext_length][ciphertext]
    """

    ciphertext = b"x" * 32

    packet = build_data_packet(
        ciphertext
    )

    # First 4 bytes = length header
    assert packet[:4] == (
        32
    ).to_bytes(4, "big")

    # Parse length header
    assert parse_length_header(
        packet[:4]
    ) == 32

    # Remaining bytes = ciphertext
    assert packet[4:] == ciphertext


def test_empty_ciphertext_should_fail():
    """
    Empty ciphertext is invalid.
    """

    with pytest.raises(ValueError):
        build_data_packet(b"")


def test_bad_length_header_should_fail():
    """
    Invalid length header should fail.
    """

    with pytest.raises(ValueError):
        parse_length_header(
            b"\x00\x01"
        )


def test_zero_length_header_should_fail():
    """
    Length header = 0 should fail.
    """

    with pytest.raises(ValueError):
        parse_length_header(
            b"\x00\x00\x00\x00"
        )


def test_large_ciphertext_packet():
    """
    Test large ciphertext packet.
    """

    ciphertext = b"A" * 1024

    packet = build_data_packet(
        ciphertext
    )

    length = parse_length_header(
        packet[:4]
    )

    assert length == 1024

    assert packet[4:] == ciphertext


def test_packet_total_size():
    """
    Total packet size must equal:
    4-byte header + ciphertext length
    """

    ciphertext = b"FIT4012"

    packet = build_data_packet(
        ciphertext
    )

    assert len(packet) == (
        4 + len(ciphertext)
    )
