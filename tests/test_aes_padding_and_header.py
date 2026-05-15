import pytest

from aes_socket_utils import (
    BLOCK_SIZE,
    build_data_packet,
    build_key_packet,
    decrypt_aes_cbc,
    encrypt_aes_cbc,
    parse_key_packet,
    parse_length_header,
    pad,
    unpad,
)

# =========================
# PKCS#7 Padding Tests
# =========================

def test_pad_unpad_roundtrip():
    """
    Test PKCS#7 padding roundtrip.
    """

    data = b"hello AES socket"

    padded = pad(data)

    assert len(padded) % BLOCK_SIZE == 0

    unpadded = unpad(padded)

    assert unpadded == data


def test_unpad_invalid_padding():
    """
    Test invalid PKCS#7 padding.
    """

    invalid = b"hello\x01\x02\x03"

    with pytest.raises(ValueError):
        unpad(invalid)


# =========================
# AES-CBC Encryption Tests
# =========================

def test_aes_cbc_roundtrip():
    """
    Test AES-CBC encrypt/decrypt.
    """

    plain = b"FIT4012 Lab 6 AES-CBC"

    key, iv, cipher_bytes = encrypt_aes_cbc(
        plain,
        key=b"1" * 16,
        iv=b"2" * 16,
    )

    assert len(key) == 16
    assert len(iv) == 16

    assert len(cipher_bytes) % 16 == 0

    decrypted = decrypt_aes_cbc(
        key,
        iv,
        cipher_bytes,
    )

    assert decrypted == plain


def test_wrong_key_decryption():
    """
    Test decryption with wrong key.
    """

    plain = b"Secret Message"

    key, iv, cipher_bytes = encrypt_aes_cbc(
        plain,
        key=b"1" * 16,
        iv=b"2" * 16,
    )

    wrong_key = b"9" * 16

    with pytest.raises(ValueError):
        decrypt_aes_cbc(
            wrong_key,
            iv,
            cipher_bytes,
        )


# =========================
# Key Channel Tests
# =========================

def test_key_packet_roundtrip():
    """
    Test key packet build/parse.
    """

    key = b"1" * 16
    iv = b"2" * 16

    packet = build_key_packet(
        key,
        iv,
    )

    parsed_key, parsed_iv = parse_key_packet(
        packet
    )

    assert parsed_key == key
    assert parsed_iv == iv


def test_invalid_key_packet():
    """
    Test invalid key packet.
    """

    invalid_packet = b"\x00\x00\x00\x10abc"

    with pytest.raises(ValueError):
        parse_key_packet(
            invalid_packet
        )


# =========================
# Data Channel Tests
# =========================

def test_data_packet_contains_correct_length():
    """
    Test data packet length header.
    """

    _, _, cipher_bytes = encrypt_aes_cbc(
        b"FIT4012",
        key=b"1" * 16,
        iv=b"2" * 16,
    )

    packet = build_data_packet(
        cipher_bytes
    )

    length = parse_length_header(
        packet[:4]
    )

    assert length == len(cipher_bytes)

    assert packet[4:] == cipher_bytes


def test_invalid_length_header():
    """
    Test invalid length header.
    """

    with pytest.raises(ValueError):
        parse_length_header(b"\x00\x01")


# =========================
# Ciphertext Tampering Test
# =========================

def test_tampered_ciphertext():
    """
    Test modified ciphertext.
    """

    plain = b"Attack at dawn"

    key, iv, cipher_bytes = encrypt_aes_cbc(
        plain,
        key=b"1" * 16,
        iv=b"2" * 16,
    )

    tampered = bytearray(cipher_bytes)

    # Modify ciphertext
    tampered[0] ^= 0xFF

    with pytest.raises(Exception):
        decrypt_aes_cbc(
            key,
            iv,
            bytes(tampered),
        )
