import os
import struct
from typing import Tuple

from Crypto.Cipher import AES

# =========================
# AES Configuration
# =========================

BLOCK_SIZE = 16
HEADER_SIZE = 4
KEY_HEADER_SIZE = 4
IV_SIZE = 16

VALID_KEY_SIZES = (16, 32)

# Compatibility aliases
LENGTH_HEADER_SIZE = HEADER_SIZE
KEY_LENGTH_HEADER_SIZE = KEY_HEADER_SIZE


# =========================
# PKCS#7 Padding
# =========================

def pad(data: bytes) -> bytes:

    if data is None:
        raise ValueError("Data cannot be None.")

    pad_len = BLOCK_SIZE - (
        len(data) % BLOCK_SIZE
    )

    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes) -> bytes:

    if not data:
        raise ValueError(
            "Invalid padded data."
        )

    pad_len = data[-1]

    if (
        pad_len < 1 or
        pad_len > BLOCK_SIZE
    ):
        raise ValueError(
            "Invalid padding length."
        )

    expected = bytes([pad_len]) * pad_len

    if data[-pad_len:] != expected:
        raise ValueError(
            "Invalid PKCS#7 padding."
        )

    return data[:-pad_len]


# =========================
# AES Key / IV
# =========================

def generate_key_iv(
    key_size: int = 16,
) -> Tuple[bytes, bytes]:

    if key_size not in VALID_KEY_SIZES:
        raise ValueError(
            "AES key size must be 16 or 32 bytes."
        )

    key = os.urandom(key_size)
    iv = os.urandom(IV_SIZE)

    return key, iv


def validate_key_iv(
    key: bytes,
    iv: bytes,
) -> None:

    if len(key) not in VALID_KEY_SIZES:
        raise ValueError(
            "Invalid AES key size."
        )

    if len(iv) != IV_SIZE:
        raise ValueError(
            "AES IV must be 16 bytes."
        )


# =========================
# AES Encryption / Decryption
# =========================

def encrypt_aes_cbc(
    plaintext: bytes,
    key: bytes | None = None,
    iv: bytes | None = None,
    key_size: int = 16,
) -> Tuple[bytes, bytes, bytes]:

    if plaintext is None:
        raise ValueError(
            "Plaintext cannot be None."
        )

    if key is None or iv is None:
        key, iv = generate_key_iv(
            key_size
        )

    validate_key_iv(key, iv)

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv,
    )

    padded = pad(plaintext)

    ciphertext = cipher.encrypt(
        padded
    )

    return key, iv, ciphertext


def decrypt_aes_cbc(
    key: bytes,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:

    validate_key_iv(key, iv)

    if len(ciphertext) == 0:
        raise ValueError(
            "Ciphertext cannot be empty."
        )

    if (
        len(ciphertext) %
        BLOCK_SIZE != 0
    ):
        raise ValueError(
            "Ciphertext length invalid."
        )

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv,
    )

    decrypted = cipher.decrypt(
        ciphertext
    )

    return unpad(decrypted)


# =========================
# Key Channel Packet
# =========================

def build_key_packet(
    key: bytes,
    iv: bytes,
) -> bytes:

    validate_key_iv(key, iv)

    return (
        struct.pack("!I", len(key))
        + key
        + iv
    )


def parse_key_packet(
    packet: bytes,
) -> Tuple[bytes, bytes]:

    if len(packet) < (
        KEY_HEADER_SIZE + IV_SIZE
    ):
        raise ValueError(
            "Key packet too short."
        )

    key_len = struct.unpack(
        "!I",
        packet[:KEY_HEADER_SIZE]
    )[0]

    if key_len not in VALID_KEY_SIZES:
        raise ValueError(
            "Invalid key length."
        )

    expected_len = (
        KEY_HEADER_SIZE +
        key_len +
        IV_SIZE
    )

    if len(packet) != expected_len:
        raise ValueError(
            "Invalid key packet length."
        )

    key_start = KEY_HEADER_SIZE
    key_end = key_start + key_len

    key = packet[key_start:key_end]

    iv = packet[
        key_end:key_end + IV_SIZE
    ]

    return key, iv


# =========================
# Data Channel Packet
# =========================

def build_packet(
    ciphertext: bytes,
) -> bytes:

    if len(ciphertext) == 0:
        raise ValueError(
            "Ciphertext cannot be empty."
        )

    return (
        struct.pack(
            "!I",
            len(ciphertext)
        )
        + ciphertext
    )


def parse_header(
    header: bytes,
) -> int:

    if len(header) != HEADER_SIZE:
        raise ValueError(
            "Header must be 4 bytes."
        )

    length = struct.unpack(
        "!I",
        header,
    )[0]

    if length <= 0:
        raise ValueError(
            "Invalid payload length."
        )

    return length


# Compatibility aliases
build_data_packet = build_packet
parse_length_header = parse_header


# =========================
# Socket Utility
# =========================

def recv_exact(
    conn,
    n: int,
) -> bytes:

    if n <= 0:
        raise ValueError(
            "n must be > 0."
        )

    chunks = []
    received = 0

    while received < n:

        chunk = conn.recv(
            n - received
        )

        if not chunk:
            raise ConnectionError(
                "Connection closed early."
            )

        chunks.append(chunk)

        received += len(chunk)

    return b"".join(chunks)
