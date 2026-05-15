import os
import struct
from typing import Tuple

from Crypto.Cipher import AES

# =========================
# AES configuration
# =========================

BLOCK_SIZE = 16

# Packet header sizes
LENGTH_HEADER_SIZE = 4
KEY_LENGTH_HEADER_SIZE = 4

# AES-CBC IV size
IV_SIZE = 16

# Supported AES key sizes
VALID_KEY_SIZES = (16, 32)


# =========================
# PKCS#7 Padding
# =========================

def pad(data: bytes) -> bytes:
    """
    Apply PKCS#7 padding for AES block size.
    """

    if data is None:
        raise ValueError("Data không được là None.")

    pad_len = BLOCK_SIZE - (
        len(data) % BLOCK_SIZE
    )

    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes) -> bytes:
    """
    Remove and validate PKCS#7 padding.
    """

    if not data:
        raise ValueError(
            "Dữ liệu rỗng, "
            "không thể bỏ padding."
        )

    pad_len = data[-1]

    # Validate padding length
    if (
        pad_len < 1 or
        pad_len > BLOCK_SIZE
    ):
        raise ValueError(
            "Padding không hợp lệ."
        )

    expected = bytes([pad_len]) * pad_len

    # Validate PKCS#7 bytes
    if data[-pad_len:] != expected:
        raise ValueError(
            "Padding PKCS#7 không hợp lệ."
        )

    return data[:-pad_len]


# =========================
# AES Key / IV Utilities
# =========================

def generate_key_iv(
    key_size: int = 16,
) -> Tuple[bytes, bytes]:
    """
    Generate random AES key and IV.
    """

    if key_size not in VALID_KEY_SIZES:
        raise ValueError(
            "AES key size phải là "
            "16 bytes (AES-128) "
            "hoặc 32 bytes (AES-256)."
        )

    key = os.urandom(key_size)
    iv = os.urandom(IV_SIZE)

    return key, iv


def validate_key_iv(
    key: bytes,
    iv: bytes,
) -> None:
    """
    Validate AES key and IV.
    """

    if len(key) not in VALID_KEY_SIZES:
        raise ValueError(
            "AES key phải dài "
            "16 hoặc 32 byte."
        )

    if len(iv) != IV_SIZE:
        raise ValueError(
            "IV của AES-CBC "
            "phải dài 16 byte."
        )


# =========================
# AES Encryption / Decryption
# =========================

def encrypt_aes_cbc(
    plain: bytes,
    key: bytes | None = None,
    iv: bytes | None = None,
    key_size: int = 16,
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext using AES-CBC.
    """

    if plain is None:
        raise ValueError(
            "Plaintext không được là None."
        )

    # Auto-generate key + IV
    if key is None or iv is None:
        key, iv = generate_key_iv(
            key_size
        )

    validate_key_iv(key, iv)

    # Create AES cipher
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv,
    )

    # Apply PKCS#7 padding
    padded_plain = pad(plain)

    # Encrypt
    cipher_bytes = cipher.encrypt(
        padded_plain
    )

    return key, iv, cipher_bytes


def decrypt_aes_cbc(
    key: bytes,
    iv: bytes,
    cipher_bytes: bytes,
) -> bytes:
    """
    Decrypt AES-CBC ciphertext.
    """

    validate_key_iv(key, iv)

    if len(cipher_bytes) == 0:
        raise ValueError(
            "Ciphertext không được rỗng."
        )

    if (
        len(cipher_bytes) %
        BLOCK_SIZE != 0
    ):
        raise ValueError(
            "Ciphertext phải có "
            "độ dài là bội số của "
            "16 byte."
        )

    # Create AES cipher
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv,
    )

    # Decrypt
    decrypted = cipher.decrypt(
        cipher_bytes
    )

    # Remove PKCS#7 padding
    return unpad(decrypted)


# =========================
# Key Channel Packet
# =========================

def build_key_packet(
    key: bytes,
    iv: bytes,
) -> bytes:
    """
    Build key channel packet:
    [key_length][key][iv]
    """

    validate_key_iv(key, iv)

    return (
        struct.pack("!I", len(key))
        + key
        + iv
    )


def parse_key_packet(
    packet: bytes,
) -> Tuple[bytes, bytes]:
    """
    Parse key channel packet.
    """

    if len(packet) < (
        KEY_LENGTH_HEADER_SIZE +
        IV_SIZE
    ):
        raise ValueError(
            "Key packet quá ngắn."
        )

    # Read key length
    key_len = struct.unpack(
        "!I",
        packet[:KEY_LENGTH_HEADER_SIZE]
    )[0]

    if key_len not in VALID_KEY_SIZES:
        raise ValueError(
            "Key length không hợp lệ."
        )

    expected_len = (
        KEY_LENGTH_HEADER_SIZE +
        key_len +
        IV_SIZE
    )

    if len(packet) != expected_len:
        raise ValueError(
            "Key packet có "
            "độ dài không đúng."
        )

    # Extract key
    key_start = KEY_LENGTH_HEADER_SIZE
    key_end = key_start + key_len

    key = packet[key_start:key_end]

    # Extract IV
    iv = packet[
        key_end:key_end + IV_SIZE
    ]

    validate_key_iv(key, iv)

    return key, iv


# =========================
# Data Channel Packet
# =========================

def build_data_packet(
    cipher_bytes: bytes,
) -> bytes:
    """
    Build data packet:
    [ciphertext_length][ciphertext]
    """

    if len(cipher_bytes) == 0:
        raise ValueError(
            "Ciphertext không được rỗng."
        )

    return (
        struct.pack(
            "!I",
            len(cipher_bytes)
        )
        + cipher_bytes
    )


def parse_length_header(
    header: bytes,
) -> int:
    """
    Parse 4-byte network-order
    length header.
    """

    if len(header) != LENGTH_HEADER_SIZE:
        raise ValueError(
            "Length header phải dài "
            "đúng 4 byte."
        )

    length = struct.unpack(
        "!I",
        header,
    )[0]

    if length <= 0:
        raise ValueError(
            "Length header phải "
            "lớn hơn 0."
        )

    return length


# =========================
# Socket Utility
# =========================

def recv_exact(
    conn,
    n: int,
) -> bytes:
    """
    Receive exactly n bytes
    from TCP connection.
    """

    if n <= 0:
        raise ValueError(
            "Số byte cần nhận "
            "phải lớn hơn 0."
        )

    chunks = []
    received = 0

    while received < n:

        chunk = conn.recv(
            n - received
        )

        if not chunk:
            raise ConnectionError(
                "Kết nối bị đóng trước "
                "khi nhận đủ dữ liệu."
            )

        chunks.append(chunk)

        received += len(chunk)

    return b"".join(chunks)
