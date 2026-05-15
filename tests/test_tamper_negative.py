import pytest

from aes_socket_utils import (
    decrypt_aes_cbc,
    encrypt_aes_cbc,
)

# =========================
# Ciphertext Tampering Tests
# =========================

def test_tampered_ciphertext_should_fail_or_change_plaintext():
    """
    Modify ciphertext and verify that:

    - Decryption fails due to invalid padding
      OR
    - Recovered plaintext is corrupted
    """

    plain = (
        b"Thong diep dung "
        b"de test tamper"
    )

    key = b"1" * 16
    iv = b"2" * 16

    # Encrypt plaintext
    _, _, cipher_bytes = encrypt_aes_cbc(
        plain,
        key=key,
        iv=iv,
    )

    # Tamper ciphertext
    tampered = bytearray(cipher_bytes)

    tampered[-1] ^= 0x01

    try:

        # Attempt decrypt
        recovered = decrypt_aes_cbc(
            key,
            iv,
            bytes(tampered),
        )

        # If decrypt succeeds,
        # plaintext must be corrupted
        assert recovered != plain

    except ValueError:

        # Expected behavior:
        # invalid PKCS#7 padding
        assert True


def test_tampered_middle_block():
    """
    Modify middle ciphertext byte.
    """

    plain = (
        b"FIT4012 AES CBC "
        b"tamper detection test"
    )

    key = b"1" * 16
    iv = b"2" * 16

    _, _, cipher_bytes = encrypt_aes_cbc(
        plain,
        key=key,
        iv=iv,
    )

    tampered = bytearray(cipher_bytes)

    # Modify middle byte
    middle_index = len(tampered) // 2

    tampered[middle_index] ^= 0xAA

    try:

        recovered = decrypt_aes_cbc(
            key,
            iv,
            bytes(tampered),
        )

        assert recovered != plain

    except ValueError:
        assert True


def test_tampered_first_byte():
    """
    Modify first ciphertext byte.
    """

    plain = b"Attack at dawn"

    key = b"1" * 16
    iv = b"2" * 16

    _, _, cipher_bytes = encrypt_aes_cbc(
        plain,
        key=key,
        iv=iv,
    )

    tampered = bytearray(cipher_bytes)

    tampered[0] ^= 0xFF

    try:

        recovered = decrypt_aes_cbc(
            key,
            iv,
            bytes(tampered),
        )

        assert recovered != plain

    except ValueError:
        assert True


def test_wrong_iv_should_fail_or_corrupt():
    """
    Decrypt with wrong IV.
    """

    plain = b"Sensitive AES message"

    key = b"1" * 16
    iv = b"2" * 16

    _, _, cipher_bytes = encrypt_aes_cbc(
        plain,
        key=key,
        iv=iv,
    )

    wrong_iv = b"9" * 16

    try:

        recovered = decrypt_aes_cbc(
            key,
            wrong_iv,
            cipher_bytes,
        )

        assert recovered != plain

    except ValueError:
        assert True
