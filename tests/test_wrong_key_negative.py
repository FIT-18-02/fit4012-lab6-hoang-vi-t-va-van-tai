from aes_socket_utils import (
    decrypt_aes_cbc,
    encrypt_aes_cbc,
)

# =========================
# Wrong Key Tests
# =========================

def test_wrong_key_should_not_recover_original_plaintext():
    """
    Decrypt ciphertext using wrong AES key.

    Expected:
    - Decryption fails with ValueError
      OR
    - Recovered plaintext is corrupted
    """

    plain = (
        b"Thong diep dung "
        b"de test wrong key"
    )

    key = b"1" * 16
    iv = b"2" * 16

    # Encrypt plaintext
    _, _, cipher_bytes = encrypt_aes_cbc(
        plain,
        key=key,
        iv=iv,
    )

    # Wrong AES key
    wrong_key = b"3" * 16

    try:

        recovered = decrypt_aes_cbc(
            wrong_key,
            iv,
            cipher_bytes,
        )

        # If decrypt succeeds,
        # plaintext must not match
        assert recovered != plain

    except ValueError:

        # Expected due to invalid padding
        assert True


def test_wrong_key_different_length():
    """
    Use wrong AES-256 key for AES-128 ciphertext.
    """

    plain = b"FIT4012 AES CBC test"

    key = b"1" * 16
    iv = b"2" * 16

    _, _, cipher_bytes = encrypt_aes_cbc(
        plain,
        key=key,
        iv=iv,
    )

    # AES-256 wrong key
    wrong_key = b"9" * 32

    try:

        recovered = decrypt_aes_cbc(
            wrong_key,
            iv,
            cipher_bytes,
        )

        assert recovered != plain

    except ValueError:
        assert True


def test_wrong_key_multiple_attempts():
    """
    Test multiple wrong keys.
    """

    plain = b"Secret AES message"

    key = b"1" * 16
    iv = b"2" * 16

    _, _, cipher_bytes = encrypt_aes_cbc(
        plain,
        key=key,
        iv=iv,
    )

    wrong_keys = [
        b"3" * 16,
        b"4" * 16,
        b"5" * 16,
    ]

    for wrong_key in wrong_keys:

        try:

            recovered = decrypt_aes_cbc(
                wrong_key,
                iv,
                cipher_bytes,
            )

            assert recovered != plain

        except ValueError:
            assert True


def test_wrong_iv_should_not_recover_plaintext():
    """
    Wrong IV should corrupt plaintext.
    """

    plain = b"Test wrong IV"

    key = b"1" * 16
    iv = b"2" * 16

    _, _, cipher_bytes = encrypt_aes_cbc(
        plain,
        key=key,
        iv=iv,
    )

    wrong_iv = b"8" * 16

    try:

        recovered = decrypt_aes_cbc(
            key,
            wrong_iv,
            cipher_bytes,
        )

        assert recovered != plain

    except ValueError:
        assert True
