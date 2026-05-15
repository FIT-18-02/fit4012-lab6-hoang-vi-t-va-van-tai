import os
import socket
from pathlib import Path

from aes_socket_utils import (
    LENGTH_HEADER_SIZE,
    decrypt_aes_cbc,
    parse_key_packet,
    parse_length_header,
    recv_exact,
)

# =========================
# Environment configuration
# =========================

HOST = os.getenv("RECEIVER_HOST", "0.0.0.0")

DATA_PORT = int(os.getenv("DATA_PORT", "6000"))
KEY_PORT = int(os.getenv("KEY_PORT", "6001"))

TIMEOUT = float(os.getenv("SOCKET_TIMEOUT", "10"))

OUTPUT_FILE = os.getenv("OUTPUT_FILE", "")
LOG_FILE = os.getenv("RECEIVER_LOG_FILE", "")


def receive_key_packet() -> bytes:
    """
    Listen on KEY_PORT and receive:
    [key_length][key][iv]
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        server.settimeout(TIMEOUT)

        server.bind((HOST, KEY_PORT))
        server.listen(1)

        print(
            f"[*] Receiver đang lắng nghe "
            f"kênh khóa tại {HOST}:{KEY_PORT}"
        )

        conn, addr = server.accept()

        print(f"[+] Key channel connected: {addr}")

        with conn:
            conn.settimeout(TIMEOUT)

            # Receive key length header
            key_len_header = recv_exact(conn, 4)

            key_len = int.from_bytes(
                key_len_header,
                "big",
            )

            print(
                f"[+] AES key length: "
                f"{key_len} bytes"
            )

            # Receive key + IV
            rest = recv_exact(
                conn,
                key_len + 16,
            )

            print("[+] Đã nhận AES key và IV")

            return key_len_header + rest


def receive_data_packet() -> bytes:
    """
    Listen on DATA_PORT and receive:
    [ciphertext_length][ciphertext]
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        server.settimeout(TIMEOUT)

        server.bind((HOST, DATA_PORT))
        server.listen(1)

        print(
            f"[*] Receiver đang lắng nghe "
            f"kênh dữ liệu tại {HOST}:{DATA_PORT}"
        )

        conn, addr = server.accept()

        print(f"[+] Data channel connected: {addr}")

        with conn:
            conn.settimeout(TIMEOUT)

            # Receive ciphertext length
            length_header = recv_exact(
                conn,
                LENGTH_HEADER_SIZE,
            )

            length = parse_length_header(
                length_header
            )

            print(
                f"[+] Ciphertext length: "
                f"{length} bytes"
            )

            # Receive ciphertext
            ciphertext = recv_exact(
                conn,
                length,
            )

            print("[+] Đã nhận ciphertext")

            return length_header + ciphertext


def save_output(plaintext: bytes) -> None:
    """
    Save plaintext to output file.
    """

    if not OUTPUT_FILE:
        return

    output_path = Path(OUTPUT_FILE)

    output_path.write_bytes(plaintext)

    print(f"[+] Đã lưu output: {OUTPUT_FILE}")


def save_log(lines: list[str]) -> None:
    """
    Save receiver log.
    """

    if not LOG_FILE:
        return

    log_path = Path(LOG_FILE)

    log_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(f"[+] Đã lưu log: {LOG_FILE}")


def main() -> None:

    print("=" * 60)
    print("FIT4012 - AES-CBC Socket Receiver")
    print("=" * 60)

    lines = [
        "=" * 60,
        "FIT4012 - AES-CBC Socket Receiver Log",
        "=" * 60,
    ]

    try:

        # =========================
        # Receive key packet
        # =========================

        key_packet = receive_key_packet()

        key, iv = parse_key_packet(
            key_packet
        )

        lines.extend([
            "[+] Đã nhận AES key và IV.",
            f"AES Key Size: {len(key)} bytes",
            f"Key: {key.hex()}",
            f"IV: {iv.hex()}",
        ])

        # =========================
        # Receive data packet
        # =========================

        data_packet = receive_data_packet()

        length = parse_length_header(
            data_packet[:LENGTH_HEADER_SIZE]
        )

        ciphertext = data_packet[
            LENGTH_HEADER_SIZE:
        ]

        # Verify ciphertext length
        if len(ciphertext) != length:
            raise ValueError(
                "Ciphertext nhận được "
                "không khớp length header."
            )

        lines.extend([
            "[+] Đã nhận ciphertext.",
            f"Ciphertext Length: {length} bytes",
            f"Ciphertext: {ciphertext.hex()}",
        ])

        # =========================
        # Decrypt ciphertext
        # =========================

        plaintext = decrypt_aes_cbc(
            key,
            iv,
            ciphertext,
        )

        print("[+] Đã giải mã thành công")

        # Decode plaintext
        message = plaintext.decode(
            "utf-8",
            errors="replace",
        )

        print(f"[+] Bản tin gốc: {message}")

        lines.extend([
            "[+] Đã giải mã thành công.",
            f"Plaintext Length: {len(plaintext)} bytes",
            f"Bản tin gốc: {message}",
        ])

        # =========================
        # Save plaintext to file
        # =========================

        save_output(plaintext)

        # =========================
        # Save logs
        # =========================

        save_log(lines)

        print("\n" + "=" * 60)
        print("RECEIVE SUCCESS")
        print("=" * 60)

    except socket.timeout:
        print("[ERROR] Socket timeout.")

    except ConnectionRefusedError:
        print(
            "[ERROR] Không thể kết nối "
            "tới sender."
        )

    except ValueError as error:
        print(f"[ERROR] ValueError: {error}")

    except FileNotFoundError as error:
        print(f"[ERROR] File error: {error}")

    except Exception as error:
        print(
            f"[ERROR] {type(error).__name__}: "
            f"{error}"
        )


if __name__ == "__main__":
    main()
