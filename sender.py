import os
import socket
from pathlib import Path

from aes_socket_utils import (
    build_data_packet,
    build_key_packet,
    encrypt_aes_cbc,
)

# =========================
# Environment configuration
# =========================

SERVER_IP = os.getenv("SERVER_IP", "127.0.0.1")
DATA_PORT = int(os.getenv("DATA_PORT", "6000"))
KEY_PORT = int(os.getenv("KEY_PORT", "6001"))

# AES key size: 16 = AES-128, 32 = AES-256
AES_KEY_SIZE = int(os.getenv("AES_KEY_SIZE", "16"))

# Message sources
MESSAGE_ENV = os.getenv("MESSAGE")
INPUT_FILE = os.getenv("INPUT_FILE", "")

# Log file
LOG_FILE = os.getenv("SENDER_LOG_FILE", "")

# Socket timeout
TIMEOUT = float(os.getenv("SOCKET_TIMEOUT", "10"))


def get_plaintext() -> bytes:
    """
    Read plaintext from:
    1. INPUT_FILE
    2. MESSAGE environment variable
    3. Keyboard input
    """

    # Read from file
    if INPUT_FILE:
        file_path = Path(INPUT_FILE)

        if not file_path.exists():
            raise FileNotFoundError(
                f"Không tìm thấy file đầu vào: {INPUT_FILE}"
            )

        print(f"[+] Đọc dữ liệu từ file: {INPUT_FILE}")
        return file_path.read_bytes()

    # Read from MESSAGE env
    if MESSAGE_ENV is not None:
        print("[+] Đọc dữ liệu từ biến môi trường MESSAGE")
        return MESSAGE_ENV.encode("utf-8")

    # Manual input
    print("[+] Nhập dữ liệu từ bàn phím")
    return input("Nhập bản tin: ").encode("utf-8")


def send_packet(host: str, port: int, packet: bytes) -> None:
    """
    Open TCP connection and send packet.
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)

        print(f"[+] Đang kết nối tới {host}:{port} ...")

        sock.connect((host, port))

        print(f"[+] Đã kết nối tới {host}:{port}")

        sock.sendall(packet)

        print(f"[+] Đã gửi {len(packet)} bytes")


def save_log(lines: list[str]) -> None:
    """
    Save sender log if LOG_FILE is configured.
    """

    if not LOG_FILE:
        return

    log_path = Path(LOG_FILE)

    # Create logs directory if not exists
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Write log
    log_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(f"[+] Đã lưu log: {LOG_FILE}")


def main() -> None:
    print("=" * 60)
    print("FIT4012 - AES-CBC Socket Sender")
    print("=" * 60)

    try:
        # Read plaintext
        plaintext = get_plaintext()

        print(f"[+] Plaintext length: {len(plaintext)} bytes")

        # Encrypt plaintext
        key, iv, ciphertext = encrypt_aes_cbc(
            plaintext,
            key_size=AES_KEY_SIZE,
        )

        print("[+] Đã mã hóa dữ liệu bằng AES-CBC")

        # Build packets
        key_packet = build_key_packet(key, iv)
        data_packet = build_data_packet(ciphertext)

        # Send key channel
        print("\n[KEY CHANNEL]")
        send_packet(SERVER_IP, KEY_PORT, key_packet)

        # Send data channel
        print("\n[DATA CHANNEL]")
        send_packet(SERVER_IP, DATA_PORT, data_packet)

        # Log information
        lines = [
            "=" * 60,
            "FIT4012 - AES-CBC Socket Sender Log",
            "=" * 60,
            "[+] Đã tạo AES key và IV.",
            "[+] Đã gửi key/IV qua kênh khóa.",
            "[+] Đã gửi ciphertext qua kênh dữ liệu.",
            "",
            f"Server IP: {SERVER_IP}",
            f"Key Port: {KEY_PORT}",
            f"Data Port: {DATA_PORT}",
            "",
            f"AES Key Size: {len(key)} bytes",
            f"Key: {key.hex()}",
            f"IV: {iv.hex()}",
            "",
            f"Plaintext Length: {len(plaintext)} bytes",
            f"Ciphertext Length: {len(ciphertext)} bytes",
            "",
            f"Ciphertext: {ciphertext.hex()}",
        ]

        # Print log
        print("\n" + "=" * 60)
        print("SEND SUCCESS")
        print("=" * 60)

        for line in lines:
            print(line)

        # Save log
        save_log(lines)

        print("\n[+] Sender hoàn thành thành công.")

    except FileNotFoundError as error:
        print(f"[ERROR] {error}")

    except socket.timeout:
        print("[ERROR] Socket timeout.")

    except ConnectionRefusedError:
        print(
            "[ERROR] Receiver chưa chạy hoặc sai IP/PORT."
        )

    except Exception as error:
        print(f"[ERROR] {type(error).__name__}: {error}")


if __name__ == "__main__":
    main()
