# FIT4012 - Lab 6 - Hệ thống gửi và nhận dữ liệu mã hóa AES-CBC qua Socket

Repo starter kit này dùng cho **Lab 6**: gửi và nhận dữ liệu mã hóa bằng **AES-CBC** qua **TCP socket**.

Lab này kế thừa ý tưởng từ Lab 3 DES Socket, nhưng nâng cấp theo 2 hướng:

1. Chuyển từ **DES-CBC** sang **AES-CBC**.
2. Tách thành **2 kênh TCP**:
   - `KEY_PORT`: kênh giả lập trao đổi AES key và IV.
   - `DATA_PORT`: kênh gửi ciphertext.

> Lưu ý quan trọng: kênh khóa trong bài này chỉ là mô phỏng học tập. Key và IV vẫn được gửi plaintext, vì vậy thiết kế này không an toàn để dùng trong hệ thống thật.

---

# Team members

- Thành viên 1: Nguyễn Hoàng Việt - MSSV: 1871020654
- Thành viên 2: Bùi Văn Tài - MSSV: 1871020515

---

# Task division

- Thành viên 1 phụ trách chính:
  - Xây dựng receiver
  - Giải mã AES-CBC
  - Xử lý dữ liệu nhận và ghi output

- Thành viên 2 phụ trách chính:
  - Xây dựng sender
  - Mã hóa AES-CBC
  - Gửi key/IV và ciphertext qua socket

- Phần làm chung:
  - Viết test
  - Viết log minh chứng
  - Hoàn thiện report và threat model
  - Kiểm thử sender-receiver local

---

# Demo roles

- Demo Sender / kênh khóa / log gửi:
  - Bùi Văn Tài

- Demo Receiver / kênh dữ liệu / giải mã:
  - Nguyễn Hoàng Việt

- Cả hai cùng trả lời threat model và ethics:
  - Nguyễn Hoàng Việt
  - Bùi Văn Tài

---

# Mục tiêu học tập

Sau bài lab này, sinh viên có thể:

- Mô tả được luồng Sender/Receiver qua TCP socket.
- Phân biệt được kênh khóa và kênh dữ liệu.
- Cài đặt được AES-CBC với key, IV và PKCS#7 padding.
- Thiết kế được header độ dài cho dữ liệu truyền qua socket.
- Viết test cho các tình huống đúng và sai.
- Nhận diện được điểm yếu của việc gửi key/IV plaintext.

---

# Cấu trúc repo

```text
.
├── aes_socket_utils.py
├── sender.py
├── receiver.py
├── requirements.txt
├── sample_input.txt
├── sample_output.txt
├── report-1page.md
├── threat-model-1page.md
├── peer-review-response.md
├── logs/
├── tests/
└── .github/workflows/ci.yml
Protocol
1. Key channel

Sender gửi AES key và IV qua KEY_PORT.

[key_length: 4 bytes][key: 16 hoặc 32 bytes][iv: 16 bytes]
2. Data channel

Sender gửi ciphertext qua DATA_PORT.

[ciphertext_length: 4 bytes][ciphertext: N bytes]
Cài đặt môi trường
Linux / macOS
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Cài đặt thư viện

Dự án sử dụng thư viện:

pycryptodome
pytest

Cài đặt nhanh:

pip install -r requirements.txt
Chạy demo local
Terminal 1 - Receiver
RECEIVER_HOST=127.0.0.1 DATA_PORT=6000 KEY_PORT=6001 python receiver.py
Terminal 2 - Sender
SERVER_IP=127.0.0.1 DATA_PORT=6000 KEY_PORT=6001 MESSAGE="Xin chao FIT4012 - Lab 6 AES Socket" python sender.py
Chạy có log minh chứng
Terminal 1
RECEIVER_HOST=127.0.0.1 \
DATA_PORT=6000 \
KEY_PORT=6001 \
RECEIVER_LOG_FILE=logs/receiver_success.log \
OUTPUT_FILE=sample_output.txt \
python receiver.py
Terminal 2
SERVER_IP=127.0.0.1 \
DATA_PORT=6000 \
KEY_PORT=6001 \
MESSAGE="Xin chao FIT4012 - Lab 6 AES Socket" \
SENDER_LOG_FILE=logs/sender_success.log \
python sender.py
Gửi dữ liệu từ file
Terminal 1
RECEIVER_HOST=127.0.0.1 DATA_PORT=6000 KEY_PORT=6001 OUTPUT_FILE=sample_output.txt python receiver.py
Terminal 2
SERVER_IP=127.0.0.1 DATA_PORT=6000 KEY_PORT=6001 INPUT_FILE=sample_input.txt python sender.py
Chạy test
pytest -q
Các test chính

Dự án có các test sau:

Test AES padding
Test encrypt/decrypt AES-CBC
Test key channel
Test data channel
Test wrong key
Test tamper ciphertext
Test sender-receiver local
Deliverables bắt buộc
README.md
sender.py
receiver.py
aes_socket_utils.py
tests/
logs/
report-1page.md
threat-model-1page.md
sample_input.txt
sample_output.txt
Submission contract cho CI

CI sẽ kiểm tra:

Có đủ file bắt buộc.
Không còn import DES.
Có sử dụng AES.
Có ít nhất 6 test.
Có test padding.
Có test key channel.
Có test data channel.
Có test wrong key.
Có test tamper.
Có test local sender-receiver.
README có thông tin nhóm 2 người.
Các file báo cáo không còn TODO_STUDENT.
Có ít nhất 1 file log thật trong logs/.
Ethics & Safe use
Chỉ chạy demo trên máy cá nhân, VM hoặc mạng nội bộ phục vụ học tập.
Không quét cổng hoặc thử nghiệm trên hệ thống không được phép.
Không dùng dữ liệu cá nhân thật hoặc dữ liệu nhạy cảm để demo.
Không trình bày hệ thống này như một giải pháp an toàn sẵn sàng triển khai thực tế.
Nếu tham khảo code hoặc tài liệu, phải ghi nguồn rõ ràng.
Hạn chế của hệ thống

Hệ thống vẫn còn nhiều hạn chế bảo mật:

AES key và IV được gửi plaintext.
Chưa sử dụng TLS.
Chưa có xác thực Sender.
Chưa chống replay attack hoàn chỉnh.
AES-CBC chưa tự bảo vệ tính toàn vẹn dữ liệu.

Vì vậy hệ thống chỉ phù hợp cho mục đích học tập và demo nội bộ.

Bài học chính

Một hệ thống có mã hóa chưa chắc đã là một hệ thống an toàn.

AES-CBC giúp che nội dung plaintext, nhưng chưa tự động đảm bảo:

Xác thực
Toàn vẹn dữ liệu
Chống replay
Bảo vệ khóa mã hóa

Muốn xây dựng hệ thống an toàn thực tế cần kết hợp:

TLS
Xác thực hai bên
Secure key exchange
AEAD như AES-GCM
