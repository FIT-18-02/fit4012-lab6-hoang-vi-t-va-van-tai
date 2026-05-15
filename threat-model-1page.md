# Threat Model - Lab 6 AES-CBC Socket

## Thông tin nhóm

- Thành viên 1: Nguyễn Hoàng Việt - MSSV: 1871020654
- Thành viên 2: Bùi Văn Tài - MSSV: 1871020515

---

## Assets

Các tài sản cần được bảo vệ trong hệ thống gồm:

- Plaintext trước khi mã hóa.
- AES key dùng để mã hóa và giải mã dữ liệu.
- IV (Initialization Vector) của AES-CBC.
- Ciphertext được truyền qua socket.
- File đầu vào (`sample_input.txt`).
- File đầu ra (`sample_output.txt`).
- Các file log trong thư mục `logs/`.
- Tính toàn vẹn và tính bí mật của dữ liệu truyền qua mạng.

---

## Attacker model

Đối tượng tấn công có thể:

- Nghe lén mạng LAN và bắt gói tin TCP.
- Đọc dữ liệu truyền trên key channel và data channel.
- Sửa đổi ciphertext trước khi Receiver giải mã.
- Replay lại packet cũ để gửi nhiều lần.
- Đọc file log nếu hệ thống lưu log không an toàn.
- Giả mạo Sender để gửi dữ liệu độc hại đến Receiver.

Kẻ tấn công không cần quyền quản trị hệ thống nhưng có khả năng truy cập mạng nội bộ hoặc môi trường chạy demo.

---

## Threats

### 1. Key disclosure

AES key và IV được gửi plaintext qua `KEY_PORT`, nên kẻ tấn công có thể bắt gói tin và lấy được key để giải mã toàn bộ dữ liệu.

### 2. Ciphertext tampering

Kẻ tấn công có thể sửa đổi ciphertext trong quá trình truyền làm Receiver giải mã sai hoặc gây lỗi dữ liệu.

### 3. Replay attack

Một packet ciphertext cũ có thể bị gửi lại nhiều lần vì hệ thống chưa kiểm tra timestamp hoặc nonce.

### 4. Log leakage

Nếu key, IV hoặc plaintext được ghi vào log, dữ liệu nhạy cảm có thể bị lộ khi attacker đọc file log.

### 5. No authentication

Receiver chưa xác thực danh tính Sender nên attacker có thể giả mạo Sender để gửi dữ liệu không hợp lệ.

---

## Mitigations

### 1. Sử dụng cơ chế trao đổi khóa an toàn

Trong hệ thống thực tế không nên gửi AES key plaintext. Có thể dùng TLS hoặc Diffie-Hellman để trao đổi khóa an toàn.

### 2. Sử dụng AES-GCM

AES-GCM cung cấp cả mã hóa và xác thực dữ liệu, giúp phát hiện ciphertext bị sửa đổi.

### 3. Không lưu key thật vào log

Chỉ ghi log thông tin cần thiết phục vụ debug, tránh lưu AES key hoặc plaintext thật.

### 4. Thêm nonce hoặc timestamp

Mỗi gói tin nên có nonce hoặc timestamp để giảm nguy cơ replay attack.

### 5. Xác thực Sender

Receiver nên kiểm tra danh tính Sender bằng token, certificate hoặc chữ ký số trước khi nhận dữ liệu.

---

## Residual risks

Dù đã có một số biện pháp giảm thiểu, hệ thống vẫn còn nhiều rủi ro:

- Key channel trong bài lab chỉ là mô phỏng và chưa an toàn.
- Chưa sử dụng TLS để bảo vệ dữ liệu truyền qua mạng.
- Hệ thống chưa có cơ chế chống replay hoàn chỉnh.
- Chưa có xác thực mạnh giữa Sender và Receiver.
- AES-CBC không tự bảo vệ tính toàn vẹn dữ liệu nếu không kết hợp cơ chế xác thực riêng.

Vì vậy hệ thống này chỉ phù hợp cho mục đích học tập và demo nội bộ, không phù hợp triển khai trong môi trường thực tế.
