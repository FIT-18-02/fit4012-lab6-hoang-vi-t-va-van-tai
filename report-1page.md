# Report 1 page - Lab 6 AES-CBC Socket

## Thông tin nhóm

- Thành viên 1: Nguyễn Hoàng Việt - MSSV: 1871020654
- Thành viên 2: Bùi Văn Tài - MSSV: 1871020515

---

## Mục tiêu

Mục tiêu của bài lab là xây dựng hệ thống gửi và nhận dữ liệu mã hóa bằng AES-CBC thông qua TCP socket. Hệ thống được chia thành hai kênh riêng biệt gồm key channel dùng để gửi AES key và IV, và data channel dùng để gửi ciphertext. Ngoài việc triển khai sender và receiver, nhóm còn thực hiện kiểm thử nhiều tình huống như truyền dữ liệu đúng, sai key, sửa ciphertext và replay dữ liệu. Bài lab giúp hiểu rõ quy trình truyền dữ liệu an toàn cơ bản cũng như nhận diện các điểm yếu bảo mật khi gửi key plaintext.

---

## Phân công thực hiện

### Nguyễn Hoàng Việt
- Xây dựng receiver.py
- Xử lý nhận dữ liệu từ socket
- Giải mã AES-CBC
- Ghi dữ liệu ra file output

### Bùi Văn Tài
- Xây dựng sender.py
- Mã hóa AES-CBC
- Tạo key và IV
- Gửi key channel và data channel

### Phần làm chung
- Viết test với pytest
- Tạo log minh chứng
- Viết README.md
- Viết threat-model-1page.md
- Kiểm thử sender-receiver local

---

## Cách làm

Hệ thống sử dụng thuật toán AES-CBC để mã hóa dữ liệu. Sender đọc plaintext từ file, biến môi trường hoặc bàn phím, sau đó thực hiện PKCS#7 padding trước khi mã hóa. Một AES key và IV được tạo ngẫu nhiên bằng thư viện pycryptodome.

Sau khi mã hóa, Sender tạo hai packet:
- Key packet gồm độ dài key, AES key và IV.
- Data packet gồm độ dài ciphertext và ciphertext.

Receiver mở hai socket:
- KEY_PORT để nhận key và IV.
- DATA_PORT để nhận ciphertext.

Sau khi nhận đủ dữ liệu, Receiver giải mã ciphertext để thu lại plaintext ban đầu và ghi ra file output. Hệ thống sử dụng length header 4 bytes để đảm bảo đọc đúng kích thước dữ liệu truyền qua TCP socket.

---

## Kết quả

Hệ thống sender và receiver hoạt động thành công trong môi trường local. Dữ liệu plaintext được mã hóa và truyền qua socket, sau đó receiver giải mã đúng nội dung ban đầu.

Nhóm đã tạo log minh chứng trong thư mục `logs/` bao gồm:
- sender_success.log
- receiver_success.log

Các test quan trọng đã thực hiện:
- Test AES padding
- Test encrypt/decrypt AES-CBC
- Test key channel
- Test data channel
- Test wrong key
- Test tamper ciphertext
- Test sender-receiver local

Tất cả test đều chạy thành công bằng pytest.

---

## Kết luận

Qua bài lab, nhóm hiểu rõ cách hoạt động của AES-CBC và quy trình truyền dữ liệu qua TCP socket. Việc tách key channel và data channel giúp mô phỏng quy trình truyền khóa và dữ liệu trong hệ thống mạng.

Ngoài kiến thức kỹ thuật, bài lab cũng cho thấy rằng việc sử dụng mã hóa chưa đủ để đảm bảo an toàn. Nếu AES key được gửi plaintext hoặc hệ thống không có xác thực và chống replay, attacker vẫn có thể đánh cắp hoặc sửa đổi dữ liệu. Vì vậy trong hệ thống thực tế cần sử dụng TLS, xác thực hai chiều và các cơ chế bảo vệ toàn vẹn dữ liệu như AES-GCM.
