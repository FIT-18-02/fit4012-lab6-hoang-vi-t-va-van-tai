# Peer Review Response - Lab 6 AES Socket

## Team Members

- Nguyễn Hoàng Việt - MSSV: 1871020654
- Bùi Văn Tài - MSSV: 1871020515

---

# Peer Review Summary

Nhóm nhận được các góp ý sau:

- Cần kiểm tra PKCS#7 padding đầy đủ hơn.
- Cần thêm test cho tampered ciphertext.
- Cần bổ sung kiểm thử wrong key và wrong IV.
- README cần mô tả rõ protocol của key channel và data channel.
- Cần có integration test sender-receiver local.

---

# Changes Implemented

Nhóm đã cập nhật hệ thống như sau:

## 1. PKCS#7 Padding Validation

Hàm `unpad()` đã được cập nhật để:

- Kiểm tra dữ liệu rỗng.
- Kiểm tra độ dài padding hợp lệ.
- Kiểm tra toàn bộ byte padding đúng chuẩn PKCS#7.

---

## 2. Tamper Ciphertext Tests

Đã bổ sung:

- `test_tampered_ciphertext_should_fail_or_change_plaintext`
- `test_tampered_middle_block`
- `test_tampered_first_byte`

Các test này kiểm tra khả năng phát hiện dữ liệu ciphertext bị sửa đổi.

---

## 3. Wrong Key / Wrong IV Tests

Đã bổ sung các test:

- `test_wrong_key_should_not_recover_original_plaintext`
- `test_wrong_key_multiple_attempts`
- `test_wrong_iv_should_not_recover_plaintext`

---

## 4. Protocol Documentation

README.md đã được cập nhật để mô tả rõ:

### Key Channel

```text
[key_length][key][iv]
