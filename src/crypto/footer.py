"""
Hàm hỗ trợ tạo footer metadata kiểu ransomware.
"""

from Crypto.Random import get_random_bytes


def append_metadata_footer(
    ciphertext: bytes,
    footer_body: bytes,
    layout: str = "suffix_length",
) -> bytes:
    """Gắn metadata footer theo một trong các bố cục mô phỏng ransomware."""
    if not footer_body:
        return ciphertext

    footer_length = len(footer_body).to_bytes(4, byteorder='big')
    if layout == "suffix_length":
        return ciphertext + footer_body + footer_length
    if layout == "prefix_length":
        return ciphertext + footer_length + footer_body
    if layout == "padded_suffix_length":
        # Đệm tới biên hợp lý để footer vẫn nhận diện được mà byte cuối không
        # làm lộ trực tiếp kích thước metadata ban đầu.
        pad_len = 8 - (len(footer_body) % 8)
        if pad_len == 0:
            pad_len = 8
        padding = get_random_bytes(pad_len)
        padded_body = footer_body + padding
        return ciphertext + padded_body + len(padded_body).to_bytes(4, byteorder='big')

    raise ValueError(f"Unknown footer layout: {layout}")
