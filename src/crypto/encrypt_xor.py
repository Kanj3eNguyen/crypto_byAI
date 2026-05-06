"""
Hàm tạo mẫu che giấu bằng XOR khóa lặp.
"""

from typing import Any, Dict, Tuple

from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor


def encrypt_repeating_xor(data: bytes, key_size: int = 128) -> Tuple[bytes, Dict[str, Any]]:
    """
    Biến đổi dữ liệu bằng XOR khóa lặp.

    Nhóm này cố ý yếu, dùng để mô phỏng các mẫu che giấu đơn giản.

    Args:
        data: Dữ liệu cần xử lý.
        key_size: Độ dài khóa tính theo bit và chia hết cho 8.

    Returns:
        Bộ giá trị gồm ciphertext và metadata.
    """
    if key_size <= 0 or key_size % 8 != 0:
        raise ValueError("XOR key_size must be a positive multiple of 8")

    key = get_random_bytes(key_size // 8)
    key_stream = (key * ((len(data) // len(key)) + 1))[:len(data)]
    ciphertext = strxor(data, key_stream)

    metadata = {
        'algorithm': 'XOR',
        'mode': 'REPEATING_KEY',
        'key_size': key_size,
        'key_hex': key.hex()
    }

    return ciphertext, metadata
