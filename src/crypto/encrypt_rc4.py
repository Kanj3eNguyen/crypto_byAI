"""
Hàm tạo mẫu mã hóa RC4.
"""

from typing import Tuple, Dict, Any
from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes


def encrypt_rc4(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Mã hóa dữ liệu bằng RC4 thông qua ARC4 của PyCryptodome.

    Args:
        data: Dữ liệu cần mã hóa.
        key_size: Độ dài khóa tính theo bit, thường dùng 128 hoặc 256.

    Returns:
        Bộ giá trị gồm ciphertext và metadata.
    """
    key = get_random_bytes(key_size // 8)
    
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(data)
    
    metadata = {
        'algorithm': 'RC4',
        'mode': 'STREAM',
        'key_size': key_size,
        'key_hex': key.hex()
    }
    
    return ciphertext, metadata
