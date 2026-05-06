"""
Hàm tạo mẫu mã hóa DES.
"""

from typing import Any, Dict, Tuple

from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from src.crypto.footer import append_metadata_footer


def encrypt_des_cbc(data: bytes, key_size: int = 56) -> Tuple[bytes, Dict[str, Any]]:
    """
    Mã hóa dữ liệu bằng DES-CBC.

    Args:
        data: Dữ liệu cần mã hóa.
        key_size: Độ dài khóa hiệu dụng tính theo bit, DES dùng 56 bit.

    Returns:
        Bộ giá trị gồm ciphertext và metadata.
    """
    if key_size != 56:
        raise ValueError("DES uses a 56-bit effective key")

    key = get_random_bytes(8)
    iv = get_random_bytes(DES.block_size)

    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = append_metadata_footer(cipher.encrypt(pad(data, DES.block_size)), iv)

    metadata = {
        'algorithm': 'DES',
        'mode': 'CBC',
        'key_size': key_size,
        'iv_hex': iv.hex(),
        'key_hex': key.hex()
    }

    return ciphertext, metadata
