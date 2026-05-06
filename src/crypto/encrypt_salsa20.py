"""
Hàm tạo mẫu mã hóa Salsa20.
"""

from typing import Tuple, Dict, Any
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

from src.crypto.footer import append_metadata_footer


def encrypt_salsa20(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Mã hóa dữ liệu bằng Salsa20.

    Args:
        data: Dữ liệu cần mã hóa.
        key_size: Độ dài khóa tính theo bit, Salsa20 dùng 256 bit.

    Returns:
        Bộ giá trị gồm ciphertext và metadata.
    """
    if key_size != 256:
        raise ValueError("Salsa20 requires 256-bit key")
    
    key = get_random_bytes(32)  # Khóa 256 bit.
    nonce = get_random_bytes(8)  # Nonce 64 bit cho Salsa20.
    
    cipher = Salsa20.new(key=key, nonce=nonce)
    ciphertext = append_metadata_footer(cipher.encrypt(data), nonce, layout="padded_suffix_length")
    
    metadata = {
        'algorithm': 'Salsa20',
        'mode': '',
        'key_size': key_size,
        'nonce_hex': nonce.hex(),
        'key_hex': key.hex()
    }
    
    return ciphertext, metadata
