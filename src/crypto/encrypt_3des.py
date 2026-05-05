"""
3DES (Triple DES) encryption utilities
"""

from typing import Tuple, Dict, Any
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from src.crypto.footer import append_metadata_footer


def encrypt_3des_cbc(data: bytes, key_size: int = 192) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using 3DES-CBC
    
    Args:
        data: Data to encrypt
        key_size: Key size in bits (must be 192 for 3DES)
    
    Returns:
        Tuple of (ciphertext, metadata)
    """
    if key_size != 192:
        raise ValueError("3DES requires 192-bit key")
    
    key = DES3.adjust_key_parity(get_random_bytes(24))  # 192-bit key
    iv = get_random_bytes(DES3.block_size)
    
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = append_metadata_footer(
        cipher.encrypt(pad(data, DES3.block_size)),
        iv,
        layout="prefix_length",
    )
    
    metadata = {
        'algorithm': '3DES',
        'mode': 'CBC',
        'key_size': key_size,
        'iv_hex': iv.hex(),
        'key_hex': key.hex()
    }
    
    return ciphertext, metadata
