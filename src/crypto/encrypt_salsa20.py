"""
Salsa20 encryption utilities
"""

from typing import Tuple, Dict, Any
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes


def encrypt_salsa20(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using Salsa20
    
    Args:
        data: Data to encrypt
        key_size: Key size in bits (256 for Salsa20)
    
    Returns:
        Tuple of (ciphertext, metadata)
    """
    if key_size != 256:
        raise ValueError("Salsa20 requires 256-bit key")
    
    key = get_random_bytes(32)  # 256-bit key
    nonce = get_random_bytes(8)  # 64-bit nonce for Salsa20
    
    cipher = Salsa20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(data)
    
    metadata = {
        'algorithm': 'Salsa20',
        'mode': '',
        'key_size': key_size,
        'nonce_hex': nonce.hex(),
        'key_hex': key.hex()
    }
    
    return ciphertext, metadata
