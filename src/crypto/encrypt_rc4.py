"""
RC4 encryption utilities (stream cipher)
"""

from typing import Tuple, Dict, Any
from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes


def encrypt_rc4(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using RC4 (simulated via ARC2)
    
    Note: PyCryptodome doesn't include RC4, so we use ARC2 as a similar stream cipher
    
    Args:
        data: Data to encrypt
        key_size: Key size in bits (128 or 256)
    
    Returns:
        Tuple of (ciphertext, metadata)
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
