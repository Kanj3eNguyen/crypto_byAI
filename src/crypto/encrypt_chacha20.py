"""
ChaCha20 encryption utilities
"""

from typing import Tuple, Dict, Any
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

from src.crypto.footer import append_metadata_footer


def encrypt_chacha20(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using ChaCha20
    
    Args:
        data: Data to encrypt
        key_size: Key size in bits (256 for ChaCha20)
    
    Returns:
        Tuple of (ciphertext, metadata)
    """
    if key_size != 256:
        raise ValueError("ChaCha20 requires 256-bit key")
    
    key = get_random_bytes(32)  # 256-bit key
    nonce = get_random_bytes(12)  # 96-bit nonce for ChaCha20-IETF
    
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = append_metadata_footer(cipher.encrypt(data), nonce, layout="prefix_length")
    
    metadata = {
        'algorithm': 'ChaCha20',
        'mode': '',
        'key_size': key_size,
        'nonce_hex': nonce.hex(),
        'key_hex': key.hex()
    }
    
    return ciphertext, metadata
