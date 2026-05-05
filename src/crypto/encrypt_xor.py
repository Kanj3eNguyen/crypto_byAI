"""
Repeating-key XOR encryption utilities.
"""

from typing import Any, Dict, Tuple

from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor


def encrypt_repeating_xor(data: bytes, key_size: int = 128) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using repeating-key XOR.

    This is intentionally weak and is included to model simple ransomware-like
    obfuscation seen in older or low-effort samples.

    Args:
        data: Data to encrypt
        key_size: Key size in bits (multiple of 8)

    Returns:
        Tuple of (ciphertext, metadata)
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
