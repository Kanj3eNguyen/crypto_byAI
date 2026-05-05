"""
CAST5 encryption utilities.
"""

from typing import Any, Dict, Tuple

from Crypto.Cipher import CAST
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from src.crypto.footer import append_metadata_footer


def encrypt_cast5_cbc(data: bytes, key_size: int = 128) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using CAST5-CBC.

    Args:
        data: Data to encrypt
        key_size: Key size in bits (40 to 128, multiple of 8)

    Returns:
        Tuple of (ciphertext, metadata)
    """
    if key_size < 40 or key_size > 128 or key_size % 8 != 0:
        raise ValueError("CAST5 key_size must be 40..128 bits and divisible by 8")

    key = get_random_bytes(key_size // 8)
    iv = get_random_bytes(CAST.block_size)

    cipher = CAST.new(key, CAST.MODE_CBC, iv)
    ciphertext = append_metadata_footer(
        cipher.encrypt(pad(data, CAST.block_size)),
        iv,
        layout="padded_suffix_length",
    )

    metadata = {
        'algorithm': 'CAST5',
        'mode': 'CBC',
        'key_size': key_size,
        'iv_hex': iv.hex(),
        'key_hex': key.hex()
    }

    return ciphertext, metadata
