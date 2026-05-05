"""
Blowfish encryption utilities.
"""

from typing import Any, Dict, Tuple

from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from src.crypto.footer import append_metadata_footer


def encrypt_blowfish_cbc(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using Blowfish-CBC.

    Args:
        data: Data to encrypt
        key_size: Key size in bits (32 to 448, multiple of 8)

    Returns:
        Tuple of (ciphertext, metadata)
    """
    if key_size < 32 or key_size > 448 or key_size % 8 != 0:
        raise ValueError("Blowfish key_size must be 32..448 bits and divisible by 8")

    key = get_random_bytes(key_size // 8)
    iv = get_random_bytes(Blowfish.block_size)

    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    ciphertext = append_metadata_footer(
        cipher.encrypt(pad(data, Blowfish.block_size)),
        iv,
        layout="padded_suffix_length",
    )

    metadata = {
        'algorithm': 'Blowfish',
        'mode': 'CBC',
        'key_size': key_size,
        'iv_hex': iv.hex(),
        'key_hex': key.hex()
    }

    return ciphertext, metadata
