"""
RC2/ARC2 encryption utilities.
"""

from typing import Any, Dict, Tuple

from Crypto.Cipher import ARC2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from src.crypto.footer import append_metadata_footer


def encrypt_rc2_cbc(data: bytes, key_size: int = 128) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using RC2-CBC.

    Args:
        data: Data to encrypt
        key_size: Key size in bits (40 to 1024, multiple of 8)

    Returns:
        Tuple of (ciphertext, metadata)
    """
    if key_size < 40 or key_size > 1024 or key_size % 8 != 0:
        raise ValueError("RC2 key_size must be 40..1024 bits and divisible by 8")

    key = get_random_bytes(key_size // 8)
    iv = get_random_bytes(ARC2.block_size)

    cipher = ARC2.new(key, ARC2.MODE_CBC, iv, effective_keylen=key_size)
    ciphertext = append_metadata_footer(
        cipher.encrypt(pad(data, ARC2.block_size)),
        iv,
        layout="prefix_length",
    )

    metadata = {
        'algorithm': 'RC2',
        'mode': 'CBC',
        'key_size': key_size,
        'iv_hex': iv.hex(),
        'key_hex': key.hex()
    }

    return ciphertext, metadata
