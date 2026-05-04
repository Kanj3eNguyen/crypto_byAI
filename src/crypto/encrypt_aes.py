"""
AES encryption utilities
"""

import os
from typing import Tuple, Dict, Any
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def encrypt_aes_cbc(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using AES-CBC
    
    Args:
        data: Data to encrypt
        key_size: Key size in bits (128, 192, or 256)
    
    Returns:
        Tuple of (ciphertext, metadata)
    """
    key = get_random_bytes(key_size // 8)
    iv = get_random_bytes(AES.block_size)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    
    metadata = {
        'algorithm': 'AES',
        'mode': 'CBC',
        'key_size': key_size,
        'iv_hex': iv.hex(),
        'key_hex': key.hex()
    }
    
    return ciphertext, metadata


def encrypt_aes_ctr(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using AES-CTR
    
    Args:
        data: Data to encrypt
        key_size: Key size in bits (128, 192, or 256)
    
    Returns:
        Tuple of (ciphertext, metadata)
    """
    key = get_random_bytes(key_size // 8)
    nonce = get_random_bytes(8)
    
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(data)
    
    metadata = {
        'algorithm': 'AES',
        'mode': 'CTR',
        'key_size': key_size,
        'nonce_hex': nonce.hex(),
        'key_hex': key.hex()
    }
    
    return ciphertext, metadata


def encrypt_aes_gcm(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using AES-GCM
    
    Args:
        data: Data to encrypt
        key_size: Key size in bits (128, 192, or 256)
    
    Returns:
        Tuple of (ciphertext, metadata)
    """
    key = get_random_bytes(key_size // 8)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext = cipher.encrypt(data)
    tag = cipher.digest()
    
    metadata = {
        'algorithm': 'AES',
        'mode': 'GCM',
        'key_size': key_size,
        'nonce_hex': cipher.nonce.hex(),
        'tag_hex': tag.hex(),
        'key_hex': key.hex()
    }
    
    return ciphertext, metadata
