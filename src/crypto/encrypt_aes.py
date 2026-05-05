"""
AES encryption utilities
"""

import os
from typing import Tuple, Dict, Any
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from src.crypto.footer import append_metadata_footer


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
    ciphertext = append_metadata_footer(cipher.encrypt(pad(data, AES.block_size)), iv)
    
    metadata = {
        'algorithm': 'AES',
        'mode': 'CBC',
        'key_size': key_size,
        'iv_hex': iv.hex(),
        'key_hex': key.hex()
    }
    
    return ciphertext, metadata


def encrypt_aes_ecb(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using AES-ECB.

    ECB is included only as a weak-pattern synthetic class because some malware
    samples use simple or incorrectly configured block-cipher modes.

    Args:
        data: Data to encrypt
        key_size: Key size in bits (128, 192, or 256)

    Returns:
        Tuple of (ciphertext, metadata)
    """
    key = get_random_bytes(key_size // 8)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    metadata = {
        'algorithm': 'AES',
        'mode': 'ECB',
        'key_size': key_size,
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
    ciphertext = append_metadata_footer(cipher.encrypt(data), nonce, layout="prefix_length")
    
    metadata = {
        'algorithm': 'AES',
        'mode': 'CTR',
        'key_size': key_size,
        'nonce_hex': nonce.hex(),
        'key_hex': key.hex()
    }
    
    return ciphertext, metadata


def encrypt_aes_cfb(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using AES-CFB.

    Args:
        data: Data to encrypt
        key_size: Key size in bits (128, 192, or 256)

    Returns:
        Tuple of (ciphertext, metadata)
    """
    key = get_random_bytes(key_size // 8)
    iv = get_random_bytes(AES.block_size)

    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    ciphertext = append_metadata_footer(cipher.encrypt(data), iv, layout="padded_suffix_length")

    metadata = {
        'algorithm': 'AES',
        'mode': 'CFB',
        'key_size': key_size,
        'iv_hex': iv.hex(),
        'key_hex': key.hex()
    }

    return ciphertext, metadata


def encrypt_aes_ofb(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using AES-OFB.

    Args:
        data: Data to encrypt
        key_size: Key size in bits (128, 192, or 256)

    Returns:
        Tuple of (ciphertext, metadata)
    """
    key = get_random_bytes(key_size // 8)
    iv = get_random_bytes(AES.block_size)

    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    ciphertext = append_metadata_footer(cipher.encrypt(data), iv, layout="prefix_length")

    metadata = {
        'algorithm': 'AES',
        'mode': 'OFB',
        'key_size': key_size,
        'iv_hex': iv.hex(),
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
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext = cipher.encrypt(data)
    tag = cipher.digest()
    ciphertext = append_metadata_footer(ciphertext, nonce + tag, layout="padded_suffix_length")
    
    metadata = {
        'algorithm': 'AES',
        'mode': 'GCM',
        'key_size': key_size,
        'nonce_hex': nonce.hex(),
        'tag_hex': tag.hex(),
        'key_hex': key.hex()
    }
    
    return ciphertext, metadata
