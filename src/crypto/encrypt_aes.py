"""
Hàm tạo mẫu mã hóa AES.
"""

from typing import Tuple, Dict, Any
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from src.crypto.footer import append_metadata_footer


def encrypt_aes_cbc(data: bytes, key_size: int = 256) -> Tuple[bytes, Dict[str, Any]]:
    """
    Mã hóa dữ liệu bằng AES-CBC.

    Args:
        data: Dữ liệu cần mã hóa.
        key_size: Độ dài khóa tính theo bit, gồm 128, 192 hoặc 256.

    Returns:
        Bộ giá trị gồm ciphertext và metadata.
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
    Mã hóa dữ liệu bằng AES-ECB.

    ECB được giữ lại để tạo mẫu mô phỏng các cấu hình block cipher yếu hoặc
    cấu hình sai.

    Args:
        data: Dữ liệu cần mã hóa.
        key_size: Độ dài khóa tính theo bit, gồm 128, 192 hoặc 256.

    Returns:
        Bộ giá trị gồm ciphertext và metadata.
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
    Mã hóa dữ liệu bằng AES-CTR.

    Args:
        data: Dữ liệu cần mã hóa.
        key_size: Độ dài khóa tính theo bit, gồm 128, 192 hoặc 256.

    Returns:
        Bộ giá trị gồm ciphertext và metadata.
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
    Mã hóa dữ liệu bằng AES-CFB.

    Args:
        data: Dữ liệu cần mã hóa.
        key_size: Độ dài khóa tính theo bit, gồm 128, 192 hoặc 256.

    Returns:
        Bộ giá trị gồm ciphertext và metadata.
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
    Mã hóa dữ liệu bằng AES-OFB.

    Args:
        data: Dữ liệu cần mã hóa.
        key_size: Độ dài khóa tính theo bit, gồm 128, 192 hoặc 256.

    Returns:
        Bộ giá trị gồm ciphertext và metadata.
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
    Mã hóa dữ liệu bằng AES-GCM.

    Args:
        data: Dữ liệu cần mã hóa.
        key_size: Độ dài khóa tính theo bit, gồm 128, 192 hoặc 256.

    Returns:
        Bộ giá trị gồm ciphertext và metadata.
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
