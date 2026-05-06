"""
Hàm tạo mẫu mã hóa lai theo kiểu ransomware.
"""

from functools import lru_cache
from typing import Tuple, Dict, Any
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Salsa20
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from src.crypto.footer import append_metadata_footer


@lru_cache(maxsize=1)
def _embedded_public_key():
    """Trả về RSA public key được cache, mô phỏng khóa nhúng trong ransomware."""
    return RSA.generate(2048).publickey()


def warm_hybrid_rsa_key() -> None:
    """Khởi động cache RSA trước khi sinh mẫu song song."""
    _embedded_public_key()


def encrypt_hybrid_aes_rsa(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    """
    Mã hóa dữ liệu bằng cơ chế lai AES + RSA.

    AES mã hóa nội dung tệp, còn RSA mã hóa khóa AES.

    Args:
        data: Dữ liệu cần mã hóa.

    Returns:
        Bộ giá trị gồm hybrid_ciphertext và metadata.
    """
    public_key = _embedded_public_key()
    
    # Mã hóa nội dung tệp bằng AES.
    aes_key = get_random_bytes(32)  # Khóa AES 256 bit.
    iv = get_random_bytes(AES.block_size)
    
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    file_ciphertext = cipher_aes.encrypt(pad(data, AES.block_size))
    
    # Mã hóa khóa AES bằng RSA.
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Cấu trúc: [file ma hoa AES][IV:16][khoa AES boc RSA][footer_length:4].
    footer_body = iv + encrypted_aes_key
    hybrid_ciphertext = append_metadata_footer(file_ciphertext, footer_body)
    
    metadata = {
        'algorithm': 'Hybrid_AES_RSA',
        'mode': 'CBC+OAEP',
        'key_size': 256,
        'rsa_key_size': 2048,
        'aes_key_hex': aes_key.hex(),
        'iv_hex': iv.hex(),
        'rsa_public_key_hex': public_key.export_key().hex()
    }
    
    return hybrid_ciphertext, metadata


def encrypt_hybrid_chacha20_rsa(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    """
    Mã hóa dữ liệu bằng cơ chế lai ChaCha20 + RSA.

    ChaCha20 mã hóa nội dung tệp, còn RSA mã hóa khóa đối xứng của từng tệp.

    Args:
        data: Dữ liệu cần mã hóa.

    Returns:
        Bộ giá trị gồm hybrid_ciphertext và metadata.
    """
    public_key = _embedded_public_key()

    chacha_key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher_chacha = ChaCha20.new(key=chacha_key, nonce=nonce)
    file_ciphertext = cipher_chacha.encrypt(data)

    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_chacha_key = cipher_rsa.encrypt(chacha_key)

    footer_body = nonce + encrypted_chacha_key
    hybrid_ciphertext = append_metadata_footer(file_ciphertext, footer_body, layout="prefix_length")

    metadata = {
        'algorithm': 'Hybrid_ChaCha20_RSA',
        'mode': 'STREAM+OAEP',
        'key_size': 256,
        'rsa_key_size': 2048,
        'chacha20_key_hex': chacha_key.hex(),
        'nonce_hex': nonce.hex(),
        'rsa_public_key_hex': public_key.export_key().hex()
    }

    return hybrid_ciphertext, metadata


def encrypt_hybrid_salsa20_rsa(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    """
    Mã hóa dữ liệu bằng cơ chế lai Salsa20 + RSA.

    Salsa20 mã hóa nội dung tệp, còn RSA mã hóa khóa đối xứng của từng tệp.

    Args:
        data: Dữ liệu cần mã hóa.

    Returns:
        Bộ giá trị gồm hybrid_ciphertext và metadata.
    """
    public_key = _embedded_public_key()

    salsa_key = get_random_bytes(32)
    nonce = get_random_bytes(8)
    cipher_salsa = Salsa20.new(key=salsa_key, nonce=nonce)
    file_ciphertext = cipher_salsa.encrypt(data)

    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_salsa_key = cipher_rsa.encrypt(salsa_key)

    footer_body = nonce + encrypted_salsa_key
    hybrid_ciphertext = append_metadata_footer(
        file_ciphertext,
        footer_body,
        layout="padded_suffix_length",
    )

    metadata = {
        'algorithm': 'Hybrid_Salsa20_RSA',
        'mode': 'STREAM+OAEP',
        'key_size': 256,
        'rsa_key_size': 2048,
        'salsa20_key_hex': salsa_key.hex(),
        'nonce_hex': nonce.hex(),
        'rsa_public_key_hex': public_key.export_key().hex()
    }

    return hybrid_ciphertext, metadata
