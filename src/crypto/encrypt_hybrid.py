"""
Hybrid encryption utilities (AES + RSA like ransomware)
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
    """Return a cached RSA public key, like an embedded ransomware public key."""
    return RSA.generate(2048).publickey()


def warm_hybrid_rsa_key() -> None:
    """Warm the cached RSA public key before parallel sample generation."""
    _embedded_public_key()


def encrypt_hybrid_aes_rsa(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using hybrid encryption (AES + RSA)
    Simulates ransomware pattern: AES encrypts file, RSA encrypts AES key
    
    Args:
        data: Data to encrypt
    
    Returns:
        Tuple of (hybrid_ciphertext, metadata)
    """
    public_key = _embedded_public_key()
    
    # Encrypt file with AES
    aes_key = get_random_bytes(32)  # 256-bit AES key
    iv = get_random_bytes(AES.block_size)
    
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    file_ciphertext = cipher_aes.encrypt(pad(data, AES.block_size))
    
    # Encrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Format: [AES_encrypted_file][IV:16][RSA_encrypted_key][footer_length:4]
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
    Encrypt data using hybrid ChaCha20 + RSA.

    Simulates ransomware pattern: ChaCha20 encrypts file content, RSA encrypts
    the per-file symmetric key.

    Args:
        data: Data to encrypt

    Returns:
        Tuple of (hybrid_ciphertext, metadata)
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
    Encrypt data using hybrid Salsa20 + RSA.

    Simulates ransomware pattern: Salsa20 encrypts file content, RSA encrypts
    the per-file symmetric key.

    Args:
        data: Data to encrypt

    Returns:
        Tuple of (hybrid_ciphertext, metadata)
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
