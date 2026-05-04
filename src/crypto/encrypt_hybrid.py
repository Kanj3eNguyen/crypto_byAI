"""
Hybrid encryption utilities (AES + RSA like ransomware)
"""

from typing import Tuple, Dict, Any
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import json


def encrypt_hybrid_aes_rsa(data: bytes) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt data using hybrid encryption (AES + RSA)
    Simulates ransomware pattern: AES encrypts file, RSA encrypts AES key
    
    Args:
        data: Data to encrypt
    
    Returns:
        Tuple of (hybrid_ciphertext, metadata)
    """
    # Generate RSA key pair
    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey()
    
    # Encrypt file with AES
    aes_key = get_random_bytes(32)  # 256-bit AES key
    iv = get_random_bytes(AES.block_size)
    
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    file_ciphertext = cipher_aes.encrypt(pad(data, AES.block_size))
    
    # Encrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Create hybrid ciphertext format (simulating ransomware pattern)
    # Format: [RSA_encrypted_key_length:4][RSA_encrypted_key][IV:16][AES_encrypted_file]
    hybrid_ciphertext = (
        len(encrypted_aes_key).to_bytes(4, byteorder='big') +
        encrypted_aes_key +
        iv +
        file_ciphertext
    )
    
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
