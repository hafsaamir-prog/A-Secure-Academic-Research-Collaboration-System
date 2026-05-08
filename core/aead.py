"""AEAD (Authenticated Encryption with Associated Data)

Demonstrates authenticated encryption combining confidentiality and integrity
in a single operation. This module implements a simple AEAD construction using:
- Keystream-based encryption (SHA-256 PRF)
- HMAC-SHA256 for authentication

Educational implementation showing how modern AEAD modes (like AES-GCM, ChaCha20-Poly1305)
work conceptually.
"""
import hashlib
import hmac
from typing import Tuple


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """
    Generate a keystream using SHA-256 as a PRF with counter mode.
    
    Args:
        key: Encryption key
        nonce: Unique nonce for this encryption
        length: Number of bytes needed
        
    Returns:
        Keystream bytes
    """
    out = b""
    counter = 0
    while len(out) < length:
        counter_bytes = counter.to_bytes(4, "big")
        out += hashlib.sha256(key + nonce + counter_bytes).digest()
        counter += 1
    return out[:length]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext and authenticate with AAD (Additional Authenticated Data).
    
    AEAD provides:
    - Confidentiality: plaintext is encrypted
    - Integrity: ciphertext and AAD are authenticated
    - Authentication: only holders of the key can create valid ciphertexts
    
    Args:
        key: 32-byte encryption key
        nonce: Unique nonce (must never repeat with same key!)
        aad: Additional data to authenticate (not encrypted)
        plaintext: Data to encrypt and authenticate
        
    Returns:
        Tuple of (ciphertext, authentication_tag)
    """
    # Encrypt: XOR plaintext with keystream
    ks = _keystream(key, nonce, len(plaintext))
    ciphertext = xor_bytes(plaintext, ks)
    
    # Authenticate: HMAC over (AAD || nonce || ciphertext)
    auth_data = aad + nonce + ciphertext
    tag = hmac.new(key, auth_data, hashlib.sha256).digest()
    
    return ciphertext, tag


def decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    Verify authentication tag and decrypt ciphertext.
    
    Args:
        key: 32-byte encryption key
        nonce: Nonce used during encryption
        aad: Additional authenticated data
        ciphertext: Encrypted data
        tag: Authentication tag to verify
        
    Returns:
        Decrypted plaintext
        
    Raises:
        ValueError: If authentication tag is invalid (tampering detected)
    """
    # Verify: Recompute and compare authentication tag
    auth_data = aad + nonce + ciphertext
    expected_tag = hmac.new(key, auth_data, hashlib.sha256).digest()
    
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("AEAD authentication failed - data may be tampered!")
    
    # Decrypt: XOR ciphertext with same keystream
    ks = _keystream(key, nonce, len(ciphertext))
    plaintext = xor_bytes(ciphertext, ks)
    
    return plaintext