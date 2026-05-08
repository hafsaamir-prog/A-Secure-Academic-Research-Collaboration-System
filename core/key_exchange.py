"""
Key Exchange (Diffie-Hellman)

Educational Diffie-Hellman key exchange for establishing shared secrets.
Used by SecureProtocol for session key establishment.
"""

import secrets
import hashlib
from typing import Optional#this value may be None

# Demo prime (160-bit)
DEMO_P = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F#A large prime number.
DEMO_G = 5#A small integer that produces all group elements when exponentiated mod p.


def generate_private_key(bits: int = 128) -> int:
    """Generate a random private key (integer)."""
    return secrets.randbits(bits)


def generate_public_key(private_key: int, p: int = DEMO_P, g: int = DEMO_G) -> int:
    """Compute DH public key = g^private mod p."""
    return pow(g, private_key, p)


def compute_shared_secret(their_public: int, my_private: int, p: int = DEMO_P) -> int:
    """Compute shared secret (their_public^my_private mod p)."""
    return pow(their_public, my_private, p)


def derive_session_key(shared_secret: int, length: int = 32) -> bytes:
    """Derive a session key from shared secret using SHA-256."""#DH shared secret is an integer.
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")#Must be converted to bytes before hashing
  #(bit_length + 7) // 8 ensures correct byte size.  
    return hashlib.sha256(secret_bytes).digest()[:length]#Converts the raw DH shared secret into a usable symmetric ke
#[:length] allows variable key sizes (default: 32 bytes)

class DHKeyExchange:
    """
    Class-based interface for Diffie-Hellman key exchange.
    """

    def __init__(self, p: Optional[int] = None, g: Optional[int] = None):
        self.p = p or DEMO_P#Uses provided values if given.
        self.g = g or DEMO_G#Otherwise falls back to defaults
        self.private_key = generate_private_key()
        self.public_key = generate_public_key(self.private_key, self.p, self.g)
        self.shared_secret: Optional[int] = None
        self.session_key: Optional[bytes] = None

    def get_public_key(self) -> int:
        """Return public key to share."""
        return self.public_key

    def compute_shared_key(self, their_public_key: int) -> bytes:
        """Compute shared secret and derive session key."""
        self.shared_secret = compute_shared_secret(their_public_key, self.private_key, self.p)
        self.session_key = derive_session_key(self.shared_secret)
        return self.session_key
#Strong DH groups (should use 2048+ bits)
#not 160 bits