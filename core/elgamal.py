"""
ElGamal Encryption Module
ElGamal key generation and encryption
"""

import random
from .crypto_math import generate_prime, find_primitive_root, power_mod


class ElGamalKeyPair:
    """
    ElGamal public/private key pair
    """
    
    def __init__(self, p, g, private_key, public_key):
        self.p = p  # Large prime
        self.g = g  # Generator (primitive root)
        self.private_key = private_key  # x (secret)
        self.public_key = public_key  # y = g^x mod p


class ElGamal:
    """
    ElGamal Asymmetric Encryption System
    Based on discrete logarithm problem
    """
    
    @staticmethod
    def generate_keys(bits=16):
        """
        Generate ElGamal key pair
        
        Returns:
            ElGamalKeyPair object containing:
            - p: large prime
            - g: generator (primitive root of p)
            - private_key (x): random secret
            - public_key (y): g^x mod p
        """
        p = generate_prime(bits)
        
        g = find_primitive_root(p)
        
        private_key = random.randint(2, p - 2)
        
        public_key = power_mod(g, private_key, p)
        
        return ElGamalKeyPair(p, g, private_key, public_key)
    
    @staticmethod
    def encrypt(plaintext, public_key_pair):
        """
        Encrypt message using ElGamal
        
        Args:
            plaintext: Message to encrypt (integer or string)
            public_key_pair: Recipient's ElGamalKeyPair
        
        Returns:
            (c1, c2): Ciphertext pair
        """
        p = public_key_pair.p
        g = public_key_pair.g
        y = public_key_pair.public_key
        
        if isinstance(plaintext, str):
            m = int.from_bytes(plaintext.encode(), 'big')#Converts a string to integer
        else:
            m = plaintext
        
        if m >= p:#message < modulus should be
            raise ValueError(f"Message too large. Must be < {p}")
        
        k = random.randint(2, p - 2)#A random, one-time secret
        
        c1 = power_mod(g, k, p)
        
        c2 = (m * power_mod(y, k, p)) % p
        
        return (c1, c2)
    
    @staticmethod
    def decrypt(ciphertext, private_key_pair):
        """
        Decrypt ElGamal ciphertext
        
        Args:
            ciphertext: (c1, c2) tuple
            private_key_pair: Recipient's ElGamalKeyPair with private key
        
        Returns:
            Decrypted message (integer)
        """
        c1, c2 = ciphertext
        p = private_key_pair.p
        x = private_key_pair.private_key
        
        s = power_mod(c1, x, p)
        
        from crypto_math import mod_inverse
        s_inv = mod_inverse(s, p)
        
        m = (c2 * s_inv) % p
        
        return m
    
    @staticmethod
    def decrypt_to_string(ciphertext, private_key_pair):
        """
        Decrypt ElGamal ciphertext and convert to string
        """
        m = ElGamal.decrypt(ciphertext, private_key_pair)
        
        num_bytes = (m.bit_length() + 7) // 8#Calculates minimum bytes needed to represent the number.
        if num_bytes == 0:
            num_bytes = 1
        
        try:
            plaintext = m.to_bytes(num_bytes, 'big').decode('utf-8', errors='ignore')#Converts integer to bytes to string
            return plaintext
        except:
            return str(m)


class KeyDistributionCenter:
    """
    Key Distribution Center (KDC)
    Simulates a trusted third party for key exchange
    """
    
    def __init__(self):
        self.public_keys = {}
        self.key_registry = {}
    
    def register_user(self, username, key_pair):
        """
        Register user's public key with KDC
        
        Args:
            username: User identifier
            key_pair: User's ElGamalKeyPair
        """
        self.public_keys[username] = key_pair
        self.key_registry[username] = {
            'p': key_pair.p,
            'g': key_pair.g,
            'public_key': key_pair.public_key,
            'registered_at': None  # Could add timestamp
        }
        
        return True
    
    def get_public_key(self, username):
        """
        Retrieve user's public key from KDC
        Args:
            username: User identifier
        Returns:
            ElGamalKeyPair or None if not found
        """
        return self.public_keys.get(username)
    
    def is_user_registered(self, username):
        """Check if user has registered their public key"""
        return username in self.public_keys
    
    def list_registered_users(self):
        """Get list of all registered users"""
        return list(self.public_keys.keys())
    
    def remove_user(self, username):
        """Remove user from KDC"""
        if username in self.public_keys:
            del self.public_keys[username]
            del self.key_registry[username]
            return True
        return False
    
    def get_key_info(self, username):
        """Get public key information for a user"""
        return self.key_registry.get(username)
