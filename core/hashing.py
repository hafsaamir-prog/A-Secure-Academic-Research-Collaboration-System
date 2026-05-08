"""
Hashing Module
SHA-256 hashing for integrity verification
"""

import hashlib
import hmac


class MessageIntegrity:
    """
    Handles message integrity verification using SHA-256 hashing
    """
    
    @staticmethod
    def compute_hash(message):
        """
        Compute SHA-256 hash of a message
        Returns: hexadecimal hash string
        """
        if isinstance(message, str):#Hash functions work on bytes, not strings
            message = message.encode()
        
        hash_obj = hashlib.sha256(message)#Creates a SHA-256 hash object
        return hash_obj.hexdigest()#Converts raw binary hash into readable hex string.
    
    @staticmethod
    def hash_message(message):
        """Alias for compute_hash for test compatibility"""
        return MessageIntegrity.compute_hash(message)
    
    @staticmethod
    def verify_hash(message, expected_hash):
        """
        Verify if message hash matches expected hash
        Returns: (is_valid: bool, computed_hash: str)
        """
        computed_hash = MessageIntegrity.compute_hash(message)
        is_valid = (computed_hash == expected_hash)
        return is_valid, computed_hash
    
    @staticmethod
    def verify_message(message, expected_hash):
        """Alias for verify_hash for test compatibility (returns just boolean)"""
        is_valid, _ = MessageIntegrity.verify_hash(message, expected_hash)
        return is_valid
    
    @staticmethod
    def compute_hmac(message, key):
        """
        Compute HMAC-SHA256 for message authentication
        HMAC provides both integrity and authenticity
        """
        if isinstance(message, str):
            message = message.encode()
        if isinstance(key, str):
            key = key.encode()
        
        hmac_obj = hmac.new(key, message, hashlib.sha256)
        return hmac_obj.hexdigest()
    
    @staticmethod
    def verify_hmac(message, key, expected_hmac):
        """
        Verify HMAC of a message
        Returns: (is_valid: bool, computed_hmac: str)
        """
        computed_hmac = MessageIntegrity.compute_hmac(message, key)
        is_valid = hmac.compare_digest(computed_hmac, expected_hmac)
        return is_valid, computed_hmac
    
    @staticmethod
    def hash_file(filepath):
        """
        Compute SHA-256 hash of a file
        Useful for file integrity verification
        """
        hash_obj = hashlib.sha256()
        
        try:
            with open(filepath, 'rb') as f:#Opens file in binary mode
                for chunk in iter(lambda: f.read(4096), b''):#Reads file in 4 KB chunks
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except FileNotFoundError:
            return None
    
    @staticmethod
    def compute_multiple_hashes(message):
        """
        Compute multiple hash algorithms for comparison
        Returns: dictionary with different hash types
        """
        if isinstance(message, str):
            message = message.encode()#Converts string to bytes
        
        hashes = {
            'md5': hashlib.md5(message).hexdigest(),
            'sha1': hashlib.sha1(message).hexdigest(),
            'sha256': hashlib.sha256(message).hexdigest(),
            'sha512': hashlib.sha512(message).hexdigest(),
        }
        
        return hashes
        
class MessageAuthenticationCode:
    """
    Message Authentication Code (MAC) for message authenticity
    """
    
    def __init__(self, secret_key):
        """Initialize MAC with a secret key"""
        if isinstance(secret_key, str):
            secret_key = secret_key.encode()
        self.secret_key = secret_key
    
    def generate_mac(self, message):
        """Generate MAC for a message"""
        return MessageIntegrity.compute_hmac(message, self.secret_key)
    
    def verify_mac(self, message, mac):
        """Verify MAC for a message"""
        is_valid, _ = MessageIntegrity.verify_hmac(message, self.secret_key, mac)
        return is_valid
