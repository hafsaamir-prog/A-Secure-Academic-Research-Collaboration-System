"""
Modern Ciphers Module
XOR-based Stream Cipher and Mini Block Cipher
"""

import os#random bytes

class XORStreamCipher:
    """
    XOR Stream Cipher: Uses XOR operation with a key stream
    Stream cipher concept
    """
    
    def __init__(self, key=None):
        if key is None:
            self.key = os.urandom(16)
        elif isinstance(key, str):
            self.key = key.encode()
        else:
            self.key = key
    
    @staticmethod
    def generate_key(length=16):
        """Generate a random key of specified length (in bytes)"""
        return os.urandom(length).hex()
    
    def _generate_keystream(self, length):
        """Generate keystream by repeating the key"""
        keystream = bytearray()
        for i in range(length):
            keystream.append(self.key[i % len(self.key)])
        return keystream
    
    def encrypt(self, plaintext, key=None):
        """Encrypt plaintext using XOR stream cipher"""
        if key is not None:
            if isinstance(key, str):
                self.key = bytes.fromhex(key) if len(key) > 16 else key.encode()
            else:
                self.key = key
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        keystream = self._generate_keystream(len(plaintext))
        ciphertext = bytearray()
        
        for i in range(len(plaintext)):
            ciphertext.append(plaintext[i] ^ keystream[i])
        
        return ciphertext.hex()
    
    def decrypt(self, ciphertext_hex, key=None):
        """Decrypt ciphertext using XOR stream cipher"""
        if key is not None:
            if isinstance(key, str):
                self.key = bytes.fromhex(key) if len(key) > 16 else key.encode()
            else:
                self.key = key
        
        ciphertext = bytes.fromhex(ciphertext_hex)
        keystream = self._generate_keystream(len(ciphertext))
        plaintext = bytearray()
        
        for i in range(len(ciphertext)):
            plaintext.append(ciphertext[i] ^ keystream[i])
        
        return plaintext.decode('utf-8', errors='ignore')
    
    def get_key_hex(self):
        """Return key in hexadecimal format"""
        return self.key.hex()
    
    def set_key_from_hex(self, key_hex):
        """Set key from hexadecimal string"""
        self.key = bytes.fromhex(key_hex)


class MiniBlockCipher:
    """
    Mini Block Cipher: Simple substitution-permutation network
    Block cipher concept
    Operates on 8-byte blocks with substitution and permutation rounds
    """
    
    def __init__(self, key=None):
        if key is None:
            self.key = os.urandom(8)
        elif isinstance(key, str):
            key_bytes = key.encode()
            if len(key_bytes) < 8:
                key_bytes += b'\x00' * (8 - len(key_bytes))
            else:
                key_bytes = key_bytes[:8]
            self.key = key_bytes
        else:
            self.key = key
        
        self.sbox = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]
        
        self.inv_sbox = [0] * 16
        for i, val in enumerate(self.sbox):
            self.inv_sbox[val] = i
    
    @staticmethod
    def generate_key():
        """Generate a random 8-byte key (returns 16 hex characters)"""
        key_bytes = os.urandom(16)  # Generate 16 bytes for 32 hex chars
        return key_bytes.hex()
    
    def _pad(self, data):
        """PKCS7 padding to make data multiple of 8 bytes"""
        pad_len = 8 - (len(data) % 8)
        return data + bytes([pad_len] * pad_len)
    
    def _unpad(self, data):
        """Remove PKCS7 padding"""
        if len(data) == 0:
            return data
        pad_len = data[-1]
        if pad_len > 8 or pad_len > len(data):
            return data  # Invalid padding, return as is
        return data[:-pad_len]
    
    def _substitute(self, block):
        """Apply S-box substitution to each nibble (4-bit)"""
        result = []
        for b in block:
            high = (b >> 4) & 0x0F
            low = b & 0x0F
            new_high = self.sbox[high]
            new_low = self.sbox[low]
            result.append((new_high << 4) | new_low)
        return bytes(result)
    
    def _inv_substitute(self, block):
        """Apply inverse S-box substitution to each nibble (4-bit)"""
        result = []
        for b in block:
            high = (b >> 4) & 0x0F
            low = b & 0x0F
            new_high = self.inv_sbox[high]
            new_low = self.inv_sbox[low]
            result.append((new_high << 4) | new_low)
        return bytes(result)
    
    def _permute(self, block):
        """Simple permutation"""
        return bytes([block[i] for i in [7, 0, 5, 2, 6, 1, 4, 3]])
    
    def _inv_permute(self, block):
        """Inverse permutation"""
        return bytes([block[i] for i in [1, 5, 3, 7, 6, 2, 4, 0]])
    
    def _xor_with_key(self, block):
        """XOR block with key"""
        return bytes([block[i] ^ self.key[i] for i in range(8)])
    
    def _encrypt_block(self, block):
        """Encrypt a single 8-byte block"""
        block = self._xor_with_key(block)
        
        block = self._substitute(block)
        
        block = self._permute(block)
        
        block = self._xor_with_key(block)
        
        return block
    
    def _decrypt_block(self, block):
        """Decrypt a single 8-byte block"""
        block = self._xor_with_key(block)
        
        block = self._inv_permute(block)
        
        block = self._inv_substitute(block)
        
        block = self._xor_with_key(block)
        
        return block
    
    def encrypt(self, plaintext, key=None):
        """Encrypt plaintext"""
        original_key = self.key
        
        if key is not None:
            if isinstance(key, str):
                key_bytes = bytes.fromhex(key)
                temp_key = key_bytes[:8]
                self.key = temp_key
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        padded = self._pad(plaintext)
        
        ciphertext = bytearray()
        for i in range(0, len(padded), 8):
            block = padded[i:i+8]
            encrypted_block = self._encrypt_block(block)
            ciphertext.extend(encrypted_block)
        
        result = ciphertext.hex()
        
        if key is not None:
            self.key = original_key
            
        return result
    
    def decrypt(self, ciphertext_hex, key=None):
        """Decrypt ciphertext"""
        original_key = self.key
        
        if key is not None:
            if isinstance(key, str):
                key_bytes = bytes.fromhex(key)
                temp_key = key_bytes[:8]
                self.key = temp_key
        
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            decrypted_block = self._decrypt_block(block)
            plaintext.extend(decrypted_block)
        
        try:
            plaintext = self._unpad(bytes(plaintext))
        except:
            plaintext = bytes(plaintext)
        
        result = plaintext.decode('utf-8', errors='ignore')
        
        if key is not None:
            self.key = original_key
            
        return result
        
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            decrypted_block = self._decrypt_block(block)
            plaintext.extend(decrypted_block)
        
        plaintext = self._unpad(bytes(plaintext))
        
        return plaintext.decode('utf-8', errors='ignore')
    
    def get_key_hex(self):
        """Return key in hexadecimal format"""
        return self.key.hex()

