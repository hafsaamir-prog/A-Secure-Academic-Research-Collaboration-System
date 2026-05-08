"""
Classical Ciphers Module
Caesar Cipher and Vigenère Cipher
"""

class CaesarCipher:
    """
    Caesar Cipher: Shifts each letter by a fixed number of positions
    """
    def __init__(self, shift=3):
        self.shift = shift
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using Caesar cipher (converts to uppercase)"""
        ciphertext = ""
        
        for char in plaintext:
            if char.isalpha():
                char = char.upper()
                ascii_offset = ord('A')#ord('A') = 65.
                shifted = (ord(char) - ascii_offset + self.shift) % 26#Used to convert letters into numbers 0–25.
                ciphertext += chr(shifted + ascii_offset)#Converts number 0–25 back into a letter
            else:
                ciphertext += char
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext using Caesar cipher"""
        original_shift = self.shift
        self.shift = -self.shift#Decryption = encryption with negative shif
        plaintext = self.encrypt(ciphertext)
        self.shift = original_shift
        return plaintext

class VigenereCipher:
    """
    Vigenère Cipher: Polyalphabetic substitution using a keyword
    """
    #Uses a repeating keyword instead of a single shift
    def __init__(self, key):
        self.key = key.upper()
    
    def _extend_key(self, text_length):
        """Extend key to match text length"""
        extended_key = ""
        key_index = 0
        
        for i in range(text_length):
            extended_key += self.key[key_index % len(self.key)]#% len(self.key) makes the key as long as the plaintext
            key_index += 1#Move to next key character.
        
        return extended_key
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using Vigenère cipher"""
        ciphertext = ""
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')#Preserves case (uppercase stays uppercase, lowercase stays lowercase).
                
                key_char = self.key[key_index % len(self.key)]
                key_shift = ord(key_char) - ord('A')
                
                shifted = (ord(char) - ascii_offset + key_shift) % 26#Same math as Caesar, but shift changes every character.
                ciphertext += chr(shifted + ascii_offset)
                
                key_index += 1
            else:
                ciphertext += char#Non-letters are copied unchanged
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext using Vigenère cipher"""
        plaintext = ""
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                
                key_char = self.key[key_index % len(self.key)]
                key_shift = ord(key_char) - ord('A')
                
                shifted = (ord(char) - ascii_offset - key_shift) % 26#Subtracts key shift instead of adding.
                plaintext += chr(shifted + ascii_offset)
                
                key_index += 1
            else:
                plaintext += char
        
        return plaintext
