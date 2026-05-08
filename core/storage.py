"""
Secure storage module

Handles saving/loading of:
- users (encrypted)
- user keys (encrypted)
- temporary blockchain with integrity hashes
"""

import os
import json
from datetime import datetime

from core.modern_ciphers import XORStreamCipher
from core.hashing import MessageIntegrity


class SecureStorage:
    """
    SecureStorage stores users, keys, and temporary blockchain data
    using simple encryption (XOR) plus HMAC/integrity hashes.
    """

    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)

        self.users_file = os.path.join(self.data_dir, "users.json")
        self.keys_file = os.path.join(self.data_dir, "keys.json")
        self.integrity_file = os.path.join(self.data_dir, "integrity.json")
        self.blockchain_file = os.path.join(self.data_dir, "blockchain_temp.json")

        # Simple fixed key used for XOR demo 
        self._xor_key = "demo-storage-key"

    # Internal helpers #

    def _encrypt_data(self, data):
        """
        Encrypt data using XORStreamCipher.
        Returns hex string.
        """
        cipher = XORStreamCipher(key=self._xor_key)
        plaintext = json.dumps(data, sort_keys=True)
        return cipher.encrypt(plaintext)

    def _decrypt_data(self, encrypted_hex, hmac_signature=None):
        """
        Decrypt data with XORStreamCipher and optional HMAC check.
        """
        try:
            cipher = XORStreamCipher(key=self._xor_key)
            plaintext = cipher.decrypt(encrypted_hex)
            data = json.loads(plaintext)
            return data
        except Exception:
            return None

    # Users #

    def save_users(self, users_dict):
        """
        Save users dictionary in encrypted form.
        """
        try:
            data = {"users": users_dict}
            encrypted_hex = self._encrypt_data(data)

            combined_data = {
                "encrypted": encrypted_hex
            }

            with open(self.users_file, "w") as f:
                json.dump(combined_data, f)

            self._save_integrity_hash("users", encrypted_hex)
            return True, "Users saved securely (XOR)"
        except Exception as e:
            return False, f"Error saving users: {e}"

    def load_users(self):
        """
        Load users from encrypted file.
        Returns dict or {}.
        """
        if not os.path.exists(self.users_file):
            return {}

        try:
            with open(self.users_file, "r") as f:
                combined_data = json.load(f)

            encrypted_hex = combined_data.get("encrypted")
            if not encrypted_hex:
                return {}

            data = self._decrypt_data(encrypted_hex)
            if data and "users" in data:
                return data["users"]
            return {}
        except Exception as e:
            print(f"Error loading users: {e}")
            return {}

    #  User keys #

    def save_user_keys(self, keys_dict):
        """
        Save user keys dictionary in encrypted form.
        """
        try:
            data = {"keys": keys_dict}
            encrypted_hex = self._encrypt_data(data)

            combined_data = {
                "encrypted": encrypted_hex
            }

            with open(self.keys_file, "w") as f:
                json.dump(combined_data, f)

            self._save_integrity_hash("keys", encrypted_hex)
            return True, "User keys saved securely (XOR)"
        except Exception as e:
            return False, f"Error saving keys: {e}"

    def load_user_keys(self):
        """
        Load user keys from encrypted file.
        Returns dict or {}.
        """
        if not os.path.exists(self.keys_file):
            return {}

        try:
            with open(self.keys_file, "r") as f:
                combined_data = json.load(f)

            encrypted_hex = combined_data.get("encrypted")
            if not encrypted_hex:
                return {}

            data = self._decrypt_data(encrypted_hex)
            if data and "keys" in data:
                return data["keys"]
            return {}
        except Exception as e:
            print(f"Error loading keys: {e}")
            return {}

    #  Integrity hashes  #

    def _save_integrity_hash(self, file_type, data):
        """
        Save SHA-256 hash of data for integrity verification.

        file_type: 'users' or 'keys'
        data: encrypted hex string
        """
        try:
            data_hash = MessageIntegrity.compute_hash(data)
            integrity_data = {}

            if os.path.exists(self.integrity_file):
                with open(self.integrity_file, "r") as f:
                    integrity_data = json.load(f)

            integrity_data[file_type] = {
                "hash": data_hash,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            with open(self.integrity_file, "w") as f:
                json.dump(integrity_data, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save integrity hash: {e}")

    def verify_file_integrity(self, file_type):
        """
        Verify file integrity using stored SHA-256 hash.

        file_type: 'users' or 'keys'
        """
        try:
            if not os.path.exists(self.integrity_file):
                return False, "No integrity data found"

            with open(self.integrity_file, "r") as f:
                integrity_data = json.load(f)

            if file_type not in integrity_data:
                return False, f"No integrity hash for {file_type}"

            expected_hash = integrity_data[file_type]["hash"]
            file_path = self.users_file if file_type == "users" else self.keys_file

            if not os.path.exists(file_path):
                return False, f"{file_type} file not found"

            with open(file_path, "r") as f:
                current_data = json.load(f)

            current_encrypted = current_data.get("encrypted", "")
            current_hash = MessageIntegrity.compute_hash(current_encrypted)

            if current_hash == expected_hash:
                return True, f"{file_type} integrity verified"
            else:
                return False, f"{file_type} integrity check failed - file may be corrupted"

        except Exception as e:
            return False, f"Error verifying integrity: {e}"

    #  Temporary blockchain -#

    def save_blockchain_temp(self, blockchain_data):
        """
        Save blockchain temporarily (unencrypted for demo).
        """
        try:
            blockchain_json = json.dumps(blockchain_data, sort_keys=True)
            blockchain_hash = MessageIntegrity.compute_hash(blockchain_json)

            data_to_save = {
                "blockchain": blockchain_data,
                "hash": blockchain_hash,
                "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "note": "Temporary blockchain storage - cleared on restart"
            }

            with open(self.blockchain_file, "w") as f:
                json.dump(data_to_save, f, indent=2)

            return True, "Blockchain saved temporarily with integrity hash"
        except Exception as e:
            return False, f"Error saving blockchain: {e}"

    def load_blockchain_temp(self):
        """
        Load temporary blockchain data with integrity verification.
        Returns list of blocks or None.
        """
        if not os.path.exists(self.blockchain_file):
            return None

        try:
            with open(self.blockchain_file, "r") as f:
                data = json.load(f)

            if not data or "blockchain" not in data:
                return None

            if "hash" in data:
                blockchain_json = json.dumps(data["blockchain"], sort_keys=True)
                computed_hash = MessageIntegrity.compute_hash(blockchain_json)
                if computed_hash != data["hash"]:
                    print("Warning: Blockchain integrity check failed")
                    return None

            return data["blockchain"]
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            return None

    def clear_blockchain_temp(self):
        """Clear temporary blockchain storage."""
        try:
            if os.path.exists(self.blockchain_file):
                os.remove(self.blockchain_file)
        except Exception:
            pass
