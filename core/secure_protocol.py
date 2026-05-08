"""
Secure protocol module for AEAD + DH + key rotation.

Uses:
- EphemeralDH (postquantum.py) for ephemeral keys
- AEAD (aead.py) for authenticated encryption
"""

import json
import secrets
import time
from typing import Dict, Optional, Tuple

from core.key_exchange import DEMO_P, DEMO_G
from core.aead import encrypt as aead_encrypt, decrypt as aead_decrypt
from core.km import KeyManager
from core.postquantum import EphemeralDH


class SecureSession:
    """
    Represents a secure communication session between client and server.
    - Ephemeral DH keys (forward secrecy)
    - Session key from key exchange
    - AEAD encryption for all messages
    - Key rotation support
    """

    def __init__(self, session_id: str, is_server: bool = False):
        self.session_id = session_id
        self.is_server = is_server
        self.created_at = time.time()

        # Ephemeral keys for forward secrecy
        self.ephemeral_dh = EphemeralDH()

        # Session key
        self.session_key: Optional[bytes] = None

        # Message counter for nonces
        self.message_counter = 0

        # Rotation tracking
        self.key_rotated_at: Optional[float] = None
        self.messages_encrypted = 0

        # Security limits
        self.max_messages_before_rotation = 1000
        self.max_session_age_seconds = 3600  # 1 hour

    def get_public_key(self) -> int:
        """Return current ephemeral public key."""
        return self.ephemeral_dh.public_key

    def complete_key_exchange(self, their_public_key: int) -> bytes:
        """Finish DH key exchange and derive session key."""
        self.session_key = self.ephemeral_dh.compute_session_key(their_public_key)
        return self.session_key

    def needs_rotation(self) -> bool:
        """Check if key rotation is needed."""
        if self.messages_encrypted >= self.max_messages_before_rotation:
            return True
        age = time.time() - self.created_at
        if age >= self.max_session_age_seconds:
            return True
        return False

    def rotate_key(self) -> Tuple[int, int]:
        """
        Rotate keys: destroy old, create new ephemeral DH keys.
        Returns (new_public, new_private) for demo/logging.
        """
        self.ephemeral_dh.destroy_keys()
        self.ephemeral_dh = EphemeralDH()
        self.key_rotated_at = time.time()
        self.messages_encrypted = 0
        return self.ephemeral_dh.public_key, self.ephemeral_dh.private_key

    def encrypt_message(self, plaintext: str, metadata: Optional[Dict] = None) -> Dict:
        """Encrypt a message with AEAD and return all crypto fields."""
        if not self.session_key:
            raise RuntimeError("Session key not established. Complete key exchange first.")

        # Unique nonce per message
        self.message_counter += 1
        nonce = self.message_counter.to_bytes(16, "big")

        # AAD
        aad_dict = {
            "session_id": self.session_id,
            "timestamp": time.time(),
            "counter": self.message_counter,
        }
        if metadata:
            aad_dict.update(metadata)

        aad = json.dumps(aad_dict, sort_keys=True).encode("utf-8")
        plaintext_bytes = plaintext.encode("utf-8")

        ciphertext, tag = aead_encrypt(self.session_key, nonce, aad, plaintext_bytes)

        self.messages_encrypted += 1

        return {
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex(),
            "nonce": nonce.hex(),
            "aad": aad_dict,
            "counter": self.message_counter,
        }

    def decrypt_message(self, encrypted_data: Dict) -> str:
        """Decrypt and verify AEAD-encrypted message."""
        if not self.session_key:
            raise RuntimeError("Session key not established. Complete key exchange first.")

        ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
        tag = bytes.fromhex(encrypted_data["tag"])
        nonce = bytes.fromhex(encrypted_data["nonce"])
        aad = json.dumps(encrypted_data["aad"], sort_keys=True).encode("utf-8")

        plaintext_bytes = aead_decrypt(self.session_key, nonce, aad, ciphertext, tag)
        return plaintext_bytes.decode("utf-8")

    def destroy(self):
        """Destroy session keys for forward secrecy."""
        self.ephemeral_dh.destroy_keys()
        if self.session_key:
            self.session_key = b"\x00" * len(self.session_key)
        print(f"[Security] Session {self.session_id} destroyed - forward secrecy achieved")


class SecureProtocol:
    """
    Manager for secure sessions:
    - Creates sessions
    - Handles handshakes
    - Encrypts/decrypts messages
    - Rotates keys on demand
    """

    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.key_manager = KeyManager()
        self.sessions: Dict[str, SecureSession] = {}

    def create_session(self, session_id: Optional[str] = None) -> SecureSession:
        """Create a new SecureSession with ephemeral keys."""
        if session_id is None:
            session_id = f"session-{secrets.token_hex(8)}"

        session = SecureSession(session_id, is_server=self.is_server)
        self.sessions[session_id] = session

        print(f"[Security] Created session {session_id} with ephemeral DH keys")
        print(f" - Public key: {hex(session.get_public_key())[:32]}...")
        return session

    def initiate_handshake(self, session_id: str) -> Dict:
        """Client-side: build handshake init message with public key."""
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.sessions[session_id]
        handshake_data = {
            "type": "HANDSHAKE_INIT",
            "session_id": session_id,
            "public_key": session.get_public_key(),
            "p": DEMO_P,
            "g": DEMO_G,
            "timestamp": time.time(),
        }
        print(f"[Security] Initiating handshake for session {session_id}")
        return handshake_data

    def respond_to_handshake(self, handshake_init: Dict) -> Tuple[Dict, SecureSession]:
        """Server-side: respond to handshake and complete key exchange."""
        session_id = handshake_init["session_id"]
        their_public_key = handshake_init["public_key"]

        session = self.create_session(session_id)
        session.complete_key_exchange(their_public_key)

        handshake_response = {
            "type": "HANDSHAKE_RESPONSE",
            "session_id": session_id,
            "public_key": session.get_public_key(),
            "timestamp": time.time(),
        }

        print(f"[Security] Handshake complete for session {session_id}")
        print(f" - Session key established: {session.session_key.hex()[:32]}...")
        return handshake_response, session

    def complete_handshake(self, session_id: str, handshake_response: Dict):
        """Client-side: finish handshake using server's public key."""
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.sessions[session_id]
        their_public_key = handshake_response["public_key"]
        session.complete_key_exchange(their_public_key)

        print(f"[Security] Handshake complete for session {session_id}")
        print(f" - Session key established: {session.session_key.hex()[:32]}...")

    def send_secure_message(self, session_id: str, message: str, metadata: Optional[Dict] = None) -> Dict:
        """Encrypt and wrap a message for sending."""
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.sessions[session_id]

        if session.needs_rotation():
            print(f"[Security] Key rotation needed for session {session_id}")
            return {
                "type": "KEY_ROTATION_REQUIRED",
                "session_id": session_id,
                "reason": "Message limit or session age exceeded",
            }

        encrypted = session.encrypt_message(message, metadata)
        encrypted["type"] = "SECURE_MESSAGE"
        encrypted["session_id"] = session_id
        return encrypted

    def receive_secure_message(self, session_id: str, encrypted_data: Dict) -> str:
        """Decrypt received secure message."""
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.sessions[session_id]
        return session.decrypt_message(encrypted_data)

    def rotate_session_key(self, session_id: str) -> Dict:
        """Start key rotation."""
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.sessions[session_id]
        print(f"[Security] Rotating keys for session {session_id}")
        new_public_key, _ = session.rotate_key()

        return {
            "type": "KEY_ROTATION",
            "session_id": session_id,
            "new_public_key": new_public_key,
            "timestamp": time.time(),
        }

    def complete_key_rotation(self, session_id: str, rotation_data: Dict):
        """Finish key rotation using other party's new public key."""
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.sessions[session_id]
        their_new_public_key = rotation_data["new_public_key"]
        session.complete_key_exchange(their_new_public_key)

        print(f"[Security] Key rotation complete for session {session_id}")
        print(f" - New session key: {session.session_key.hex()[:32]}...")

    def destroy_session(self, session_id: str):
        """Destroy a session and its keys."""
        if session_id in self.sessions:
            self.sessions[session_id].destroy()
            del self.sessions[session_id]
