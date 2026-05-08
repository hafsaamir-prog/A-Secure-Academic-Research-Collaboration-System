"""
Academic Research Collaborator - Client

we have two collaborators yet
  - Login as hafsa / hafsa123
  - Login as amna  / amna123
Then exchange research messages securely.
"""

import socket
import json
import secrets

from core.classical_ciphers import CaesarCipher, VigenereCipher
from core.modern_ciphers import XORStreamCipher, MiniBlockCipher
from core.hashing import MessageIntegrity
from core.secure_protocol import SecureProtocol


class MessageClient:
    """
    Client application for secure academic research collaboration
    """

    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port

        self.socket = None
        self.connected = False

        self.username = None
        self.session_id = None
        self.running = False

        self.protocol = SecureProtocol(is_server=False)
        self.secure_session_id = None
        self.secure_mode = False

    def connect(self):
        """Connect to server and establish secure session."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            self.running = True

            print(f"\nConnected to server at {self.host}:{self.port}")
            print("\n[Security] Establishing secure transport layer...")
            return self._establish_secure_session()
        except Exception as e:
            print(f"\nCould not connect to server: {e}")
            print("Make sure the server is running!")
            return False

    def disconnect(self):
        """Disconnect and destroy session."""
        self.running = False

        if self.connected and self.username:
            if self.secure_mode:
                self._send_secure_command({'command': 'LOGOUT'})
            else:
                self._send_request({'command': 'LOGOUT'})

        if self.secure_session_id and self.secure_session_id in self.protocol.sessions:
            self.protocol.destroy_session(self.secure_session_id)
            print("\n[Security] Session destroyed - forward secrecy achieved")

        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass

        self.connected = False
        print("\nDisconnected from server")

    def _establish_secure_session(self):
        """DH-based secure session establishment."""
        try:
            print("\n[Security] Establishing secure session...")
            self.secure_session_id = f"client-{secrets.token_hex(8)}"
            session = self.protocol.create_session(self.secure_session_id)

            print("\n[Security] Generated ephemeral DH keys")
            print(f" Public key: {hex(session.get_public_key())[:40]}...")

            handshake_init = self.protocol.initiate_handshake(self.secure_session_id)
            self._send_request(handshake_init)

            handshake_response = self._receive_response()
            if handshake_response and handshake_response.get('type') == 'HANDSHAKE_RESPONSE':
                self.protocol.complete_handshake(self.secure_session_id, handshake_response)
                self.secure_mode = True
                session_key = self.protocol.sessions[self.secure_session_id].session_key

                print("\nSecure transport layer established!")
                print(f" Session ID: {self.secure_session_id}")
                print(f" Session key: {session_key.hex()[:40]}...")
                print("\n[Security] Transport Layer: AEAD encrypted")
                print("[Security] Message Layer: Classical/modern ciphers")
                return True
            else:
                print("\nHandshake failed")
                self.secure_mode = False
                return True
        except Exception as e:
            print(f"\nSecure session establishment failed: {e}")
            print("Falling back to basic mode")
            self.secure_mode = False
            return True

    def _send_request(self, request):
        """Send plain JSON request."""
        try:
            if not self.connected or not self.socket:
                print("\nNot connected to server")
                return False

            request_json = json.dumps(request)
            self.socket.send(request_json.encode('utf-8'))
            return True
        except Exception as e:
            print(f"\nError sending request: {e}")
            self.connected = False
            return False

    def _send_secure_command(self, command):
        """Send AEAD-encrypted command."""
        try:
            if not self.secure_mode:
                return self._send_request(command)

            command_json = json.dumps(command)
            encrypted = self.protocol.send_secure_message(
                self.secure_session_id,
                command_json,
                {'command': command.get('command')}
            )

            if encrypted.get('type') == 'KEY_ROTATION_REQUIRED':
                print("\n[Security] Key rotation needed - rotating keys...")
                self._rotate_keys()
                return self._send_secure_command(command)

            return self._send_request(encrypted)
        except Exception as e:
            print(f"\nError sending secure command: {e}")
            return False

    def _receive_response(self, timeout=15):
        """Receive response from server (handles notifications)."""
        try:
            original_timeout = self.socket.gettimeout()
            self.socket.settimeout(timeout)
            data = self.socket.recv(32768)
            self.socket.settimeout(original_timeout)

            if data:
                response = json.loads(data.decode('utf-8'))

                if response.get('type') == 'NEW_MESSAGE':
                    print(f"\n\n[NOTIFICATION] New message from {response['from']}!")
                    print("Choose '2' to view your messages\n")
                    print("> ", end='', flush=True)
                    return self._receive_response(timeout)

                return response
            return None
        except socket.timeout:
            return {'status': 'error', 'message': 'Server timeout'}
        except Exception as e:
            return {'status': 'error', 'message': f'Error: {str(e)}'}

    def _receive_secure_response(self, timeout=15):
        """Receive and decrypt secure response."""
        try:
            encrypted_response = self._receive_response(timeout)
            if not encrypted_response or not self.secure_mode:
                return encrypted_response

            if encrypted_response.get('type') == 'SECURE_MESSAGE':
                decrypted_json = self.protocol.receive_secure_message(
                    self.secure_session_id,
                    encrypted_response
                )
                return json.loads(decrypted_json)
            else:
                return encrypted_response
        except Exception as e:
            return {'status': 'error', 'message': f'Decryption error: {str(e)}'}

    def _rotate_keys(self):
        """Perform key rotation."""
        try:
            print("[Security] Initiating key rotation...")
            rotation_req = self.protocol.rotate_session_key(self.secure_session_id)
            self._send_request(rotation_req)
            rotation_resp = self._receive_response()

            if rotation_resp and rotation_resp.get('type') == 'KEY_ROTATION':
                self.protocol.complete_key_rotation(self.secure_session_id, rotation_resp)
                print("Key rotation complete - new session key established")
                return True
            else:
                print("Key rotation failed")
                return False
        except Exception as e:
            print(f"Key rotation error: {e}")
            return False


    def login(self):
        """Login as Hafsa or Amna."""
        print("\n--- LOGIN (research collaborator) ---")
        print("Use one of:")
        print("  - hafsa / hafsa123")
        print("  - amna  / amna123\n")

        username = input("Username: ").strip()
        password = input("Password: ").strip()

        request = {
            'command': 'LOGIN',
            'username': username,
            'password': password
        }

        send_func = self._send_secure_command if self.secure_mode else self._send_request
        recv_func = self._receive_secure_response if self.secure_mode else self._receive_response

        if send_func(request):
            response = recv_func()
            if response and response.get('status') == 'success':
                self.username = username
                self.session_id = response['session_id']

                print(f"\n{response['message']}")
                print(f"Welcome, {self.username} (research collaborator)!")
                return True
            else:
                msg = response.get('message') if isinstance(response, dict) else 'Login failed'
                print(f"\n{msg}")
                return False
        return False

    def send_message(self):
        """Send a research message."""
        print("\n--- SEND RESEARCH MESSAGE ---")
        print("[Transport: Secure AEAD | Message: Choose cipher]\n")

        request = {
            'command': 'GET_USERS',
            'username': self.username
        }

        send_func = self._send_secure_command if self.secure_mode else self._send_request
        recv_func = self._receive_secure_response if self.secure_mode else self._receive_response

        if not send_func(request):
            print("\nFailed to get collaborators")
            return

        response = recv_func()
        if not response or response.get('status') != 'success':
            msg = response.get('message') if isinstance(response, dict) else 'Failed to get users'
            print(f"\n{msg}")
            return

        users = response['users']
        online_users = response['online_users']

        if not users:
            print("\nNo other collaborators registered.")
            return

        print("\nAvailable collaborators:")
        for user in users:
            status = "* online" if user in online_users else "offline"
            print(f" - {user} ({status})")

        receiver = input("\nSend to (username): ").strip()
        if receiver not in users:
            print(f"\nUser '{receiver}' not found")
            return

        message = input("Research message: ").strip()
        if not message:
            print("\nMessage cannot be empty")
            return

        print("\n--- SELECT ENCRYPTION ---")
        print("1. Caesar Cipher")
        print("2. Vigenère Cipher")
        print("3. XOR Stream Cipher")
        print("4. Mini Block Cipher")

        choice = input("\nChoice (1-4): ").strip()
        encryption_method = None
        encryption_params = {}

        if choice == '1':
            shift = input("Shift value (default 3): ").strip()
            encryption_method = 'Caesar'
            encryption_params['shift'] = int(shift) if shift else 3
        elif choice == '2':
            key = input("Vigenère key: ").strip()
            if not key:
                print("Key required")
                return
            encryption_method = 'Vigenere'
            encryption_params['key'] = key
        elif choice == '3':
            key = input("XOR key (optional, Enter for random): ").strip()
            encryption_method = 'XOR'
            if key:
                encryption_params['key'] = key
        elif choice == '4':
            key = input("Block key (optional, Enter for random): ").strip()
            encryption_method = 'Block'
            if key:
                encryption_params['key'] = key
        else:
            print("\nInvalid choice")
            return

        request = {
            'command': 'SEND_MESSAGE',
            'sender': self.username,
            'receiver': receiver,
            'plaintext': message,
            'encryption_method': encryption_method,
            'encryption_params': encryption_params
        }

        if send_func(request):
            response = recv_func(timeout=15)
            if response and response.get('status') == 'success':
                print("\nMessage sent successfully!")
                print(f"Block #{response['block_index']}")
                print(f"Block hash: {response['block_hash'][:32]}...")
                print(f"Message hash: {response['message_hash'][:32]}...")
                if 'encryption_params' in response and 'key_hex' in response['encryption_params']:
                    print("\nSAVE THIS KEY FOR DECRYPTION:")
                    print(f" Key (hex): {response['encryption_params']['key_hex']}")
            else:
                msg = response.get('message') if isinstance(response, dict) else 'Failed to send'
                print(f"\n{msg}")

    def view_messages(self):
        """View messages for this user."""
        print("\n--- YOUR RESEARCH MESSAGES ---")
        request = {
            'command': 'GET_MESSAGES',
            'username': self.username
        }

        send_func = self._send_secure_command if self.secure_mode else self._send_request
        recv_func = self._receive_secure_response if self.secure_mode else self._receive_response

        if not send_func(request):
            print("\nFailed to get messages")
            return

        response = recv_func()
        if not response or response.get('status') != 'success':
            msg = response.get('message') if isinstance(response, dict) else 'Failed to get messages'
            print(f"\n{msg}")
            return

        messages = response['messages']
        if not messages:
            print("\nNo messages found.")
            return

        print(f"\nFound {len(messages)} message(s):\n")
        for i, msg in enumerate(messages, 1):
            print("-" * 60)
            print(f"Message #{i} (Block #{msg['block_index']})")
            print(f"From: {msg['sender']}")
            print(f"To: {msg['receiver']}")
            print(f"Timestamp: {msg['timestamp']}")
            print(f"Encryption: {msg['encryption_method']}")
            print(f"Ciphertext: {msg['ciphertext'][:60]}...")
            print(f"Hash: {msg['message_hash'][:32]}...")

            if msg['receiver'] == self.username:
                decrypt = input("\nDecrypt this message? (y/n): ").strip().lower()
                if decrypt == 'y':
                    self._decrypt_message(msg)
                    print()

    def _decrypt_message(self, message_data):
        """Decrypt a single message."""
        encryption_method = message_data['encryption_method']
        ciphertext = message_data['ciphertext']
        original_hash = message_data['message_hash']

        print(f"\n[Decrypting with {encryption_method}]")
        try:
            plaintext = None

            if encryption_method == 'Caesar':
                shift = int(input("Enter shift value used: ") or "3")
                cipher = CaesarCipher(shift=shift)
                plaintext = cipher.decrypt(ciphertext)

            elif encryption_method == 'Vigenere':
                key = input("Enter Vigenère key used: ").strip()
                cipher = VigenereCipher(key=key)
                plaintext = cipher.decrypt(ciphertext)

            elif encryption_method == 'XOR':
                key_hex = input("Enter XOR key (hex): ").strip()
                cipher = XORStreamCipher()
                cipher.set_key_from_hex(key_hex)
                plaintext = cipher.decrypt(ciphertext)

            elif encryption_method == 'Block':
                key_hex = input("Enter block cipher key (hex): ").strip()
                cipher = MiniBlockCipher()
                cipher.key = bytes.fromhex(key_hex)
                plaintext = cipher.decrypt(ciphertext)
            else:
                print("Unknown encryption method")
                return

            if plaintext:
                print(f"\nDecrypted message: {plaintext}")
                print("\n[Verifying message integrity...]")
                is_valid, computed_hash = MessageIntegrity.verify_hash(plaintext, original_hash)
                if is_valid:
                    print("Message integrity verified! Hash matches.")
                else:
                    print("WARNING: Message integrity check failed!")
                    print(f"Expected: {original_hash[:32]}...")
                    print(f"Computed: {computed_hash[:32]}...")

        except Exception as e:
            print(f"Decryption failed: {e}")

    def view_blockchain(self):
        """View full blockchain log."""
        print("\n--- BLOCKCHAIN EXPLORER (research log) ---")
        request = {'command': 'GET_BLOCKCHAIN'}

        if not self._send_request(request):
            print("\nFailed to request blockchain")
            return

        response = self._receive_response()
        if not response or response.get('status') != 'success':
            print("\nFailed to get blockchain")
            return

        blocks = response['blocks']
        print(f"\nTotal blocks: {len(blocks)}\n")
        for block in blocks:
            print("=" * 60)
            print(f"Block #{block['index']}")
            print(f"Timestamp: {block['timestamp']}")
            print(f"Previous Hash: {block['previous_hash'][:32]}...")
            print(f"Block Hash: {block['hash']}")
            print(f"Nonce: {block['nonce']}")
            if block['index'] > 0:
                data = block['data']
                print("\nMessage Data:")
                print(f"  Sender:   {data['sender']}")
                print(f"  Receiver: {data['receiver']}")
                print(f"  Method:   {data['encryption_method']}")
            print()

    def verify_blockchain(self):
        """Verify blockchain integrity."""
        print("\n--- BLOCKCHAIN VERIFICATION ---")
        request = {'command': 'VERIFY_BLOCKCHAIN'}

        if not self._send_request(request):
            print("\nVerification request failed")
            return

        response = self._receive_response()
        if not response or response.get('status') != 'success':
            print("\nVerification failed")
            return

        is_valid = response['is_valid']
        message = response['message']
        length = response['chain_length']

        print(f"\n{message}")
        print(f"Blocks checked: {length}")
        print("Chain integrity:", "INTACT" if is_valid else "COMPROMISED")

    def display_banner(self):
        print("\n" + "=" * 60)
        print(" " * 8 + "ACADEMIC RESEARCH COLLABORATOR - CLIENT")
        print("=" * 60 + "\n")

    def display_menu(self):
        print(f"\n[Logged in as: {self.username}]")
        print("[Transport: Secure Protocol | Message: Research text]")
        print("\n--- MENU ---")
        print("1. Send research message")
        print("2. View my messages")
        print("3. View research blockchain")
        print("4. Verify blockchain")
        print("5. Manual key rotation")
        print("6. Show certificate info")      # NEW
        print("7. Logout")
        print("8. Exit")


    def run(self):
        self.display_banner()
        if not self.connect():
            return

        while True:
            print("\n1. Login")
            print("2. Exit")
            choice = input("\nChoice: ").strip()

            if choice == '1':
                if self.login():
                    break
            elif choice == '2':
                self.disconnect()
                return
            else:
                print("\nInvalid choice")

        while self.running:
            try:
                self.display_menu()
                choice = input("\nChoice > ").strip()

                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.view_messages()
                elif choice == '3':
                    self.view_blockchain()
                elif choice == '4':
                    self.verify_blockchain()
                elif choice == '5':
                    print("\n[Security] Manually rotating keys...")
                    self._rotate_keys()
                elif choice == '6':
                    self.show_certificate_info()       # NEW
                elif choice == '7':
                    print("\nLogging out...")
                    self.disconnect()
                    break
                elif choice == '8':
                    print("\nExiting...")
                    self.disconnect()
                    break


            except KeyboardInterrupt:
                print("\n\nInterrupted. Logging out...")
                self.disconnect()
                break
            except Exception as e:
                print(f"\nError: {e}")


    def show_certificate_info(self):
        """
        Display where the self-signed certificates are stored.
        Certificates are created by the server using core.pki_certs.ensure_certificates().
        """
        print("\n--- CERTIFICATE INFORMATION ---")
        print("Self-signed CA and server certificates are stored on the server side in:")
        print("  certs/ca_key.pem")
        print("  certs/ca_cert.pem")
        print("  certs/server_key.pem")
        print("  certs/server_cert.pem")
        print("\nThese PEM files were generated automatically when the server started.")

def main():
    client = MessageClient(host='127.0.0.1', port=5555)
    try:
        client.run()
    finally:
        if client.connected:
            client.disconnect()


if __name__ == "__main__":
    main()
