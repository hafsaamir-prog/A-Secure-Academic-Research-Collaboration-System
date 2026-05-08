"""
Academic Research Collaborator - Server

Two default collaborators:
  - hafsa / hafsa123
  - amna  / amna123
"""

import socket
import threading
import json
from datetime import datetime

from core.authentication import UserAuthentication
from core.classical_ciphers import CaesarCipher, VigenereCipher
from core.modern_ciphers import XORStreamCipher, MiniBlockCipher
from core.hashing import MessageIntegrity
from core.blockchain import MessageBlockchain
from core.elgamal import ElGamal, KeyDistributionCenter, ElGamalKeyPair
from core.storage import SecureStorage
from core.secure_protocol import SecureProtocol
from core.pki_certs import ensure_certificates


class MessageServer:
    """
    Multi-threaded server for academic research collaborators
    """

    def __init__(self, host='127.0.0.1', port=5555):
        #PKI: generate or load certificates ----
        cert_info = ensure_certificates()
        self.ca_cert_path = cert_info["ca_cert"]
        self.server_cert_path = cert_info["server_cert"]
        self.server_key_path = cert_info["server_key"]

        self.host = host
        self.port = port

        self.server_socket = None
        self.running = False

        self.storage = SecureStorage(data_dir="data")
        self.auth = UserAuthentication(storage=self.storage)
        self.kdc = KeyDistributionCenter()
        self.blockchain = MessageBlockchain(difficulty=2, storage=self.storage)

        self.user_keys = {}
        stored_keys = self.storage.load_user_keys()

        # Rebuild user_keys and KDC from stored keys
        for username, key_data in stored_keys.items():
            if isinstance(key_data, dict):
                key_obj = ElGamalKeyPair(
                    p=key_data['p'],
                    g=key_data['g'],
                    private_key=key_data['private_key'],
                    public_key=key_data['public_key']
                )
                self.user_keys[username] = key_obj
                self.kdc.register_user(username, key_obj)

        # Ensure every auth user has keys and is in KDC
        for username in self.auth.users.keys():
            if username not in self.user_keys:
                # generate missing ElGamal keys
                key_pair = ElGamal.generate_keys(bits=16)
                self.user_keys[username] = key_pair
                self.kdc.register_user(username, key_pair)

        # Save updated keys if we added any
        if self.user_keys and stored_keys != self.user_keys:
            self.storage.save_user_keys(self.user_keys)


        self.protocol = SecureProtocol(is_server=True)

        self.clients = {}   # {username: (socket, session_id)}
        self.sessions = {}  # {session_id: username}
        self.client_threads = []
        self.lock = threading.Lock()

        self._setup_demo_users()

    def _setup_demo_users(self):
        """
        Create Hafsa and Amna if no users exist yet.
        """
        if len(self.auth.users) > 0:
            print(f"Found {len(self.auth.users)} existing users in storage.")
            return

        demo_users = [
            ("hafsa", "hafsa123", "hafsa@example.com"),
            ("amna",  "amna123",  "amna@example.com"),
        ]

        print("Setting up research collaborators (Hafsa, Amna)...")
        for username, password, email in demo_users:
            success, _ = self.auth.register_user(username, password, email)
            if success:
                key_pair = ElGamal.generate_keys(bits=16)
                self.user_keys[username] = key_pair
                self.kdc.register_user(username, key_pair)
                print(f"Research user '{username}' registered")

        if self.user_keys:
            self.storage.save_user_keys(self.user_keys)
            print("User keys saved to storage")

    def start(self):
        """Start the server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            print("\n" + "=" * 60)
            print(" " * 10 + "ACADEMIC RESEARCH COLLABORATOR - SERVER")
            print("=" * 60)
            print(f"\nServer started on {self.host}:{self.port}")
            print("\nWaiting for collaborators to connect...")
            print("Press Ctrl+C to stop the server\n")

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] New connection from {address}")

                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.client_threads.append(client_thread)

                except KeyboardInterrupt:
                    print("\n\nServer shutting down...")
                    break
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection: {e}")
        except Exception as e:
            print(f"Error starting server: {e}")
        finally:
            self.stop()

    def _handle_client(self, client_socket, address):
        """Handle individual client."""
        username = None
        session_id = None
        secure_mode = False

        try:
            client_socket.settimeout(10.0)

            while self.running:
                try:
                    data = client_socket.recv(32768)
                    if not data:
                        break

                    request = json.loads(data.decode('utf-8'))
                    msg_type = request.get('type')
                    command = request.get('command')

                    if msg_type == 'HANDSHAKE_INIT':
                        print(f"[Security] DH handshake initiated from {address}")
                        response = self._handle_handshake(request)
                        session_id = request['session_id']
                        secure_mode = True
                        self._send_response(client_socket, response)
                        continue

                    elif msg_type == 'SECURE_MESSAGE' and secure_mode:
                        response = self._handle_secure_message(request, session_id, client_socket)
                        self._send_response(client_socket, response)
                        continue

                    elif msg_type == 'KEY_ROTATION' and secure_mode:
                        print(f"[Security] Key rotation requested for session {session_id}")
                        response = self._handle_key_rotation(request)
                        self._send_response(client_socket, response)
                        continue

                    if command == 'LOGIN':
                        response = self._handle_login(request, client_socket, session_id)
                        if response['status'] == 'success':
                            username = request['username']

                    elif command == 'REGISTER':
                        response = {
                            'status': 'error',
                            'message': 'Registration disabled. Use hafsa/amna accounts.'
                        }

                    elif command == 'SEND_MESSAGE':
                        response = self._handle_send_message(request)

                    elif command == 'GET_MESSAGES':
                        response = self._handle_get_messages(request)

                    elif command == 'GET_USERS':
                        response = self._handle_get_users(request)

                    elif command == 'VERIFY_BLOCKCHAIN':
                        response = self._handle_verify_blockchain()

                    elif command == 'GET_BLOCKCHAIN':
                        response = self._handle_get_blockchain()

                    elif command == 'LOGOUT':
                        response = {'status': 'success', 'message': 'Logged out'}
                        self._send_response(client_socket, response)
                        break

                    else:
                        response = {'status': 'error', 'message': 'Unknown command'}

                    self._send_response(client_socket, response)

                except socket.timeout:
                    continue
                except json.JSONDecodeError:
                    self._send_response(client_socket, {'status': 'error', 'message': 'Invalid JSON'})

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            if session_id and session_id in self.protocol.sessions:
                self.protocol.destroy_session(session_id)
                print(f"[Security] Session {session_id} destroyed (forward secrecy)")

            if username:
                with self.lock:
                    if username in self.clients:
                        del self.clients[username]
                    if session_id and session_id in self.sessions:
                        del self.sessions[session_id]
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} disconnected")

            client_socket.close()

    def _send_response(self, client_socket, response):
        try:
            response_json = json.dumps(response)
            client_socket.send(response_json.encode('utf-8'))
        except Exception as e:
            print(f"Error sending response: {e}")

    def _handle_handshake(self, request):
        try:
            handshake_response, session = self.protocol.respond_to_handshake(request)
            session_id = request['session_id']
            self.sessions[session_id] = None
            return handshake_response
        except Exception as e:
            return {'status': 'error', 'message': f'Handshake failed: {str(e)}'}

    def _handle_secure_message(self, request, session_id, client_socket=None):
        try:
            if session_id not in self.protocol.sessions:
                return {'status': 'error', 'message': 'Invalid session'}

            decrypted = self.protocol.receive_secure_message(session_id, request)
            command_data = json.loads(decrypted)

            response = self._process_command(command_data, session_id, client_socket)

            response_json = json.dumps(response)
            encrypted_response = self.protocol.send_secure_message(
                session_id, response_json, {'response_to': command_data.get('command')}
            )
            return encrypted_response
        except Exception as e:
            return {'status': 'error', 'message': f'Secure message failed: {str(e)}'}

    def _handle_key_rotation(self, request):
        try:
            session_id = request['session_id']
            rotation_response = self.protocol.rotate_session_key(session_id)
            self.protocol.complete_key_rotation(session_id, request)
            return rotation_response
        except Exception as e:
            return {'status': 'error', 'message': f'Key rotation failed: {str(e)}'}

    def _process_command(self, request, session_id, client_socket=None):
        command = request.get('command')

        if command == 'LOGIN':
            return self._handle_login(request, client_socket, session_id)
        elif command == 'REGISTER':
            return {
                'status': 'error',
                'message': 'Registration disabled. Use hafsa/amna accounts.'
            }
        elif command == 'SEND_MESSAGE':
            return self._handle_send_message(request)
        elif command == 'GET_MESSAGES':
            return self._handle_get_messages(request)
        elif command == 'GET_USERS':
            return self._handle_get_users(request)
        elif command == 'VERIFY_BLOCKCHAIN':
            return self._handle_verify_blockchain()
        elif command == 'GET_BLOCKCHAIN':
            return self._handle_get_blockchain()
        else:
            return {'status': 'error', 'message': 'Unknown command'}

    def _handle_login(self, request, client_socket, session_id=None):
        username = request.get('username')
        password = request.get('password')

        success, message = self.auth.login(username, password)
        if success:
            with self.lock:
                if client_socket:
                    self.clients[username] = (client_socket, session_id)
                if session_id:
                    self.sessions[session_id] = username

            auth_session_id = message.split(": ")[1] if ": " in message else None
            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] {username} logged in" +
                (f" (secure session: {session_id})" if session_id else "")
            )

            return {
                'status': 'success',
                'message': 'Login successful',
                'session_id': auth_session_id or session_id,
                'username': username,
                'secure_session': session_id is not None
            }
        else:
            return {'status': 'error', 'message': message}

    def _handle_send_message(self, request):
        sender = request.get('sender')
        receiver = request.get('receiver')
        plaintext = request.get('plaintext')
        encryption_method = request.get('encryption_method')
        encryption_params = request.get('encryption_params', {})

        if not self.kdc.is_user_registered(receiver):
            return {'status': 'error', 'message': f"User '{receiver}' not found"}

        try:
            ciphertext = None
            normalized_plaintext = plaintext

            if encryption_method == 'Caesar':
                shift = encryption_params.get('shift', 3)
                cipher = CaesarCipher(shift=shift)
                ciphertext = cipher.encrypt(plaintext)
                normalized_plaintext = plaintext.upper()

            elif encryption_method == 'Vigenere':
                key = encryption_params.get('key', 'KEY')
                cipher = VigenereCipher(key=key)
                ciphertext = cipher.encrypt(plaintext)
                normalized_plaintext = plaintext

            elif encryption_method == 'XOR':
                key = encryption_params.get('key')
                cipher = XORStreamCipher(key=key if key else None)
                ciphertext = cipher.encrypt(plaintext)
                encryption_params['key_hex'] = cipher.get_key_hex()
                normalized_plaintext = plaintext

            elif encryption_method == 'Block':
                key = encryption_params.get('key')
                cipher = MiniBlockCipher(key=key if key else None)
                ciphertext = cipher.encrypt(plaintext)
                encryption_params['key_hex'] = cipher.get_key_hex()
                normalized_plaintext = plaintext

            else:
                return {'status': 'error', 'message': 'Invalid encryption method'}

            message_hash = MessageIntegrity.compute_hash(normalized_plaintext)

            with self.lock:
                block = self.blockchain.add_message_block(
                    sender=sender,
                    receiver=receiver,
                    ciphertext=str(ciphertext),
                    message_hash=message_hash,
                    encryption_method=encryption_method
                )

            print(f"[{datetime.now().strftime('%H:%M:%S')}] Message: {sender} -> {receiver} (Block #{block.index})")

            if receiver in self.clients:
                notification = {
                    'type': 'NEW_MESSAGE',
                    'from': sender,
                    'timestamp': block.timestamp
                }
                try:
                    receiver_socket = self.clients[receiver][0]
                    self._send_response(receiver_socket, notification)
                except Exception:
                    pass

            return {
                'status': 'success',
                'message': 'Message sent successfully',
                'block_index': block.index,
                'block_hash': block.hash,
                'message_hash': message_hash,
                'encryption_params': encryption_params
            }

        except Exception as e:
            return {'status': 'error', 'message': f'Encryption failed: {str(e)}'}

    def _handle_get_messages(self, request):
        username = request.get('username')

        with self.lock:
            messages = self.blockchain.get_messages_for_user(username)
            message_list = []
            for block in messages:
                data = block.data
                message_list.append({
                    'block_index': block.index,
                    'timestamp': block.timestamp,
                    'sender': data['sender'],
                    'receiver': data['receiver'],
                    'ciphertext': data['ciphertext'],
                    'message_hash': data['message_hash'],
                    'encryption_method': data['encryption_method'],
                    'block_hash': block.hash
                })

        return {
            'status': 'success',
            'messages': message_list,
            'count': len(message_list)
        }

    def _handle_get_users(self, request):
        current_user = request.get('username')

        with self.lock:
            all_users = self.kdc.list_registered_users()
            online_users = list(self.clients.keys())
            available_users = [u for u in all_users if u != current_user]

        return {
            'status': 'success',
            'users': available_users,
            'online_users': online_users
        }

    def _handle_verify_blockchain(self):
        with self.lock:
            is_valid, message = self.blockchain.is_chain_valid()
            return {
                'status': 'success',
                'is_valid': is_valid,
                'message': message,
                'chain_length': self.blockchain.get_chain_length()
            }

    def _handle_get_blockchain(self):
        with self.lock:
            blocks = []
            for block in self.blockchain.chain:
                blocks.append({
                    'index': block.index,
                    'timestamp': block.timestamp,
                    'data': block.data,
                    'previous_hash': block.previous_hash,
                    'hash': block.hash,
                    'nonce': block.nonce
                })
            return {
                'status': 'success',
                'blocks': blocks,
                'chain_length': len(blocks)
            }

    def stop(self):
        self.running = False
        with self.lock:
            for username, (client_socket, _) in self.clients.items():
                try:
                    client_socket.close()
                except Exception:
                    pass
            self.clients.clear()

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        print("\nServer stopped")


def main():
    server = MessageServer(host='127.0.0.1', port=5555)
    try:
        server.start()
    finally:
        server.stop()


if __name__ == "__main__":
    main()
