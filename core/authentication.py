"""
User Authentication Module
Python basics, collections (dictionaries), conditionals
Handles user registration and login using secure credential storage
"""

import hashlib
from datetime import datetime


class UserAuthentication:
    """Manages user registration and authentication"""
    
    def __init__(self, storage=None):
        self.users = {}
        self.active_sessions = {}
        self.sessions = self.active_sessions  # Alias for test compatibility
        self.storage = storage
        
        if self.storage:
            loaded_users = self.storage.load_users()
            for username, user_data in loaded_users.items():
                if 'password_hash' in user_data:
                    user_data['password'] = user_data.pop('password_hash')
            self.users = loaded_users
    
    def _hash_password(self, password):
        """Hash password using SHA-256 for secure storage"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _save_users(self):
        """Save users to storage if available"""
        if self.storage:
            storage_users = {}
            for username, user_data in self.users.items():
                storage_data = user_data.copy()
                if 'password' in storage_data:
                    storage_data['password_hash'] = storage_data.pop('password')
                storage_users[username] = storage_data
            self.storage.save_users(storage_users)
    
    def register_user(self, username, password, email=""):
        """
        Register a new user
        Returns: (success: bool, message: str)
        """
        if not username or not password:
            return False, "Username and password required"
        
        if username in self.users:
            return False, "Username already exists"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters"
        
        self.users[username] = {
            'password': self._hash_password(password),
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'email': email,
            'login_count': 0
        }
        
        self._save_users()
        
        return True, "Registration successful"
    
    def register(self, username, password, email=""):
        """Alias for register_user for test compatibility"""
        return self.register_user(username, password, email)
    
    def login(self, username, password):
        """
        Authenticate user login
        Returns: (success: bool, message: str)
        """
        if username not in self.users:
            return False, "Invalid username or password"
        
        password_hash = self._hash_password(password)
        if self.users[username]['password'] != password_hash:
            return False, "Invalid username or password"
        
        session_id = hashlib.sha256(f"{username}{datetime.now()}".encode()).hexdigest()[:16]
        self.active_sessions[session_id] = {
            'username': username,
            'login_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.active_sessions[username] = {
            'username': username,
            'login_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.users[username]['login_count'] += 1
        
        self._save_users()
        
        return True, f"Login successful. Session ID: {session_id}"
    
    def logout(self, session_id_or_username):
        """
        Logout user and end session
        Accepts either session_id or username for compatibility
        """
        if session_id_or_username in self.active_sessions:
            username = self.active_sessions[session_id_or_username]['username']
            del self.active_sessions[session_id_or_username]
            return True, f"User '{username}' logged out successfully"
        
        for session_id, session_data in list(self.active_sessions.items()):
            if session_data['username'] == session_id_or_username:
                del self.active_sessions[session_id]
                return True, f"User '{session_id_or_username}' logged out successfully"
        
        return False, "Invalid session"
    
    def get_user_info(self, username):
        """Get user information (excluding password hash)"""
        if username not in self.users:
            return None
        
        user_info = self.users[username].copy()
        user_info.pop('password', None)  # Remove password hash
        return user_info
    
    def is_session_active(self, session_id):
        """Check if a session is active"""
        return session_id in self.active_sessions
    
    def get_username_from_session(self, session_id):
        """Get username from session ID"""
        if session_id in self.active_sessions:
            return self.active_sessions[session_id]['username']
        return None
    
    def list_users(self):
        """List all registered users (for admin purposes)"""
        return list(self.users.keys())
    
    def change_password(self, username, old_password, new_password):
        """Change user password"""
        if username not in self.users:
            return False, "User not found"
        
        old_hash = self._hash_password(old_password)
        if self.users[username]['password_hash'] != old_hash:
            return False, "Incorrect old password"
        
        if len(new_password) < 6:
            return False, "New password must be at least 6 characters long"
        
        self.users[username]['password_hash'] = self._hash_password(new_password)
        
        self._save_users()
        
        return True, "Password changed successfully"
