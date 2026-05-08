"""
Blockchain Module
Blockchain for message logging with immutability and non-repudiation
Each encrypted message is stored as a block in the blockchain
"""

import hashlib
import json
from datetime import datetime


class Block:
    """
    Represents a single block in the blockchain
    Contains message transaction data
    """
    
    def __init__(self, index, timestamp, data, previous_hash):
        """
        Initialize a block
        
        Args:
            index: Position of block in chain
            timestamp: When the block was created
            data: Dictionary containing message data
            previous_hash: Hash of the previous block
        """
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """
        Calculate SHA-256 hash of the block
        Ensures immutability
        """
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty=2):
        """
        Proof of Work: Mine block with specified difficulty
        Difficulty determines number of leading zeros required
        """
        target = "0" * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        
        return self.hash
    
    def to_dict(self):
        """Convert block to dictionary for serialization"""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
            "nonce": self.nonce
        }


class MessageBlockchain:
    """
    Blockchain for storing encrypted messages
    Provides immutability and non-repudiation
    """
    
    def __init__(self, difficulty=2, storage=None):
        """
        Initialize blockchain with genesis block
        
        Args:
            difficulty: Mining difficulty (number of leading zeros)
            storage: SecureStorage instance for temporary persistence
        """
        self.chain = []
        self.difficulty = difficulty
        self.storage = storage
        
        if self.storage:
            loaded_chain = self.storage.load_blockchain_temp()
            if loaded_chain:
                self._restore_from_dict(loaded_chain)
                return
        
        self.create_genesis_block()
    
    def _restore_from_dict(self, chain_data):
        """Restore blockchain from dictionary data"""
        for block_data in chain_data:
            block = Block(
                index=block_data['index'],
                timestamp=block_data['timestamp'],
                data=block_data['data'],
                previous_hash=block_data['previous_hash']
            )
            block.nonce = block_data['nonce']
            block.hash = block_data['hash']
            self.chain.append(block)
    
    def _save_to_storage(self):
        """Save blockchain to temporary storage"""
        if self.storage:
            chain_data = [block.to_dict() for block in self.chain]
            self.storage.save_blockchain_temp(chain_data)
    
    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_block = Block(
            index=0,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data={
                "sender": "System",
                "receiver": "System",
                "message": "Genesis Block",
                "hash": "0" * 64
            },
            previous_hash="0"
        )
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)
    
    def get_latest_block(self):
        """Return the most recent block in the chain"""
        return self.chain[-1]
    
    def add_message_block(self, sender, receiver, ciphertext, message_hash, encryption_method):
        """
        Add a new message block to the blockchain
        
        Args:
            sender: Username of sender
            receiver: Username of receiver
            ciphertext: Encrypted message
            message_hash: SHA-256 hash of original plaintext
            encryption_method: Cipher used for encryption
        
        Returns:
            The newly created block
        """
        previous_block = self.get_latest_block()
        
        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data={
                "sender": sender,
                "receiver": receiver,
                "ciphertext": ciphertext,
                "message_hash": message_hash,
                "encryption_method": encryption_method
            },
            previous_hash=previous_block.hash
        )
        
        new_block.mine_block(self.difficulty)
        
        self.chain.append(new_block)
        
        self._save_to_storage()
        
        return new_block
    
    def add_block(self, data):
        """
        Add a generic block to the blockchain (for test compatibility)
        
        Args:
            data: Dictionary containing block data
        
        Returns:
            The newly created block
        """
        previous_block = self.get_latest_block()
        
        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data=data,
            previous_hash=previous_block.hash
        )
        
        new_block.mine_block(self.difficulty)
        
        self.chain.append(new_block)
        
        self._save_to_storage()
        
        return new_block
    
    def is_chain_valid(self):
        """
        Verify the integrity of the entire blockchain
        Checks:
        1. Each block's hash is valid
        2. Each block correctly references previous block
        
        Returns:
            tuple: (is_valid, message) for server compatibility
        """
        if len(self.chain) == 0:
            return (False, "Blockchain is empty")
        
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Recalculate hash to verify integrity
            # Create a temporary block to recalculate the hash properly
            temp_block = Block(
                index=current_block.index,
                timestamp=current_block.timestamp,
                data=current_block.data,
                previous_hash=current_block.previous_hash
            )
            temp_block.nonce = current_block.nonce
            recalculated_hash = temp_block.calculate_hash()
            
            if current_block.hash != recalculated_hash:
                return (False, f"Block {i} has invalid hash")
            
            # Check chain linkage
            if current_block.previous_hash != previous_block.hash:
                return (False, f"Block {i} has invalid previous_hash reference")
        
        return (True, f"Blockchain is valid ({len(self.chain)} blocks)")
    
    def get_messages_for_user(self, username):
        """
        Retrieve all messages sent to or from a specific user
        
        Args:
            username: Username to filter messages
        
        Returns:
            List of blocks containing messages for the user
        """
        user_messages = []
        
        for block in self.chain[1:]:  # Skip genesis block
            if (block.data.get("sender") == username or 
                block.data.get("receiver") == username):
                user_messages.append(block)
        
        return user_messages
    
    def get_block_by_index(self, index):
        """Retrieve a specific block by index"""
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None
    
    def display_chain(self):
        """Display the entire blockchain"""
        for block in self.chain:
            print(f"\n{'='*60}")
            print(f"Block #{block.index}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Data: {json.dumps(block.data, indent=2)}")
            print(f"Previous Hash: {block.previous_hash}")
            print(f"Hash: {block.hash}")
            print(f"Nonce: {block.nonce}")
    
    def get_chain_length(self):
        """Return the number of blocks in the chain"""
        return len(self.chain)
    
    def export_chain(self):
        """Export blockchain to JSON format"""
        return json.dumps([block.to_dict() for block in self.chain], indent=2)
