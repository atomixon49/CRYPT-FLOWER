"""
Key Storage Module

This module provides functionality for securely storing cryptographic keys
between program executions.
"""

import os
import json
import time
import base64
import hashlib
from typing import Dict, Any, Optional, Union, List
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class KeyStorage:
    """
    Secure storage for cryptographic keys.

    This class provides functionality to securely store and retrieve
    cryptographic keys using a master password for protection.
    """

    def __init__(self, storage_path: str = None):
        """
        Initialize the key storage.

        Args:
            storage_path: Path to the key storage file. If None, uses default location.
        """
        if storage_path is None:
            # Use default location in user's home directory
            home_dir = os.path.expanduser("~")
            storage_dir = os.path.join(home_dir, ".secure_crypto")
            if not os.path.exists(storage_dir):
                os.makedirs(storage_dir)
            self.storage_path = os.path.join(storage_dir, "key_storage.dat")
        else:
            self.storage_path = storage_path

        self.keys: Dict[str, Dict[str, Any]] = {}
        self.metadata: Dict[str, Any] = {
            "version": "1.0",
            "created": time.time(),
            "last_modified": time.time(),
            "key_count": 0
        }
        self.is_loaded = False
        self.is_modified = False
        self.master_key = None
        self.salt = None

    def create_new_storage(self, master_password: str) -> bool:
        """
        Create a new key storage file.

        Args:
            master_password: Master password to protect the storage

        Returns:
            True if successful, False otherwise
        """
        if os.path.exists(self.storage_path):
            try:
                os.remove(self.storage_path)
            except Exception:
                return False

        # Generate a random salt
        self.salt = os.urandom(16)

        # Derive the master key
        self.master_key = self._derive_key(master_password, self.salt)

        # Initialize empty storage
        self.keys = {}
        self.metadata = {
            "version": "1.0",
            "created": time.time(),
            "last_modified": time.time(),
            "key_count": 0
        }

        # Save the storage
        result = self._save_storage()
        if result:
            self.is_loaded = True
        return result

    def load_storage(self, master_password: str) -> bool:
        """
        Load the key storage using the master password.

        Args:
            master_password: Master password to unlock the storage

        Returns:
            True if successful, False otherwise

        Raises:
            FileNotFoundError: If the storage file doesn't exist
            ValueError: If the master password is incorrect
        """
        if not os.path.exists(self.storage_path):
            raise FileNotFoundError(f"Key storage file not found: {self.storage_path}")

        try:
            # Read the file
            with open(self.storage_path, 'rb') as f:
                # First 16 bytes are the salt
                self.salt = f.read(16)
                # Rest is the encrypted data
                encrypted_data = f.read()

            # Derive the master key
            self.master_key = self._derive_key(master_password, self.salt)

            # Decrypt the data
            try:
                # Extract nonce (first 12 bytes) and ciphertext
                nonce = encrypted_data[:12]
                ciphertext_with_tag = encrypted_data[12:]

                # Decrypt
                aesgcm = AESGCM(self.master_key)
                json_data = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

                # Parse JSON
                data = json.loads(json_data.decode('utf-8'))
                self.metadata = data.get('metadata', {})
                serialized_keys = data.get('keys', {})

                # Convert serialized keys back to their original format
                self.keys = {}
                for key_id, key_data in serialized_keys.items():
                    # Create a copy of the key data
                    deserialized_key_data = key_data.copy()
                    # Convert base64 strings back to bytes
                    if 'key' in deserialized_key_data and 'key_format' in deserialized_key_data:
                        if deserialized_key_data['key_format'] == 'base64':
                            deserialized_key_data['key'] = base64.b64decode(deserialized_key_data['key'])
                            del deserialized_key_data['key_format']
                    self.keys[key_id] = deserialized_key_data

                self.is_loaded = True
                return True
            except Exception as e:
                raise ValueError(f"Failed to decrypt storage: {str(e)}. The master password may be incorrect.")
        except Exception as e:
            raise ValueError(f"Failed to load key storage: {str(e)}")

    def add_key(self, key_id: str, key_data: Dict[str, Any]) -> bool:
        """
        Add a key to the storage.

        Args:
            key_id: Unique identifier for the key
            key_data: Dictionary containing key data and metadata

        Returns:
            True if successful, False otherwise
        """
        if not self.is_loaded:
            return False

        # Add the key
        self.keys[key_id] = key_data

        # Update metadata
        self.metadata["last_modified"] = time.time()
        self.metadata["key_count"] = len(self.keys)

        self.is_modified = True
        return True

    def get_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a key from the storage.

        Args:
            key_id: Unique identifier for the key

        Returns:
            The key data dictionary, or None if not found
        """
        if not self.is_loaded:
            return None

        return self.keys.get(key_id)

    def remove_key(self, key_id: str) -> bool:
        """
        Remove a key from the storage.

        Args:
            key_id: Unique identifier for the key

        Returns:
            True if successful, False otherwise
        """
        if not self.is_loaded or key_id not in self.keys:
            return False

        # Remove the key
        del self.keys[key_id]

        # Update metadata
        self.metadata["last_modified"] = time.time()
        self.metadata["key_count"] = len(self.keys)

        self.is_modified = True
        return True

    def save(self) -> bool:
        """
        Save the key storage to disk.

        Returns:
            True if successful, False otherwise
        """
        if not self.is_loaded or not self.is_modified:
            return False

        return self._save_storage()

    def change_master_password(self, current_password: str, new_password: str) -> bool:
        """
        Change the master password.

        Args:
            current_password: Current master password
            new_password: New master password

        Returns:
            True if successful, False otherwise
        """
        if not self.is_loaded:
            return False

        # Verify current password
        test_key = self._derive_key(current_password, self.salt)
        if test_key != self.master_key:
            return False

        # Generate new salt
        self.salt = os.urandom(16)

        # Derive new master key
        self.master_key = self._derive_key(new_password, self.salt)

        # Save with new master key
        self.is_modified = True
        return self._save_storage()

    def _save_storage(self) -> bool:
        """
        Save the storage to disk.

        Returns:
            True if successful, False otherwise
        """
        try:
            # Prepare data with serializable keys
            serializable_keys = {}
            for key_id, key_data in self.keys.items():
                # Create a copy of the key data
                serializable_key_data = key_data.copy()
                # Convert bytes to base64 strings
                if 'key' in serializable_key_data and isinstance(serializable_key_data['key'], bytes):
                    serializable_key_data['key'] = base64.b64encode(serializable_key_data['key']).decode('ascii')
                    serializable_key_data['key_format'] = 'base64'
                serializable_keys[key_id] = serializable_key_data

            data = {
                'metadata': self.metadata,
                'keys': serializable_keys
            }

            # Convert to JSON
            json_data = json.dumps(data).encode('utf-8')

            # Encrypt the data
            aesgcm = AESGCM(self.master_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, json_data, None)

            # Write to file
            with open(self.storage_path, 'wb') as f:
                # Write salt
                f.write(self.salt)
                # Write nonce
                f.write(nonce)
                # Write encrypted data
                f.write(ciphertext)

            self.is_modified = False
            return True
        except Exception as e:
            print(f"Failed to save key storage: {str(e)}")
            return False

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a key from a password and salt.

        Args:
            password: The password
            salt: The salt

        Returns:
            The derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        try:
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            print(f"Error deriving key: {str(e)}")
            return b''

    def list_keys(self) -> List[Dict[str, Any]]:
        """
        List all keys in the storage.

        Returns:
            List of dictionaries containing key metadata
        """
        if not self.is_loaded:
            return []

        result = []
        for key_id, key_data in self.keys.items():
            # Create a copy without the actual key material
            key_info = key_data.copy()
            if 'key' in key_info:
                del key_info['key']
            key_info['id'] = key_id
            result.append(key_info)

        return result

    def close(self) -> bool:
        """
        Close the key storage, saving if necessary.

        Returns:
            True if successful, False otherwise
        """
        if self.is_loaded and self.is_modified:
            return self._save_storage()
        return True
