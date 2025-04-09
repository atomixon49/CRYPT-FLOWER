"""
Tests for the key management module.
"""

import unittest
import time
from src.core.key_management import KeyManager

class TestKeyManagement(unittest.TestCase):
    """Test cases for the key management module."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key_manager = KeyManager()
    
    def test_generate_symmetric_key(self):
        """Test generating a symmetric key."""
        # Generate an AES-256 key
        key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        
        # Verify the key
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 32)  # 256 bits = 32 bytes
        
        # Verify that the key is stored in the key manager
        self.assertEqual(len(self.key_manager.active_keys), 1)
        
        # Get the key ID
        key_id = list(self.key_manager.active_keys.keys())[0]
        
        # Verify the key metadata
        key_data = self.key_manager.active_keys[key_id]
        self.assertEqual(key_data['algorithm'], 'AES')
        self.assertEqual(key_data['key_size'], 256)
        self.assertEqual(key_data['key'], key)
        self.assertEqual(key_data['purpose'], 'symmetric_encryption')
    
    def test_generate_multiple_keys(self):
        """Test generating multiple keys."""
        # Generate keys
        key1 = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=128)
        key2 = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=192)
        key3 = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        
        # Verify the keys
        self.assertIsNotNone(key1)
        self.assertIsNotNone(key2)
        self.assertIsNotNone(key3)
        
        self.assertEqual(len(key1), 16)  # 128 bits = 16 bytes
        self.assertEqual(len(key2), 24)  # 192 bits = 24 bytes
        self.assertEqual(len(key3), 32)  # 256 bits = 32 bytes
        
        # Verify that all keys are stored in the key manager
        self.assertEqual(len(self.key_manager.active_keys), 3)
    
    def test_get_key(self):
        """Test retrieving a key by ID."""
        # Generate a key
        key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        
        # Get the key ID
        key_id = list(self.key_manager.active_keys.keys())[0]
        
        # Retrieve the key
        retrieved_key = self.key_manager.get_key(key_id)
        
        # Verify the retrieved key
        self.assertEqual(retrieved_key, key)
    
    def test_get_nonexistent_key(self):
        """Test retrieving a nonexistent key."""
        # Try to retrieve a nonexistent key
        retrieved_key = self.key_manager.get_key('nonexistent')
        
        # Verify that None is returned
        self.assertIsNone(retrieved_key)
    
    def test_derive_key_from_password(self):
        """Test deriving a key from a password."""
        # Derive a key
        password = 'test-password'
        key, salt = self.key_manager.derive_key_from_password(password)
        
        # Verify the key and salt
        self.assertIsNotNone(key)
        self.assertIsNotNone(salt)
        self.assertEqual(len(key), 32)  # 256 bits = 32 bytes
        
        # Derive the key again with the same salt
        key2, _ = self.key_manager.derive_key_from_password(password, salt)
        
        # Verify that the keys match
        self.assertEqual(key, key2)
        
        # Derive a key with a different password
        key3, _ = self.key_manager.derive_key_from_password('different-password', salt)
        
        # Verify that the keys don't match
        self.assertNotEqual(key, key3)
    
    def test_rotate_keys(self):
        """Test key rotation."""
        # Generate keys
        self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        
        # Get the key ID and original key
        key_id = list(self.key_manager.active_keys.keys())[0]
        original_key = self.key_manager.active_keys[key_id]['key']
        
        # Modify the creation time to make the key old
        self.key_manager.active_keys[key_id]['created'] = time.time() - 91 * 24 * 60 * 60  # 91 days old
        
        # Rotate keys
        rotated_keys = self.key_manager.rotate_keys(max_age_days=90)
        
        # Verify that the key was rotated
        self.assertEqual(len(rotated_keys), 1)
        self.assertEqual(rotated_keys[0], key_id)
        
        # Verify that the key was changed
        new_key = self.key_manager.active_keys[key_id]['key']
        self.assertNotEqual(original_key, new_key)
    
    def test_secure_erase(self):
        """Test securely erasing a key."""
        # Generate a key
        self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        
        # Get the key ID
        key_id = list(self.key_manager.active_keys.keys())[0]
        
        # Verify that the key exists
        self.assertIn(key_id, self.key_manager.active_keys)
        
        # Erase the key
        result = self.key_manager.secure_erase(key_id)
        
        # Verify that the key was erased
        self.assertTrue(result)
        self.assertNotIn(key_id, self.key_manager.active_keys)
        
        # Try to erase a nonexistent key
        result = self.key_manager.secure_erase('nonexistent')
        
        # Verify that the operation failed
        self.assertFalse(result)
    
    def test_invalid_algorithm(self):
        """Test generating a key with an invalid algorithm."""
        # Try to generate a key with an invalid algorithm
        with self.assertRaises(ValueError):
            self.key_manager.generate_symmetric_key(algorithm='INVALID', key_size=256)
    
    def test_invalid_key_size(self):
        """Test generating a key with an invalid key size."""
        # Try to generate a key with an invalid key size
        with self.assertRaises(ValueError):
            self.key_manager.generate_symmetric_key(algorithm='AES', key_size=123)


if __name__ == '__main__':
    unittest.main()
