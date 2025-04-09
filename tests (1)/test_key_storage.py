"""
Tests for the key storage module.
"""

import unittest
import os
import tempfile
import shutil
from src.core.key_storage import KeyStorage

class TestKeyStorage(unittest.TestCase):
    """Test cases for the key storage module."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.storage_path = os.path.join(self.test_dir, "test_key_storage.dat")
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        shutil.rmtree(self.test_dir)
    
    def test_create_new_storage(self):
        """Test creating a new key storage."""
        # Create a new key storage
        storage = KeyStorage(self.storage_path)
        result = storage.create_new_storage("test-password")
        
        # Verify the result
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.storage_path))
        
        # Verify that the storage is loaded
        self.assertTrue(storage.is_loaded)
        self.assertFalse(storage.is_modified)
        self.assertEqual(storage.metadata["key_count"], 0)
    
    def test_add_and_get_key(self):
        """Test adding and retrieving a key."""
        # Create a new key storage
        storage = KeyStorage(self.storage_path)
        storage.create_new_storage("test-password")
        
        # Add a key
        key_data = {
            "algorithm": "AES",
            "key_size": 256,
            "created": 1234567890,
            "key": b"test-key-data",
            "purpose": "test"
        }
        result = storage.add_key("test-key-id", key_data)
        
        # Verify the result
        self.assertTrue(result)
        self.assertTrue(storage.is_modified)
        
        # Get the key
        retrieved_key = storage.get_key("test-key-id")
        
        # Verify the retrieved key
        self.assertIsNotNone(retrieved_key)
        self.assertEqual(retrieved_key["algorithm"], "AES")
        self.assertEqual(retrieved_key["key_size"], 256)
        self.assertEqual(retrieved_key["created"], 1234567890)
        self.assertEqual(retrieved_key["key"], b"test-key-data")
        self.assertEqual(retrieved_key["purpose"], "test")
    
    def test_save_and_load_storage(self):
        """Test saving and loading key storage."""
        # Create a new key storage
        storage1 = KeyStorage(self.storage_path)
        storage1.create_new_storage("test-password")
        
        # Add a key
        key_data = {
            "algorithm": "AES",
            "key_size": 256,
            "created": 1234567890,
            "key": b"test-key-data",
            "purpose": "test"
        }
        storage1.add_key("test-key-id", key_data)
        
        # Save the storage
        result = storage1.save()
        self.assertTrue(result)
        
        # Create a new storage object and load the saved storage
        storage2 = KeyStorage(self.storage_path)
        result = storage2.load_storage("test-password")
        
        # Verify the result
        self.assertTrue(result)
        self.assertTrue(storage2.is_loaded)
        self.assertFalse(storage2.is_modified)
        
        # Verify that the key was loaded
        retrieved_key = storage2.get_key("test-key-id")
        self.assertIsNotNone(retrieved_key)
        self.assertEqual(retrieved_key["algorithm"], "AES")
        self.assertEqual(retrieved_key["key_size"], 256)
        self.assertEqual(retrieved_key["created"], 1234567890)
        self.assertEqual(retrieved_key["key"], b"test-key-data")
        self.assertEqual(retrieved_key["purpose"], "test")
    
    def test_wrong_password(self):
        """Test loading storage with wrong password."""
        # Create a new key storage
        storage1 = KeyStorage(self.storage_path)
        storage1.create_new_storage("test-password")
        storage1.add_key("test-key-id", {"key": b"test-key-data"})
        storage1.save()
        
        # Try to load with wrong password
        storage2 = KeyStorage(self.storage_path)
        with self.assertRaises(ValueError):
            storage2.load_storage("wrong-password")
    
    def test_change_master_password(self):
        """Test changing the master password."""
        # Create a new key storage
        storage = KeyStorage(self.storage_path)
        storage.create_new_storage("old-password")
        
        # Add a key
        key_data = {
            "algorithm": "AES",
            "key_size": 256,
            "created": 1234567890,
            "key": b"test-key-data",
            "purpose": "test"
        }
        storage.add_key("test-key-id", key_data)
        
        # Change the master password
        result = storage.change_master_password("old-password", "new-password")
        self.assertTrue(result)
        
        # Save the storage
        storage.save()
        
        # Try to load with old password
        storage2 = KeyStorage(self.storage_path)
        with self.assertRaises(ValueError):
            storage2.load_storage("old-password")
        
        # Load with new password
        result = storage2.load_storage("new-password")
        self.assertTrue(result)
        
        # Verify that the key was loaded
        retrieved_key = storage2.get_key("test-key-id")
        self.assertIsNotNone(retrieved_key)
        self.assertEqual(retrieved_key["key"], b"test-key-data")
    
    def test_remove_key(self):
        """Test removing a key."""
        # Create a new key storage
        storage = KeyStorage(self.storage_path)
        storage.create_new_storage("test-password")
        
        # Add a key
        storage.add_key("test-key-id", {"key": b"test-key-data"})
        
        # Verify that the key exists
        self.assertIsNotNone(storage.get_key("test-key-id"))
        
        # Remove the key
        result = storage.remove_key("test-key-id")
        self.assertTrue(result)
        
        # Verify that the key was removed
        self.assertIsNone(storage.get_key("test-key-id"))
        
        # Verify metadata
        self.assertEqual(storage.metadata["key_count"], 0)
    
    def test_list_keys(self):
        """Test listing keys."""
        # Create a new key storage
        storage = KeyStorage(self.storage_path)
        storage.create_new_storage("test-password")
        
        # Add keys
        storage.add_key("key1", {"algorithm": "AES", "key_size": 256, "key": b"key1-data"})
        storage.add_key("key2", {"algorithm": "ChaCha20", "key_size": 256, "key": b"key2-data"})
        
        # List keys
        keys = storage.list_keys()
        
        # Verify the result
        self.assertEqual(len(keys), 2)
        
        # Verify that key material is not included
        for key in keys:
            self.assertIn("id", key)
            self.assertNotIn("key", key)


if __name__ == "__main__":
    unittest.main()
