"""
Tests for the directory handler.
"""

import unittest
import os
import tempfile
import json
import shutil
from pathlib import Path

from src.core.key_management import KeyManager
from src.core.encryption import EncryptionEngine
from src.file_handlers.directory_handler import DirectoryHandler

class TestDirectoryHandler(unittest.TestCase):
    """Test cases for the directory handler."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key_manager = KeyManager()
        self.encryption_engine = EncryptionEngine()
        self.directory_handler = DirectoryHandler(self.key_manager, self.encryption_engine)
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.input_dir = os.path.join(self.test_dir, "input")
        self.output_dir = os.path.join(self.test_dir, "output")
        
        # Create test directory structure
        os.makedirs(self.input_dir)
        
        # Create some test files
        self.create_test_files()
        
        # Generate a key for testing
        self.key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        self.key_id = list(self.key_manager.active_keys.keys())[-1]
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        shutil.rmtree(self.test_dir)
    
    def create_test_files(self):
        """Create test files and directories."""
        # Create files in the root directory
        with open(os.path.join(self.input_dir, "file1.txt"), "w") as f:
            f.write("This is file 1")
        
        with open(os.path.join(self.input_dir, "file2.txt"), "w") as f:
            f.write("This is file 2")
        
        # Create a subdirectory
        subdir = os.path.join(self.input_dir, "subdir")
        os.makedirs(subdir)
        
        # Create files in the subdirectory
        with open(os.path.join(subdir, "file3.txt"), "w") as f:
            f.write("This is file 3")
        
        with open(os.path.join(subdir, "file4.txt"), "w") as f:
            f.write("This is file 4")
        
        # Create a nested subdirectory
        nested_subdir = os.path.join(subdir, "nested")
        os.makedirs(nested_subdir)
        
        # Create a file in the nested subdirectory
        with open(os.path.join(nested_subdir, "file5.txt"), "w") as f:
            f.write("This is file 5")
    
    def test_encrypt_decrypt_directory_with_key(self):
        """Test encrypting and decrypting a directory with a key."""
        # Encrypt the directory
        result = self.directory_handler.encrypt_directory(
            input_path=self.input_dir,
            output_path=self.output_dir,
            key=self.key
        )
        
        # Verify the encrypted directory exists
        self.assertTrue(os.path.exists(self.output_dir))
        
        # Verify the metadata file exists
        metadata_path = os.path.join(self.output_dir, ".metadata.json")
        self.assertTrue(os.path.exists(metadata_path))
        
        # Verify the metadata
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        self.assertEqual(metadata["algorithm"], "AES-GCM")
        self.assertEqual(metadata["directory_structure"]["original_path"], self.input_dir)
        self.assertEqual(metadata["directory_structure"]["encrypted_path"], self.output_dir)
        
        # Verify the encrypted files
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "file1.txt.encrypted")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "file2.txt.encrypted")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "subdir")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "subdir", "file3.txt.encrypted")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "subdir", "file4.txt.encrypted")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "subdir", "nested")))
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, "subdir", "nested", "file5.txt.encrypted")))
        
        # Decrypt the directory
        decrypted_dir = os.path.join(self.test_dir, "decrypted")
        result = self.directory_handler.decrypt_directory(
            input_path=self.output_dir,
            output_path=decrypted_dir,
            key=self.key
        )
        
        # Verify the decrypted directory exists
        self.assertTrue(os.path.exists(decrypted_dir))
        
        # Verify the decrypted files
        self.assertTrue(os.path.exists(os.path.join(decrypted_dir, "file1.txt")))
        self.assertTrue(os.path.exists(os.path.join(decrypted_dir, "file2.txt")))
        self.assertTrue(os.path.exists(os.path.join(decrypted_dir, "subdir")))
        self.assertTrue(os.path.exists(os.path.join(decrypted_dir, "subdir", "file3.txt")))
        self.assertTrue(os.path.exists(os.path.join(decrypted_dir, "subdir", "file4.txt")))
        self.assertTrue(os.path.exists(os.path.join(decrypted_dir, "subdir", "nested")))
        self.assertTrue(os.path.exists(os.path.join(decrypted_dir, "subdir", "nested", "file5.txt")))
        
        # Verify the content of the decrypted files
        with open(os.path.join(decrypted_dir, "file1.txt"), "r") as f:
            self.assertEqual(f.read(), "This is file 1")
        
        with open(os.path.join(decrypted_dir, "file2.txt"), "r") as f:
            self.assertEqual(f.read(), "This is file 2")
        
        with open(os.path.join(decrypted_dir, "subdir", "file3.txt"), "r") as f:
            self.assertEqual(f.read(), "This is file 3")
        
        with open(os.path.join(decrypted_dir, "subdir", "file4.txt"), "r") as f:
            self.assertEqual(f.read(), "This is file 4")
        
        with open(os.path.join(decrypted_dir, "subdir", "nested", "file5.txt"), "r") as f:
            self.assertEqual(f.read(), "This is file 5")
    
    def test_encrypt_decrypt_directory_with_password(self):
        """Test encrypting and decrypting a directory with a password."""
        # Encrypt the directory
        password = "test-password-123"
        result = self.directory_handler.encrypt_directory(
            input_path=self.input_dir,
            output_path=self.output_dir,
            password=password
        )
        
        # Verify the encrypted directory exists
        self.assertTrue(os.path.exists(self.output_dir))
        
        # Verify the metadata file exists
        metadata_path = os.path.join(self.output_dir, ".metadata.json")
        self.assertTrue(os.path.exists(metadata_path))
        
        # Decrypt the directory
        decrypted_dir = os.path.join(self.test_dir, "decrypted")
        result = self.directory_handler.decrypt_directory(
            input_path=self.output_dir,
            output_path=decrypted_dir,
            password=password
        )
        
        # Verify the decrypted directory exists
        self.assertTrue(os.path.exists(decrypted_dir))
        
        # Verify the content of the decrypted files
        with open(os.path.join(decrypted_dir, "file1.txt"), "r") as f:
            self.assertEqual(f.read(), "This is file 1")
    
    def test_decrypt_with_wrong_key(self):
        """Test decrypting with the wrong key."""
        # Encrypt the directory
        result = self.directory_handler.encrypt_directory(
            input_path=self.input_dir,
            output_path=self.output_dir,
            key=self.key
        )
        
        # Generate a different key
        wrong_key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        
        # Try to decrypt with the wrong key
        decrypted_dir = os.path.join(self.test_dir, "decrypted")
        with self.assertRaises(ValueError):
            self.directory_handler.decrypt_directory(
                input_path=self.output_dir,
                output_path=decrypted_dir,
                key=wrong_key
            )
    
    def test_decrypt_with_wrong_password(self):
        """Test decrypting with the wrong password."""
        # Encrypt the directory
        password = "test-password-123"
        result = self.directory_handler.encrypt_directory(
            input_path=self.input_dir,
            output_path=self.output_dir,
            password=password
        )
        
        # Try to decrypt with the wrong password
        wrong_password = "wrong-password"
        decrypted_dir = os.path.join(self.test_dir, "decrypted")
        with self.assertRaises(ValueError):
            self.directory_handler.decrypt_directory(
                input_path=self.output_dir,
                output_path=decrypted_dir,
                password=wrong_password
            )


if __name__ == "__main__":
    unittest.main()
