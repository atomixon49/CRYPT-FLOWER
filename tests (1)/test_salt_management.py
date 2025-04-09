"""
Tests for the salt management in password-based encryption.
"""

import unittest
import os
import json
import base64
import tempfile
from src.core.key_management import KeyManager
from src.core.encryption import EncryptionEngine
from src.file_handlers.text_handler import TextFileHandler

class TestSaltManagement(unittest.TestCase):
    """Test cases for salt management in password-based encryption."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key_manager = KeyManager()
        self.encryption_engine = EncryptionEngine()
        self.text_handler = TextFileHandler(self.key_manager, self.encryption_engine)
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a test file
        self.test_file_path = os.path.join(self.test_dir, "test_file.txt")
        with open(self.test_file_path, "w") as f:
            f.write("This is a test file with some content.")
        
        # Define paths for encrypted and decrypted files
        self.encrypted_file_path = os.path.join(self.test_dir, "test_file.txt.encrypted")
        self.decrypted_file_path = os.path.join(self.test_dir, "test_file_decrypted.txt")
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        for root, dirs, files in os.walk(self.test_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.test_dir)
    
    def test_salt_storage_in_metadata(self):
        """Test that salt is stored in metadata during encryption."""
        # Encrypt a file with a password
        password = "test-password"
        result = self.text_handler.encrypt_file(
            input_path=self.test_file_path,
            output_path=self.encrypted_file_path,
            password=password
        )
        
        # Verify that the file was encrypted
        self.assertTrue(os.path.exists(self.encrypted_file_path))
        
        # Read the encrypted file
        with open(self.encrypted_file_path, "r") as f:
            encrypted_data = json.load(f)
        
        # Verify that the metadata contains the encryption method and salt
        metadata = encrypted_data.get("metadata", {})
        self.assertEqual(metadata.get("encryption_method"), "password_based")
        self.assertIn("salt", metadata)
        
        # Verify that the salt is a valid base64 string
        salt_base64 = metadata.get("salt")
        try:
            salt = base64.b64decode(salt_base64)
            self.assertEqual(len(salt), 16)  # Salt should be 16 bytes
        except Exception as e:
            self.fail(f"Failed to decode salt: {str(e)}")
    
    def test_decrypt_with_password_only(self):
        """Test decryption with just a password (salt from metadata)."""
        # Encrypt a file with a password
        password = "test-password"
        self.text_handler.encrypt_file(
            input_path=self.test_file_path,
            output_path=self.encrypted_file_path,
            password=password
        )
        
        # Decrypt the file with just the password
        result = self.text_handler.decrypt_file(
            input_path=self.encrypted_file_path,
            output_path=self.decrypted_file_path,
            password=password
        )
        
        # Verify that the file was decrypted
        self.assertTrue(os.path.exists(self.decrypted_file_path))
        
        # Verify the content of the decrypted file
        with open(self.decrypted_file_path, "r") as f:
            decrypted_content = f.read()
        
        with open(self.test_file_path, "r") as f:
            original_content = f.read()
        
        self.assertEqual(decrypted_content, original_content)
    
    def test_decrypt_with_wrong_password(self):
        """Test decryption with wrong password."""
        # Encrypt a file with a password
        password = "test-password"
        self.text_handler.encrypt_file(
            input_path=self.test_file_path,
            output_path=self.encrypted_file_path,
            password=password
        )
        
        # Try to decrypt with wrong password
        with self.assertRaises(ValueError):
            self.text_handler.decrypt_file(
                input_path=self.encrypted_file_path,
                output_path=self.decrypted_file_path,
                password="wrong-password"
            )
    
    def test_backward_compatibility(self):
        """Test backward compatibility with old format (no salt in metadata)."""
        # Create an encrypted file in the old format (no salt in metadata)
        password = "test-password"
        salt = os.urandom(16)
        key, _ = self.key_manager.derive_key_from_password(password, salt)
        
        # Encrypt the file with the derived key
        result = self.text_handler.encrypt_file(
            input_path=self.test_file_path,
            output_path=self.encrypted_file_path,
            key=key
        )
        
        # Modify the encrypted file to remove encryption_method
        with open(self.encrypted_file_path, "r") as f:
            encrypted_data = json.load(f)
        
        # Remove encryption_method from metadata
        if "encryption_method" in encrypted_data["metadata"]:
            del encrypted_data["metadata"]["encryption_method"]
        
        # Write back the modified data
        with open(self.encrypted_file_path, "w") as f:
            json.dump(encrypted_data, f)
        
        # Try to decrypt with password and salt
        result = self.text_handler.decrypt_file(
            input_path=self.encrypted_file_path,
            output_path=self.decrypted_file_path,
            password=password,
            salt=salt
        )
        
        # Verify that the file was decrypted
        self.assertTrue(os.path.exists(self.decrypted_file_path))
        
        # Verify the content of the decrypted file
        with open(self.decrypted_file_path, "r") as f:
            decrypted_content = f.read()
        
        with open(self.test_file_path, "r") as f:
            original_content = f.read()
        
        self.assertEqual(decrypted_content, original_content)


if __name__ == "__main__":
    unittest.main()
