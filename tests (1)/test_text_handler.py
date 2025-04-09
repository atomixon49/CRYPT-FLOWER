"""
Tests for the text file handler.
"""

import unittest
import os
import tempfile
import shutil
from pathlib import Path
import codecs

from src.core.key_management import KeyManager
from src.core.encryption import EncryptionEngine
from src.file_handlers.text_handler import TextFileHandler


class TestTextFileHandler(unittest.TestCase):
    """Test cases for the text file handler."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key_manager = KeyManager()
        self.encryption_engine = EncryptionEngine()
        self.text_handler = TextFileHandler(self.key_manager, self.encryption_engine)
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Generate a key for testing
        self.key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        self.key_id = list(self.key_manager.active_keys.keys())[-1]
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        shutil.rmtree(self.test_dir)
    
    def test_encrypt_decrypt_with_key(self):
        """Test encrypting and decrypting a text file with a key."""
        # Create a test file
        input_path = os.path.join(self.test_dir, "test.txt")
        with open(input_path, "w") as f:
            f.write("This is a test file.")
        
        # Encrypt the file
        output_path = os.path.join(self.test_dir, "test.txt.encrypted")
        result = self.text_handler.encrypt_file(
            input_path=input_path,
            output_path=output_path,
            key=self.key,
            algorithm="AES-GCM"
        )
        
        # Verify the encrypted file exists
        self.assertTrue(os.path.exists(output_path))
        
        # Decrypt the file
        decrypted_path = os.path.join(self.test_dir, "test.txt.decrypted")
        result = self.text_handler.decrypt_file(
            input_path=output_path,
            output_path=decrypted_path,
            key=self.key
        )
        
        # Verify the decrypted file exists
        self.assertTrue(os.path.exists(decrypted_path))
        
        # Verify the content of the decrypted file
        with open(decrypted_path, "r") as f:
            content = f.read()
        
        self.assertEqual(content, "This is a test file.")
    
    def test_encrypt_decrypt_with_password(self):
        """Test encrypting and decrypting a text file with a password."""
        # Create a test file
        input_path = os.path.join(self.test_dir, "test.txt")
        with open(input_path, "w") as f:
            f.write("This is a test file.")
        
        # Encrypt the file
        output_path = os.path.join(self.test_dir, "test.txt.encrypted")
        result = self.text_handler.encrypt_file(
            input_path=input_path,
            output_path=output_path,
            password="test-password-123",
            algorithm="AES-GCM"
        )
        
        # Verify the encrypted file exists
        self.assertTrue(os.path.exists(output_path))
        
        # Decrypt the file
        decrypted_path = os.path.join(self.test_dir, "test.txt.decrypted")
        result = self.text_handler.decrypt_file(
            input_path=output_path,
            output_path=decrypted_path,
            password="test-password-123"
        )
        
        # Verify the decrypted file exists
        self.assertTrue(os.path.exists(decrypted_path))
        
        # Verify the content of the decrypted file
        with open(decrypted_path, "r") as f:
            content = f.read()
        
        self.assertEqual(content, "This is a test file.")
    
    def test_empty_file(self):
        """Test encrypting and decrypting an empty file."""
        # Create an empty test file
        input_path = os.path.join(self.test_dir, "empty.txt")
        with open(input_path, "w") as f:
            pass
        
        # Encrypt the file
        output_path = os.path.join(self.test_dir, "empty.txt.encrypted")
        result = self.text_handler.encrypt_file(
            input_path=input_path,
            output_path=output_path,
            key=self.key,
            algorithm="AES-GCM"
        )
        
        # Verify the encrypted file exists
        self.assertTrue(os.path.exists(output_path))
        
        # Decrypt the file
        decrypted_path = os.path.join(self.test_dir, "empty.txt.decrypted")
        result = self.text_handler.decrypt_file(
            input_path=output_path,
            output_path=decrypted_path,
            key=self.key
        )
        
        # Verify the decrypted file exists
        self.assertTrue(os.path.exists(decrypted_path))
        
        # Verify the content of the decrypted file
        with open(decrypted_path, "r") as f:
            content = f.read()
        
        self.assertEqual(content, "")
    
    def test_large_file(self):
        """Test encrypting and decrypting a large file."""
        # Create a large test file (1 MB)
        input_path = os.path.join(self.test_dir, "large.txt")
        with open(input_path, "w") as f:
            f.write("A" * 1024 * 1024)  # 1 MB of 'A's
        
        # Encrypt the file
        output_path = os.path.join(self.test_dir, "large.txt.encrypted")
        result = self.text_handler.encrypt_file(
            input_path=input_path,
            output_path=output_path,
            key=self.key,
            algorithm="AES-GCM"
        )
        
        # Verify the encrypted file exists
        self.assertTrue(os.path.exists(output_path))
        
        # Decrypt the file
        decrypted_path = os.path.join(self.test_dir, "large.txt.decrypted")
        result = self.text_handler.decrypt_file(
            input_path=output_path,
            output_path=decrypted_path,
            key=self.key
        )
        
        # Verify the decrypted file exists
        self.assertTrue(os.path.exists(decrypted_path))
        
        # Verify the content of the decrypted file
        with open(decrypted_path, "r") as f:
            content = f.read()
        
        self.assertEqual(content, "A" * 1024 * 1024)
    
    def test_different_encodings(self):
        """Test encrypting and decrypting files with different encodings."""
        # Test encodings
        encodings = ["utf-8", "utf-16", "latin-1", "cp1252"]
        
        for encoding in encodings:
            # Create a test file with the specified encoding
            input_path = os.path.join(self.test_dir, f"test_{encoding}.txt")
            with codecs.open(input_path, "w", encoding=encoding) as f:
                f.write("This is a test file with special characters: áéíóúñ")
            
            # Encrypt the file
            output_path = os.path.join(self.test_dir, f"test_{encoding}.txt.encrypted")
            result = self.text_handler.encrypt_file(
                input_path=input_path,
                output_path=output_path,
                key=self.key,
                algorithm="AES-GCM"
            )
            
            # Verify the encrypted file exists
            self.assertTrue(os.path.exists(output_path))
            
            # Decrypt the file
            decrypted_path = os.path.join(self.test_dir, f"test_{encoding}.txt.decrypted")
            result = self.text_handler.decrypt_file(
                input_path=output_path,
                output_path=decrypted_path,
                key=self.key
            )
            
            # Verify the decrypted file exists
            self.assertTrue(os.path.exists(decrypted_path))
            
            # Verify the content of the decrypted file
            with codecs.open(decrypted_path, "r", encoding=encoding) as f:
                content = f.read()
            
            self.assertEqual(content, "This is a test file with special characters: áéíóúñ")
    
    def test_wrong_password(self):
        """Test decrypting with the wrong password."""
        # Create a test file
        input_path = os.path.join(self.test_dir, "test.txt")
        with open(input_path, "w") as f:
            f.write("This is a test file.")
        
        # Encrypt the file
        output_path = os.path.join(self.test_dir, "test.txt.encrypted")
        result = self.text_handler.encrypt_file(
            input_path=input_path,
            output_path=output_path,
            password="correct-password",
            algorithm="AES-GCM"
        )
        
        # Verify the encrypted file exists
        self.assertTrue(os.path.exists(output_path))
        
        # Try to decrypt with the wrong password
        decrypted_path = os.path.join(self.test_dir, "test.txt.decrypted")
        with self.assertRaises(ValueError):
            self.text_handler.decrypt_file(
                input_path=output_path,
                output_path=decrypted_path,
                password="wrong-password"
            )
    
    def test_wrong_key(self):
        """Test decrypting with the wrong key."""
        # Create a test file
        input_path = os.path.join(self.test_dir, "test.txt")
        with open(input_path, "w") as f:
            f.write("This is a test file.")
        
        # Encrypt the file
        output_path = os.path.join(self.test_dir, "test.txt.encrypted")
        result = self.text_handler.encrypt_file(
            input_path=input_path,
            output_path=output_path,
            key=self.key,
            algorithm="AES-GCM"
        )
        
        # Verify the encrypted file exists
        self.assertTrue(os.path.exists(output_path))
        
        # Generate a different key
        wrong_key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        
        # Try to decrypt with the wrong key
        decrypted_path = os.path.join(self.test_dir, "test.txt.decrypted")
        with self.assertRaises(ValueError):
            self.text_handler.decrypt_file(
                input_path=output_path,
                output_path=decrypted_path,
                key=wrong_key
            )
    
    def test_corrupted_file(self):
        """Test decrypting a corrupted file."""
        # Create a test file
        input_path = os.path.join(self.test_dir, "test.txt")
        with open(input_path, "w") as f:
            f.write("This is a test file.")
        
        # Encrypt the file
        output_path = os.path.join(self.test_dir, "test.txt.encrypted")
        result = self.text_handler.encrypt_file(
            input_path=input_path,
            output_path=output_path,
            key=self.key,
            algorithm="AES-GCM"
        )
        
        # Verify the encrypted file exists
        self.assertTrue(os.path.exists(output_path))
        
        # Corrupt the encrypted file
        with open(output_path, "rb") as f:
            content = f.read()
        
        # Modify a byte in the middle of the file
        middle = len(content) // 2
        corrupted_content = content[:middle] + bytes([content[middle] ^ 0xFF]) + content[middle+1:]
        
        with open(output_path, "wb") as f:
            f.write(corrupted_content)
        
        # Try to decrypt the corrupted file
        decrypted_path = os.path.join(self.test_dir, "test.txt.decrypted")
        with self.assertRaises(ValueError):
            self.text_handler.decrypt_file(
                input_path=output_path,
                output_path=decrypted_path,
                key=self.key
            )
    
    def test_different_algorithms(self):
        """Test encrypting and decrypting with different algorithms."""
        # Test algorithms
        algorithms = ["AES-GCM", "ChaCha20-Poly1305"]
        
        for algorithm in algorithms:
            # Create a test file
            input_path = os.path.join(self.test_dir, f"test_{algorithm}.txt")
            with open(input_path, "w") as f:
                f.write("This is a test file.")
            
            # Encrypt the file
            output_path = os.path.join(self.test_dir, f"test_{algorithm}.txt.encrypted")
            result = self.text_handler.encrypt_file(
                input_path=input_path,
                output_path=output_path,
                key=self.key,
                algorithm=algorithm
            )
            
            # Verify the encrypted file exists
            self.assertTrue(os.path.exists(output_path))
            
            # Decrypt the file
            decrypted_path = os.path.join(self.test_dir, f"test_{algorithm}.txt.decrypted")
            result = self.text_handler.decrypt_file(
                input_path=output_path,
                output_path=decrypted_path,
                key=self.key
            )
            
            # Verify the decrypted file exists
            self.assertTrue(os.path.exists(decrypted_path))
            
            # Verify the content of the decrypted file
            with open(decrypted_path, "r") as f:
                content = f.read()
            
            self.assertEqual(content, "This is a test file.")


if __name__ == "__main__":
    unittest.main()
