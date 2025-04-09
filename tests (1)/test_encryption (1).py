"""
Tests for the encryption module.
"""

import unittest
import os
import tempfile
from src.core.encryption import EncryptionEngine
from src.core.key_management import KeyManager

class TestEncryption(unittest.TestCase):
    """Test cases for the encryption module."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.encryption_engine = EncryptionEngine()
        self.key_manager = KeyManager()
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        for root, dirs, files in os.walk(self.test_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.test_dir)
    
    def test_aes_gcm_encryption_decryption(self):
        """Test AES-GCM encryption and decryption."""
        # Generate a key
        key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        
        # Test data
        plaintext = b'This is a test message.'
        
        # Encrypt the data
        encryption_result = self.encryption_engine.encrypt(
            data=plaintext,
            key=key,
            algorithm='AES-GCM'
        )
        
        # Verify the encryption result
        self.assertEqual(encryption_result['algorithm'], 'AES-GCM')
        self.assertIn('ciphertext', encryption_result)
        self.assertIn('nonce', encryption_result)
        self.assertIn('tag', encryption_result)
        
        # Decrypt the data
        decrypted = self.encryption_engine.decrypt(
            encryption_result=encryption_result,
            key=key
        )
        
        # Verify the decryption result
        self.assertEqual(decrypted, plaintext)
    
    def test_chacha20_poly1305_encryption_decryption(self):
        """Test ChaCha20-Poly1305 encryption and decryption."""
        # Generate a key
        key = self.key_manager.generate_symmetric_key(algorithm='ChaCha20', key_size=256)
        
        # Test data
        plaintext = b'This is a test message.'
        
        # Encrypt the data
        encryption_result = self.encryption_engine.encrypt(
            data=plaintext,
            key=key,
            algorithm='ChaCha20-Poly1305'
        )
        
        # Verify the encryption result
        self.assertEqual(encryption_result['algorithm'], 'ChaCha20-Poly1305')
        self.assertIn('ciphertext', encryption_result)
        self.assertIn('nonce', encryption_result)
        self.assertIn('tag', encryption_result)
        
        # Decrypt the data
        decrypted = self.encryption_engine.decrypt(
            encryption_result=encryption_result,
            key=key
        )
        
        # Verify the decryption result
        self.assertEqual(decrypted, plaintext)
    
    def test_encryption_with_associated_data(self):
        """Test encryption with associated data."""
        # Generate a key
        key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        
        # Test data
        plaintext = b'This is a test message.'
        associated_data = b'Associated data'
        
        # Encrypt the data
        encryption_result = self.encryption_engine.encrypt(
            data=plaintext,
            key=key,
            algorithm='AES-GCM',
            associated_data=associated_data
        )
        
        # Verify the encryption result
        self.assertEqual(encryption_result['algorithm'], 'AES-GCM')
        self.assertEqual(encryption_result['associated_data'], associated_data)
        
        # Decrypt the data
        decrypted = self.encryption_engine.decrypt(
            encryption_result=encryption_result,
            key=key
        )
        
        # Verify the decryption result
        self.assertEqual(decrypted, plaintext)
    
    def test_decryption_with_wrong_key(self):
        """Test decryption with the wrong key."""
        # Generate keys
        key1 = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        key2 = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        
        # Test data
        plaintext = b'This is a test message.'
        
        # Encrypt the data with key1
        encryption_result = self.encryption_engine.encrypt(
            data=plaintext,
            key=key1,
            algorithm='AES-GCM'
        )
        
        # Try to decrypt with key2
        with self.assertRaises(ValueError):
            self.encryption_engine.decrypt(
                encryption_result=encryption_result,
                key=key2
            )
    
    def test_decryption_with_modified_ciphertext(self):
        """Test decryption with modified ciphertext."""
        # Generate a key
        key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        
        # Test data
        plaintext = b'This is a test message.'
        
        # Encrypt the data
        encryption_result = self.encryption_engine.encrypt(
            data=plaintext,
            key=key,
            algorithm='AES-GCM'
        )
        
        # Modify the ciphertext
        if encryption_result['ciphertext']:
            modified_byte = (encryption_result['ciphertext'][0] + 1) % 256
            modified_ciphertext = bytes([modified_byte]) + encryption_result['ciphertext'][1:]
            encryption_result['ciphertext'] = modified_ciphertext
        
        # Try to decrypt the modified ciphertext
        with self.assertRaises(ValueError):
            self.encryption_engine.decrypt(
                encryption_result=encryption_result,
                key=key
            )


if __name__ == '__main__':
    unittest.main()
