"""
Tests for post-quantum cryptography functionality.
"""

import unittest
import os
import tempfile
from pathlib import Path

from src.core.key_management import KeyManager
from src.core.encryption import EncryptionEngine
from src.core.post_quantum import PostQuantumCrypto, PQCRYPTO_AVAILABLE


@unittest.skipIf(not PQCRYPTO_AVAILABLE, "pqcrypto library not available")
class TestPostQuantumCrypto(unittest.TestCase):
    """Test cases for post-quantum cryptography."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.pq_crypto = PostQuantumCrypto()
        self.key_manager = KeyManager()
        self.encryption_engine = EncryptionEngine()
        
        # Test data
        self.test_message = b"This is a test message for post-quantum cryptography."
    
    def test_dilithium_sign_verify(self):
        """Test Dilithium signature generation and verification."""
        # Generate a key pair
        public_key, private_key = self.pq_crypto.generate_sign_keypair(algorithm="DILITHIUM2")
        
        # Sign a message
        signature = self.pq_crypto.sign(self.test_message, private_key, algorithm="DILITHIUM2")
        
        # Verify the signature
        result = self.pq_crypto.verify(self.test_message, signature, public_key, algorithm="DILITHIUM2")
        
        # Check that verification succeeded
        self.assertTrue(result)
        
        # Verify with a modified message
        modified_message = self.test_message + b"modified"
        result = self.pq_crypto.verify(modified_message, signature, public_key, algorithm="DILITHIUM2")
        
        # Check that verification failed
        self.assertFalse(result)
    
    def test_kyber_encapsulation(self):
        """Test Kyber key encapsulation mechanism."""
        # Generate a key pair
        public_key, private_key = self.pq_crypto.generate_kem_keypair(algorithm="KYBER768")
        
        # Encapsulate a shared secret
        ciphertext, shared_secret1 = self.pq_crypto.encapsulate(public_key, algorithm="KYBER768")
        
        # Decapsulate the shared secret
        shared_secret2 = self.pq_crypto.decapsulate(ciphertext, private_key, algorithm="KYBER768")
        
        # Check that the shared secrets match
        self.assertEqual(shared_secret1, shared_secret2)
    
    def test_kyber_encryption(self):
        """Test encryption and decryption using Kyber."""
        # Generate a key pair
        public_key, private_key = self.pq_crypto.generate_kem_keypair(algorithm="KYBER768")
        
        # Encrypt data
        encrypted_data = self.pq_crypto.encrypt_with_kem(self.test_message, public_key, algorithm="KYBER768")
        
        # Decrypt data
        decrypted_data = self.pq_crypto.decrypt_with_kem(encrypted_data, private_key)
        
        # Check that the decrypted data matches the original
        self.assertEqual(self.test_message, decrypted_data)
    
    def test_key_manager_integration(self):
        """Test integration with KeyManager."""
        # Generate a post-quantum key pair
        public_key, private_key = self.key_manager.generate_asymmetric_keypair(algorithm="KYBER768")
        
        # Check that the key was generated
        self.assertIsNotNone(public_key)
        self.assertIsNotNone(private_key)
        
        # List keys and check that the post-quantum key is there
        keys = self.key_manager.list_keys()
        
        # Find the post-quantum keys
        pq_keys = [k for k in keys if k.get('algorithm') == "KYBER768"]
        
        # Check that we have both public and private keys
        self.assertEqual(len(pq_keys), 2)
        
        # Check that the keys are marked as post-quantum
        for key in pq_keys:
            self.assertTrue(key.get('post_quantum', False))
    
    def test_encryption_engine_integration(self):
        """Test integration with EncryptionEngine."""
        # Skip if post-quantum crypto is not available in EncryptionEngine
        if not hasattr(self.encryption_engine, 'pq_crypto') or self.encryption_engine.pq_crypto is None:
            self.skipTest("Post-quantum crypto not available in EncryptionEngine")
        
        # Generate a post-quantum key pair
        public_key, private_key = self.pq_crypto.generate_kem_keypair(algorithm="KYBER768")
        
        # Encrypt data using the encryption engine
        encryption_result = self.encryption_engine._encrypt_kyber(
            self.test_message, 
            public_key, 
            algorithm="KYBER768"
        )
        
        # Check that the encryption result contains the expected fields
        self.assertIn('ciphertext', encryption_result)
        self.assertIn('kem_ciphertext', encryption_result)
        self.assertIn('algorithm', encryption_result)
        self.assertEqual(encryption_result['algorithm'], "KYBER768")
        self.assertTrue(encryption_result.get('post_quantum', False))
        
        # Decrypt data using the encryption engine
        decrypted_data = self.encryption_engine._decrypt_kyber(
            encryption_result['ciphertext'],
            private_key,
            encryption_result['kem_ciphertext'],
            algorithm="KYBER768"
        )
        
        # Check that the decrypted data matches the original
        self.assertEqual(self.test_message, decrypted_data)


if __name__ == "__main__":
    unittest.main()
