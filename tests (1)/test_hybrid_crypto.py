"""
Tests for the hybrid cryptography module.
"""

import unittest
import os
import tempfile
import shutil
import json
import base64
from pathlib import Path

from src.core.key_management import KeyManager
from src.core.encryption import EncryptionEngine
from src.core.signatures import SignatureEngine
from src.core.hybrid_crypto import HybridCrypto, POSTQUANTUM_AVAILABLE


class TestHybridCrypto(unittest.TestCase):
    """Test cases for the hybrid cryptography module."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key_manager = KeyManager()
        self.encryption_engine = EncryptionEngine()
        self.signature_engine = SignatureEngine()
        self.hybrid_crypto = HybridCrypto(self.key_manager)
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        shutil.rmtree(self.test_dir)
    
    def test_generate_hybrid_keypair(self):
        """Test generating a hybrid key pair."""
        # Generate a hybrid key pair
        hybrid_key_info = self.hybrid_crypto.generate_hybrid_keypair(
            classical_algorithm="RSA",
            classical_key_size=2048
        )
        
        # Verify the hybrid key info
        self.assertIsNotNone(hybrid_key_info)
        self.assertEqual(hybrid_key_info["type"], "hybrid")
        self.assertIn("classical", hybrid_key_info)
        self.assertEqual(hybrid_key_info["classical"]["algorithm"], "RSA")
        self.assertEqual(hybrid_key_info["classical"]["key_size"], 2048)
        
        # Verify that the classical keys exist
        classical_private_key_id = hybrid_key_info["classical"]["private_key_id"]
        classical_public_key_id = hybrid_key_info["classical"]["public_key_id"]
        
        self.assertIn(classical_private_key_id, self.key_manager.active_keys)
        self.assertIn(classical_public_key_id, self.key_manager.active_keys)
        
        # Check if post-quantum keys were generated (if available)
        if POSTQUANTUM_AVAILABLE and "post_quantum" in hybrid_key_info:
            pq_private_key_id = hybrid_key_info["post_quantum"]["private_key_id"]
            pq_public_key_id = hybrid_key_info["post_quantum"]["public_key_id"]
            
            self.assertIn(pq_private_key_id, self.key_manager.active_keys)
            self.assertIn(pq_public_key_id, self.key_manager.active_keys)
    
    def test_encrypt_decrypt_hybrid(self):
        """Test encrypting and decrypting data using hybrid encryption."""
        # Generate a hybrid key pair
        hybrid_key_info = self.hybrid_crypto.generate_hybrid_keypair(
            classical_algorithm="RSA",
            classical_key_size=2048
        )
        
        # Get the key IDs
        hybrid_key_id = hybrid_key_info["id"]
        
        # Test data
        test_data = "This is a test message for hybrid encryption."
        
        # Encrypt the data
        encrypted_result = self.hybrid_crypto.encrypt_hybrid(
            data=test_data,
            public_key_id=hybrid_key_id
        )
        
        # Verify the encrypted result
        self.assertIsNotNone(encrypted_result)
        self.assertEqual(encrypted_result["type"], "hybrid_encrypted")
        self.assertIn("data", encrypted_result)
        self.assertIn("nonce", encrypted_result)
        self.assertIn("tag", encrypted_result)
        self.assertIn("key_encryption", encrypted_result)
        self.assertIn("classical", encrypted_result["key_encryption"])
        
        # Check if post-quantum encryption was used (if available)
        if POSTQUANTUM_AVAILABLE and "post_quantum" in hybrid_key_info:
            self.assertIn("post_quantum", encrypted_result["key_encryption"])
        
        # Decrypt the data
        decrypted_data = self.hybrid_crypto.decrypt_hybrid(
            encrypted_data=encrypted_result,
            private_key_id=hybrid_key_id
        )
        
        # Verify the decrypted data
        self.assertEqual(decrypted_data.decode('utf-8'), test_data)
    
    def test_sign_verify_hybrid(self):
        """Test signing and verifying data using hybrid signatures."""
        # Generate a hybrid key pair
        hybrid_key_info = self.hybrid_crypto.generate_hybrid_keypair(
            classical_algorithm="RSA",
            classical_key_size=2048
        )
        
        # Get the key IDs
        hybrid_key_id = hybrid_key_info["id"]
        
        # Test data
        test_data = "This is a test message for hybrid signatures."
        
        # Sign the data
        signature_result = self.hybrid_crypto.sign_hybrid(
            data=test_data,
            private_key_id=hybrid_key_id
        )
        
        # Verify the signature result
        self.assertIsNotNone(signature_result)
        self.assertEqual(signature_result["type"], "hybrid_signature")
        self.assertIn("signatures", signature_result)
        self.assertIn("classical", signature_result["signatures"])
        
        # Check if post-quantum signature was used (if available)
        if POSTQUANTUM_AVAILABLE and "post_quantum" in hybrid_key_info:
            self.assertIn("post_quantum", signature_result["signatures"])
        
        # Verify the signature
        is_valid = self.hybrid_crypto.verify_hybrid(
            data=test_data,
            signature_result=signature_result,
            public_key_id=hybrid_key_id
        )
        
        # Verify the result
        self.assertTrue(is_valid)
        
        # Test with modified data
        modified_data = test_data + " This has been tampered with."
        is_valid_modified = self.hybrid_crypto.verify_hybrid(
            data=modified_data,
            signature_result=signature_result,
            public_key_id=hybrid_key_id
        )
        
        # Verify the result with modified data
        self.assertFalse(is_valid_modified)
    
    def test_large_data_hybrid(self):
        """Test hybrid encryption and decryption with large data."""
        # Generate a hybrid key pair
        hybrid_key_info = self.hybrid_crypto.generate_hybrid_keypair(
            classical_algorithm="RSA",
            classical_key_size=2048
        )
        
        # Get the key IDs
        hybrid_key_id = hybrid_key_info["id"]
        
        # Generate large test data (1 MB)
        test_data = os.urandom(1024 * 1024)
        
        # Encrypt the data
        encrypted_result = self.hybrid_crypto.encrypt_hybrid(
            data=test_data,
            public_key_id=hybrid_key_id
        )
        
        # Decrypt the data
        decrypted_data = self.hybrid_crypto.decrypt_hybrid(
            encrypted_data=encrypted_result,
            private_key_id=hybrid_key_id
        )
        
        # Verify the decrypted data
        self.assertEqual(decrypted_data, test_data)
    
    def test_serialization(self):
        """Test serialization and deserialization of hybrid encryption results."""
        # Generate a hybrid key pair
        hybrid_key_info = self.hybrid_crypto.generate_hybrid_keypair(
            classical_algorithm="RSA",
            classical_key_size=2048
        )
        
        # Get the key IDs
        hybrid_key_id = hybrid_key_info["id"]
        
        # Test data
        test_data = "This is a test message for serialization."
        
        # Encrypt the data
        encrypted_result = self.hybrid_crypto.encrypt_hybrid(
            data=test_data,
            public_key_id=hybrid_key_id
        )
        
        # Serialize the encrypted result
        serialized = json.dumps(encrypted_result)
        
        # Deserialize the encrypted result
        deserialized = json.loads(serialized)
        
        # Decrypt the data using the deserialized result
        decrypted_data = self.hybrid_crypto.decrypt_hybrid(
            encrypted_data=deserialized,
            private_key_id=hybrid_key_id
        )
        
        # Verify the decrypted data
        self.assertEqual(decrypted_data.decode('utf-8'), test_data)
    
    def test_fallback_mechanism(self):
        """Test the fallback mechanism when one algorithm is unavailable."""
        # This test is only meaningful if post-quantum crypto is available
        if not POSTQUANTUM_AVAILABLE:
            self.skipTest("Post-quantum cryptography not available")
        
        # Generate a hybrid key pair
        hybrid_key_info = self.hybrid_crypto.generate_hybrid_keypair(
            classical_algorithm="RSA",
            classical_key_size=2048
        )
        
        # Get the key IDs
        hybrid_key_id = hybrid_key_info["id"]
        
        # Test data
        test_data = "This is a test message for fallback mechanism."
        
        # Encrypt the data
        encrypted_result = self.hybrid_crypto.encrypt_hybrid(
            data=test_data,
            public_key_id=hybrid_key_id
        )
        
        # Simulate a scenario where post-quantum decryption fails
        # by removing the post-quantum key encryption data
        if "post_quantum" in encrypted_result["key_encryption"]:
            del encrypted_result["key_encryption"]["post_quantum"]
        
        # Decrypt the data (should fall back to classical decryption)
        decrypted_data = self.hybrid_crypto.decrypt_hybrid(
            encrypted_data=encrypted_result,
            private_key_id=hybrid_key_id
        )
        
        # Verify the decrypted data
        self.assertEqual(decrypted_data.decode('utf-8'), test_data)


if __name__ == "__main__":
    unittest.main()
