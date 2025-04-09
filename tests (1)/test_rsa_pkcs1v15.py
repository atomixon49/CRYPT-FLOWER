"""
Tests for RSA-PKCS1v15 signature algorithm.
"""

import unittest
import os
import tempfile
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from src.core.signatures import SignatureEngine

class TestRSAPKCS1v15(unittest.TestCase):
    """Test cases for RSA-PKCS1v15 signature algorithm."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.signature_engine = SignatureEngine()
        
        # Generate a key pair for testing
        self.key_pair = self.signature_engine.generate_key_pair(
            algorithm='RSA-PKCS1v15',
            key_size=2048  # Smaller key for faster tests
        )
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a test file
        self.test_file_path = os.path.join(self.test_dir, "test_file.txt")
        with open(self.test_file_path, "w") as f:
            f.write("This is a test file for RSA-PKCS1v15 signatures.")
        
        # Read the test file
        with open(self.test_file_path, "rb") as f:
            self.test_data = f.read()
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        for root, dirs, files in os.walk(self.test_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.test_dir)
    
    def test_sign_and_verify_pkcs1v15(self):
        """Test signing and verifying with RSA-PKCS1v15."""
        # Sign the test data
        signature_result = self.signature_engine.sign(
            data=self.test_data,
            private_key=self.key_pair['private_key'],
            algorithm='RSA-PKCS1v15'
        )
        
        # Verify the signature
        is_valid = self.signature_engine.verify(
            data=self.test_data,
            signature_result=signature_result,
            public_key=self.key_pair['public_key']
        )
        
        # The signature should be valid
        self.assertTrue(is_valid)
    
    def test_sign_and_verify_pkcs1v15_with_wrong_algorithm(self):
        """Test signing with RSA-PKCS1v15 but verifying with RSA-PSS."""
        # Sign the test data with RSA-PKCS1v15
        signature_result = self.signature_engine.sign(
            data=self.test_data,
            private_key=self.key_pair['private_key'],
            algorithm='RSA-PKCS1v15'
        )
        
        # Modify the algorithm to RSA-PSS
        modified_result = signature_result.copy()
        modified_result['algorithm'] = 'RSA-PSS'
        
        # Verify the signature with the wrong algorithm
        is_valid = False
        try:
            is_valid = self.signature_engine.verify(
                data=self.test_data,
                signature_result=modified_result,
                public_key=self.key_pair['public_key']
            )
        except Exception:
            # We expect this to fail
            pass
        
        # The signature should be invalid
        self.assertFalse(is_valid)
    
    def test_cli_simulation(self):
        """Simulate the CLI behavior to reproduce the issue."""
        # Sign the test data with RSA-PKCS1v15
        signature_result = self.signature_engine.sign(
            data=self.test_data,
            private_key=self.key_pair['private_key'],
            algorithm='RSA-PKCS1v15'
        )
        
        # Save the signature to a file
        signature_path = os.path.join(self.test_dir, "test_file.sig")
        with open(signature_path, "wb") as f:
            f.write(signature_result['signature'])
        
        # Save the keys to files
        private_key_path = os.path.join(self.test_dir, "test_key.private")
        with open(private_key_path, "wb") as f:
            f.write(self.key_pair['private_pem'])
        
        public_key_path = os.path.join(self.test_dir, "test_key.public")
        with open(public_key_path, "wb") as f:
            f.write(self.key_pair['public_pem'])
        
        # Now simulate the CLI verification process
        # Read the public key
        with open(public_key_path, "rb") as f:
            public_key_data = f.read()
            public_key = load_pem_public_key(public_key_data)
        
        # Read the signature
        with open(signature_path, "rb") as f:
            signature = f.read()
        
        # This is what the CLI does - it always uses RSA-PSS
        algorithm = 'RSA-PSS'  # This is the issue!
        
        signature_result = {
            'algorithm': algorithm,
            'signature': signature
        }
        
        # Try to verify with the wrong algorithm
        is_valid = False
        try:
            is_valid = self.signature_engine.verify(
                data=self.test_data,
                signature_result=signature_result,
                public_key=public_key
            )
        except Exception:
            # We expect this to fail
            pass
        
        # The signature should be invalid because we're using the wrong algorithm
        self.assertFalse(is_valid)
        
        # Now try with the correct algorithm
        signature_result['algorithm'] = 'RSA-PKCS1v15'
        
        is_valid = self.signature_engine.verify(
            data=self.test_data,
            signature_result=signature_result,
            public_key=public_key
        )
        
        # Now the signature should be valid
        self.assertTrue(is_valid)


if __name__ == "__main__":
    unittest.main()
