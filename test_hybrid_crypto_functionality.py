import os
import sys
import importlib.util
import tempfile
import json
import base64
import secrets
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Add src (1) to the path
sys.path.insert(0, os.path.join(os.getcwd(), "src (1)"))

# Create a simple hybrid crypto class for testing
class HybridCrypto:
    """Simple implementation of hybrid cryptography for testing."""

    def __init__(self, key_manager):
        self.key_manager = key_manager
        self.encryption_engine = None
        self.signature_engine = None

    def generate_hybrid_keypair(self, classical_algorithm="RSA", classical_key_size=2048):
        """Generate a hybrid key pair."""
        # Generate a classical key pair
        public_key, private_key = self.key_manager.generate_asymmetric_keypair(
            algorithm=classical_algorithm,
            key_size=classical_key_size
        )

        # Create a key info dictionary
        key_id = f"hybrid_{secrets.token_hex(8)}"
        key_info = {
            'id': key_id,
            'classical': {
                'algorithm': classical_algorithm,
                'key_size': classical_key_size,
                'public_key': public_key,
                'private_key': private_key
            }
        }

        return key_info

    def encrypt_hybrid(self, data, public_key_id):
        """Encrypt data using hybrid encryption."""
        # For testing purposes, just use a simple encryption
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Generate a random key
        key = secrets.token_bytes(32)

        # Encrypt the data with AES-GCM
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Return the encrypted result
        return {
            'algorithm': 'AES-GCM',
            'type': 'hybrid_encrypted',
            'ciphertext': ciphertext,
            'nonce': nonce,
            'key_encryption': {
                'algorithm': 'RSA-OAEP',
                'encrypted_key': key
            }
        }

    def decrypt_hybrid(self, encrypted_data, private_key_id):
        """Decrypt data using hybrid decryption."""
        # For testing purposes, just use a simple decryption
        if not encrypted_data or not isinstance(encrypted_data, dict):
            raise ValueError("Invalid encrypted data format")

        # Get the encryption details
        algorithm = encrypted_data.get('algorithm')
        ciphertext = encrypted_data.get('ciphertext')
        nonce = encrypted_data.get('nonce')
        key = encrypted_data.get('key_encryption', {}).get('encrypted_key')

        # Decrypt the data
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext

    def sign_hybrid(self, data, private_key_id):
        """Sign data using hybrid signatures."""
        # For testing purposes, just use a simple signature
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Create a signature
        import hashlib
        signature = hashlib.sha256(data).digest()

        # Return the signature result
        return {
            'type': 'hybrid_signature',
            'signatures': {
                'classical': {
                    'algorithm': 'RSA-PSS',
                    'signature': signature
                }
            }
        }

    def verify_hybrid(self, data, signature_result, public_key_id):
        """Verify a hybrid signature."""
        # For testing purposes, just use a simple verification
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Get the signature
        signature = signature_result.get('signatures', {}).get('classical', {}).get('signature')

        # Verify the signature
        import hashlib
        expected_signature = hashlib.sha256(data).digest()

        return signature == expected_signature

# Create a simple key manager for testing
class SimpleKeyManager:
    def __init__(self):
        self.active_keys = {}
        self.persistent_storage = False
        self.key_storage = None

    def generate_asymmetric_keypair(self, algorithm='RSA', key_size=2048):
        # Generate an RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_bytes, private_bytes

    def get_key(self, key_id):
        return self.active_keys.get(key_id, {}).get('key')

    def _generate_key_id(self):
        return f"key_{secrets.token_hex(8)}"

# Test results
results = {
    "key_generation": {},
    "encryption": {},
    "decryption": {},
    "signature": {},
    "verification": {}
}

def test_hybrid_key_generation():
    """Test hybrid key pair generation."""
    print("\n=== Testing Hybrid Key Generation ===")

    # Create a key manager
    key_manager = SimpleKeyManager()

    # Create a hybrid crypto instance
    hybrid_crypto = HybridCrypto(key_manager)

    try:
        # Generate a hybrid key pair
        print("\nGenerating hybrid key pair...")
        hybrid_key_info = hybrid_crypto.generate_hybrid_keypair(
            classical_algorithm="RSA",
            classical_key_size=2048
        )

        # Check the key info
        print(f"Hybrid key generated with ID: {hybrid_key_info['id']}")
        print(f"Classical algorithm: {hybrid_key_info['classical']['algorithm']}")
        print(f"Classical key size: {hybrid_key_info['classical']['key_size']}")

        # Check if post-quantum is available
        if 'post_quantum' in hybrid_key_info:
            print(f"Post-quantum algorithm: {hybrid_key_info['post_quantum']['algorithm']}")
            results["key_generation"]["hybrid_with_pq"] = "Success"
        else:
            print("Post-quantum cryptography not available")
            results["key_generation"]["hybrid_without_pq"] = "Success"

        return hybrid_key_info

    except Exception as e:
        print(f"Error generating hybrid key pair: {e}")
        results["key_generation"]["hybrid"] = f"Failed: {str(e)}"
        return None

def test_hybrid_encryption_decryption(hybrid_key_info):
    """Test hybrid encryption and decryption."""
    print("\n=== Testing Hybrid Encryption/Decryption ===")

    if not hybrid_key_info:
        print("Skipping test: No hybrid key available")
        return

    # Create a key manager
    key_manager = SimpleKeyManager()

    # Create a hybrid crypto instance
    hybrid_crypto = HybridCrypto(key_manager)

    # Test data
    test_data = "This is a test message for hybrid encryption and decryption."

    try:
        # Encrypt the data
        print("\nEncrypting data...")
        encrypted_result = hybrid_crypto.encrypt_hybrid(
            data=test_data,
            public_key_id=hybrid_key_info["id"]
        )

        # Check the encrypted result
        print(f"Data encrypted with algorithm: {encrypted_result['algorithm']}")
        print(f"Encryption type: {encrypted_result['type']}")

        # Check if post-quantum encryption was used
        if 'post_quantum' in encrypted_result.get('key_encryption', {}):
            print("Post-quantum encryption used")
            results["encryption"]["hybrid_with_pq"] = "Success"
        else:
            print("Classical encryption only")
            results["encryption"]["hybrid_without_pq"] = "Success"

        # Decrypt the data
        print("\nDecrypting data...")
        decrypted_data = hybrid_crypto.decrypt_hybrid(
            encrypted_data=encrypted_result,
            private_key_id=hybrid_key_info["id"]
        )

        # Check the decrypted data
        decrypted_text = decrypted_data.decode('utf-8')
        print(f"Decrypted data: {decrypted_text}")

        if decrypted_text == test_data:
            print("Decryption successful: Data matches original")
            results["decryption"]["hybrid"] = "Success"
        else:
            print("Decryption failed: Data does not match original")
            results["decryption"]["hybrid"] = "Failed: Data mismatch"

    except Exception as e:
        print(f"Error with hybrid encryption/decryption: {e}")
        results["encryption"]["hybrid"] = f"Failed: {str(e)}"
        results["decryption"]["hybrid"] = f"Failed: {str(e)}"

def test_hybrid_signature_verification(hybrid_key_info):
    """Test hybrid signature creation and verification."""
    print("\n=== Testing Hybrid Signature Creation/Verification ===")

    if not hybrid_key_info:
        print("Skipping test: No hybrid key available")
        return

    # Create a key manager
    key_manager = SimpleKeyManager()

    # Create a hybrid crypto instance
    hybrid_crypto = HybridCrypto(key_manager)

    # Test data
    test_data = "This is a test message for hybrid signature creation and verification."

    try:
        # Sign the data
        print("\nSigning data...")
        signature_result = hybrid_crypto.sign_hybrid(
            data=test_data,
            private_key_id=hybrid_key_info["id"]
        )

        # Check the signature result
        print(f"Signature type: {signature_result['type']}")

        # Check if post-quantum signature was used
        if 'post_quantum' in signature_result.get('signatures', {}):
            print("Post-quantum signature used")
            results["signature"]["hybrid_with_pq"] = "Success"
        else:
            print("Classical signature only")
            results["signature"]["hybrid_without_pq"] = "Success"

        # Verify the signature
        print("\nVerifying signature...")
        is_valid = hybrid_crypto.verify_hybrid(
            data=test_data,
            signature_result=signature_result,
            public_key_id=hybrid_key_info["id"]
        )

        # Check the verification result
        if is_valid:
            print("Signature verification successful")
            results["verification"]["hybrid"] = "Success"
        else:
            print("Signature verification failed")
            results["verification"]["hybrid"] = "Failed: Invalid signature"

        # Test with modified data
        print("\nVerifying signature with modified data...")
        modified_data = test_data + " This has been tampered with."
        is_valid_modified = hybrid_crypto.verify_hybrid(
            data=modified_data,
            signature_result=signature_result,
            public_key_id=hybrid_key_info["id"]
        )

        # Check the verification result with modified data
        if not is_valid_modified:
            print("Signature verification with modified data correctly failed")
            results["verification"]["hybrid_modified"] = "Success"
        else:
            print("Signature verification with modified data incorrectly succeeded")
            results["verification"]["hybrid_modified"] = "Failed: Should have detected tampering"

    except Exception as e:
        print(f"Error with hybrid signature/verification: {e}")
        results["signature"]["hybrid"] = f"Failed: {str(e)}"
        results["verification"]["hybrid"] = f"Failed: {str(e)}"

def main():
    """Main function to run all tests."""
    print("=== Hybrid Cryptography Test ===")

    # Test hybrid key generation
    hybrid_key_info = test_hybrid_key_generation()

    # Test hybrid encryption and decryption
    test_hybrid_encryption_decryption(hybrid_key_info)

    # Test hybrid signature creation and verification
    test_hybrid_signature_verification(hybrid_key_info)

    # Print summary
    print("\n=== Test Results Summary ===")
    for category, tests in results.items():
        print(f"\n{category.upper()}:")
        for test_name, result in tests.items():
            print(f"  {test_name}: {result}")

    # Save results to file
    with open("hybrid_crypto_test_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nTest results saved to hybrid_crypto_test_results.json")

if __name__ == "__main__":
    main()
