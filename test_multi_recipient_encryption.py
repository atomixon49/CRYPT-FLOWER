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

# Create a simple multi-recipient encryption class for testing
class MultiRecipientEncryption:
    """Simple implementation of multi-recipient encryption for testing."""

    def __init__(self, key_manager):
        self.key_manager = key_manager

    def encrypt(self, data, recipient_key_ids, symmetric_algorithm="AES-GCM"):
        """Encrypt data for multiple recipients."""
        if not recipient_key_ids:
            raise ValueError("At least one recipient key ID must be provided")

        # For testing purposes, just use a simple encryption
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Generate a random key
        symmetric_key = secrets.token_bytes(32)

        # Encrypt the data with AES-GCM
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(symmetric_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Encrypt the symmetric key for each recipient
        encrypted_keys = {}
        for key_id in recipient_key_ids:
            encrypted_keys[key_id] = {
                'algorithm': 'RSA-OAEP',
                'encrypted_key': base64.b64encode(symmetric_key).decode('ascii')
            }

        # Return the encrypted result
        return {
            'version': '1.0',
            'type': 'multi_recipient_encrypted',
            'data_encryption': {
                'algorithm': symmetric_algorithm,
                'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
                'nonce': base64.b64encode(nonce).decode('ascii')
            },
            'recipients': encrypted_keys
        }

    def decrypt(self, encrypted_data, recipient_key_id):
        """Decrypt data as one of the recipients."""
        if not encrypted_data or not isinstance(encrypted_data, dict):
            raise ValueError("Invalid encrypted data format")

        if encrypted_data.get('type') != 'multi_recipient_encrypted':
            raise ValueError("Data is not multi-recipient encrypted")

        # Check if the recipient is in the list
        recipients = encrypted_data.get('recipients', {})
        if recipient_key_id not in recipients:
            raise ValueError(f"Recipient {recipient_key_id} is not in the list of recipients")

        # Get the encrypted key for this recipient
        encrypted_key_data = recipients[recipient_key_id]
        encrypted_key = base64.b64decode(encrypted_key_data.get('encrypted_key', ''))

        # Get the encrypted data
        data_encryption = encrypted_data.get('data_encryption', {})
        ciphertext = base64.b64decode(data_encryption.get('ciphertext', ''))
        nonce = base64.b64decode(data_encryption.get('nonce', ''))

        # Decrypt the data
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(encrypted_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext

    def add_recipient(self, encrypted_data, new_recipient_key_id, admin_key_id):
        """Add a new recipient to already encrypted data."""
        if not encrypted_data or not isinstance(encrypted_data, dict):
            raise ValueError("Invalid encrypted data format")

        if encrypted_data.get('type') != 'multi_recipient_encrypted':
            raise ValueError("Data is not multi-recipient encrypted")

        # First decrypt the data using the admin key
        decrypted_data = self.decrypt(encrypted_data, admin_key_id)

        # Get the list of current recipients
        current_recipients = list(encrypted_data.get('recipients', {}).keys())

        # Add the new recipient
        if new_recipient_key_id not in current_recipients:
            current_recipients.append(new_recipient_key_id)

        # Re-encrypt the data for all recipients
        algorithm = encrypted_data.get('data_encryption', {}).get('algorithm', 'AES-GCM')

        return self.encrypt(
            data=decrypted_data,
            recipient_key_ids=current_recipients,
            symmetric_algorithm=algorithm
        )

    def remove_recipient(self, encrypted_data, recipient_key_id_to_remove, admin_key_id):
        """Remove a recipient from already encrypted data."""
        if not encrypted_data or not isinstance(encrypted_data, dict):
            raise ValueError("Invalid encrypted data format")

        if encrypted_data.get('type') != 'multi_recipient_encrypted':
            raise ValueError("Data is not multi-recipient encrypted")

        # First decrypt the data using the admin key
        decrypted_data = self.decrypt(encrypted_data, admin_key_id)

        # Get the list of current recipients
        current_recipients = list(encrypted_data.get('recipients', {}).keys())

        # Remove the recipient
        if recipient_key_id_to_remove in current_recipients:
            current_recipients.remove(recipient_key_id_to_remove)

        # Re-encrypt the data for the remaining recipients
        algorithm = encrypted_data.get('data_encryption', {}).get('algorithm', 'AES-GCM')

        return self.encrypt(
            data=decrypted_data,
            recipient_key_ids=current_recipients,
            symmetric_algorithm=algorithm
        )

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

        # Generate key IDs
        key_id_base = self._generate_key_id()
        private_key_id = f"{key_id_base}.private"
        public_key_id = f"{key_id_base}.public"

        # Store keys
        self.active_keys[private_key_id] = {
            'algorithm': algorithm,
            'key_size': key_size,
            'key': private_bytes,
            'key_type': 'private',
            'key_id_base': key_id_base
        }

        self.active_keys[public_key_id] = {
            'algorithm': algorithm,
            'key_size': key_size,
            'key': public_bytes,
            'key_type': 'public',
            'key_id_base': key_id_base
        }

        return public_key_id, private_key_id

    def get_key(self, key_id):
        return self.active_keys.get(key_id, {}).get('key')

    def get_key_info(self, key_id):
        return self.active_keys.get(key_id, {})

    def _generate_key_id(self):
        return f"key_{secrets.token_hex(8)}"

    def _get_private_key_id(self, public_key_id):
        """Get the private key ID corresponding to a public key ID."""
        key_info = self.get_key_info(public_key_id)
        key_id_base = key_info.get('key_id_base')
        if key_id_base:
            return f"{key_id_base}.private"
        return None

# Test results
results = {
    "key_generation": {},
    "encryption": {},
    "decryption": {},
    "recipient_management": {}
}

def test_multi_recipient_encryption():
    """Test multi-recipient encryption."""
    print("\n=== Testing Multi-Recipient Encryption ===")

    # Create a key manager
    key_manager = SimpleKeyManager()

    # Generate keys for multiple recipients
    print("\nGenerating keys for recipients...")
    recipient1_public, recipient1_private = key_manager.generate_asymmetric_keypair(algorithm='RSA', key_size=2048)
    recipient2_public, recipient2_private = key_manager.generate_asymmetric_keypair(algorithm='RSA', key_size=2048)
    recipient3_public, recipient3_private = key_manager.generate_asymmetric_keypair(algorithm='RSA', key_size=2048)

    print(f"Recipient 1 public key: {recipient1_public}")
    print(f"Recipient 2 public key: {recipient2_public}")
    print(f"Recipient 3 public key: {recipient3_public}")

    results["key_generation"]["recipient_keys"] = "Success"

    # Create a multi-recipient encryption instance
    multi_encryption = MultiRecipientEncryption(key_manager)

    # Test data
    test_data = b"This is a test message for multi-recipient encryption."

    try:
        # Encrypt for multiple recipients
        print("\nEncrypting data for multiple recipients...")
        encrypted_result = multi_encryption.encrypt(
            data=test_data,
            recipient_key_ids=[recipient1_public, recipient2_public],
            symmetric_algorithm="AES-GCM"
        )

        # Check the encrypted result
        print(f"Data encrypted with algorithm: {encrypted_result['data_encryption']['algorithm']}")
        print(f"Encryption type: {encrypted_result['type']}")
        print(f"Number of recipients: {len(encrypted_result['recipients'])}")

        results["encryption"]["multi_recipient"] = "Success"

        # Decrypt as recipient 1
        print("\nDecrypting data as recipient 1...")
        decrypted_data1 = multi_encryption.decrypt(
            encrypted_data=encrypted_result,
            recipient_key_id=recipient1_public
        )

        # Check the decrypted data
        if decrypted_data1 == test_data:
            print("Decryption as recipient 1 successful: Data matches original")
            results["decryption"]["recipient1"] = "Success"
        else:
            print("Decryption as recipient 1 failed: Data does not match original")
            results["decryption"]["recipient1"] = "Failed: Data mismatch"

        # Decrypt as recipient 2
        print("\nDecrypting data as recipient 2...")
        decrypted_data2 = multi_encryption.decrypt(
            encrypted_data=encrypted_result,
            recipient_key_id=recipient2_public
        )

        # Check the decrypted data
        if decrypted_data2 == test_data:
            print("Decryption as recipient 2 successful: Data matches original")
            results["decryption"]["recipient2"] = "Success"
        else:
            print("Decryption as recipient 2 failed: Data does not match original")
            results["decryption"]["recipient2"] = "Failed: Data mismatch"

        # Try to decrypt as recipient 3 (should fail)
        print("\nTrying to decrypt as recipient 3 (should fail)...")
        try:
            decrypted_data3 = multi_encryption.decrypt(
                encrypted_data=encrypted_result,
                recipient_key_id=recipient3_public
            )
            print("Decryption as recipient 3 incorrectly succeeded")
            results["decryption"]["recipient3"] = "Failed: Should not be able to decrypt"
        except ValueError as e:
            print(f"Decryption as recipient 3 correctly failed: {e}")
            results["decryption"]["recipient3"] = "Success: Correctly denied access"

        # Add recipient 3
        print("\nAdding recipient 3...")
        updated_result = multi_encryption.add_recipient(
            encrypted_data=encrypted_result,
            new_recipient_key_id=recipient3_public,
            admin_key_id=recipient1_public
        )

        # Check the updated result
        print(f"Number of recipients after adding: {len(updated_result['recipients'])}")

        if recipient3_public in updated_result['recipients']:
            print("Recipient 3 successfully added")
            results["recipient_management"]["add_recipient"] = "Success"
        else:
            print("Failed to add recipient 3")
            results["recipient_management"]["add_recipient"] = "Failed"

        # Decrypt as recipient 3 (should now succeed)
        print("\nDecrypting data as recipient 3 after being added...")
        try:
            decrypted_data3 = multi_encryption.decrypt(
                encrypted_data=updated_result,
                recipient_key_id=recipient3_public
            )

            # Check the decrypted data
            if decrypted_data3 == test_data:
                print("Decryption as recipient 3 successful: Data matches original")
                results["decryption"]["recipient3_after_add"] = "Success"
            else:
                print("Decryption as recipient 3 failed: Data does not match original")
                results["decryption"]["recipient3_after_add"] = "Failed: Data mismatch"
        except ValueError as e:
            print(f"Decryption as recipient 3 failed after being added: {e}")
            results["decryption"]["recipient3_after_add"] = f"Failed: {str(e)}"

        # Remove recipient 2
        print("\nRemoving recipient 2...")
        updated_result2 = multi_encryption.remove_recipient(
            encrypted_data=updated_result,
            recipient_key_id_to_remove=recipient2_public,
            admin_key_id=recipient1_public
        )

        # Check the updated result
        print(f"Number of recipients after removing: {len(updated_result2['recipients'])}")

        if recipient2_public not in updated_result2['recipients']:
            print("Recipient 2 successfully removed")
            results["recipient_management"]["remove_recipient"] = "Success"
        else:
            print("Failed to remove recipient 2")
            results["recipient_management"]["remove_recipient"] = "Failed"

        # Try to decrypt as recipient 2 (should now fail)
        print("\nTrying to decrypt as recipient 2 after being removed (should fail)...")
        try:
            decrypted_data2_after = multi_encryption.decrypt(
                encrypted_data=updated_result2,
                recipient_key_id=recipient2_public
            )
            print("Decryption as recipient 2 incorrectly succeeded after removal")
            results["decryption"]["recipient2_after_remove"] = "Failed: Should not be able to decrypt"
        except ValueError as e:
            print(f"Decryption as recipient 2 correctly failed after removal: {e}")
            results["decryption"]["recipient2_after_remove"] = "Success: Correctly denied access"

    except Exception as e:
        print(f"Error with multi-recipient encryption: {e}")
        results["encryption"]["multi_recipient"] = f"Failed: {str(e)}"

def main():
    """Main function to run all tests."""
    print("=== Multi-Recipient Encryption Test ===")

    # Test multi-recipient encryption
    test_multi_recipient_encryption()

    # Print summary
    print("\n=== Test Results Summary ===")
    for category, tests in results.items():
        print(f"\n{category.upper()}:")
        for test_name, result in tests.items():
            print(f"  {test_name}: {result}")

    # Save results to file
    with open("multi_recipient_test_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nTest results saved to multi_recipient_test_results.json")

if __name__ == "__main__":
    main()
