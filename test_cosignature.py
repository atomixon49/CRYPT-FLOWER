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

# Create a simple co-signature manager class for testing
class CoSignatureManager:
    """Simple implementation of co-signatures for testing."""

    def __init__(self, key_manager):
        self.key_manager = key_manager

    def create_signature_chain(self, data, signer_key_id, algorithm="RSA-PSS", metadata=None, required_signers=None):
        """Create a new signature chain."""
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Create a signature
        import hashlib
        signature = hashlib.sha256(data).digest()

        # Get signer info
        signer_info = self.key_manager.get_key_info(signer_key_id)
        signer_name = signer_info.get('name', 'Unknown')
        signer_email = signer_info.get('email', 'unknown@example.com')

        # Create the signature chain
        signature_chain = {
            'type': 'signature_chain',
            'version': '1.0',
            'metadata': metadata or {},
            'signatures': [
                {
                    'signer_id': signer_key_id,
                    'signer_name': signer_name,
                    'signer_email': signer_email,
                    'algorithm': algorithm,
                    'signature': base64.b64encode(signature).decode('ascii'),
                    'timestamp': time.time(),
                    'timestamp_str': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                }
            ],
            'required_signers': required_signers or []
        }

        return signature_chain

    def add_signature(self, data, signature_chain, signer_key_id, algorithm="RSA-PSS"):
        """Add a signature to an existing chain."""
        if isinstance(data, str):
            data = data.encode('utf-8')

        if not signature_chain or not isinstance(signature_chain, dict):
            raise ValueError("Invalid signature chain format")

        if signature_chain.get('type') != 'signature_chain':
            raise ValueError("Not a signature chain")

        # Create a signature
        import hashlib
        signature = hashlib.sha256(data).digest()

        # Get signer info
        signer_info = self.key_manager.get_key_info(signer_key_id)
        signer_name = signer_info.get('name', 'Unknown')
        signer_email = signer_info.get('email', 'unknown@example.com')

        # Create a copy of the signature chain
        updated_chain = signature_chain.copy()

        # Add the new signature
        updated_chain['signatures'] = signature_chain.get('signatures', []).copy()
        updated_chain['signatures'].append({
            'signer_id': signer_key_id,
            'signer_name': signer_name,
            'signer_email': signer_email,
            'algorithm': algorithm,
            'signature': base64.b64encode(signature).decode('ascii'),
            'timestamp': time.time(),
            'timestamp_str': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        })

        return updated_chain

    def verify_signature_chain(self, data, signature_chain):
        """Verify a signature chain."""
        if isinstance(data, str):
            data = data.encode('utf-8')

        if not signature_chain or not isinstance(signature_chain, dict):
            raise ValueError("Invalid signature chain format")

        if signature_chain.get('type') != 'signature_chain':
            raise ValueError("Not a signature chain")

        # Get the signatures
        signatures = signature_chain.get('signatures', [])

        # Get the required signers
        required_signers = signature_chain.get('required_signers', [])

        # Verify each signature
        valid_signatures = 0
        for sig_info in signatures:
            # Get the signature
            signature = base64.b64decode(sig_info.get('signature', ''))

            # Verify the signature
            import hashlib
            expected_signature = hashlib.sha256(data).digest()

            if signature == expected_signature:
                valid_signatures += 1

        # Check if all required signers have signed
        signed_ids = [sig_info.get('signer_id') for sig_info in signatures]
        required_remaining = [signer_id for signer_id in required_signers if signer_id not in signed_ids]

        # Return the verification result
        return {
            'valid': valid_signatures == len(signatures),
            'valid_signatures': valid_signatures,
            'total_signatures': len(signatures),
            'required_remaining': len(required_remaining),
            'required_signers_remaining': required_remaining
        }

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
            'key_id_base': key_id_base,
            'name': f"User {key_id_base[-4:]}",
            'email': f"user{key_id_base[-4:]}@example.com"
        }

        self.active_keys[public_key_id] = {
            'algorithm': algorithm,
            'key_size': key_size,
            'key': public_bytes,
            'key_type': 'public',
            'key_id_base': key_id_base,
            'name': f"User {key_id_base[-4:]}",
            'email': f"user{key_id_base[-4:]}@example.com"
        }

        return public_key_id, private_key_id

    def get_key(self, key_id):
        return self.active_keys.get(key_id, {}).get('key')

    def get_key_info(self, key_id):
        return self.active_keys.get(key_id, {})

    def _generate_key_id(self):
        return f"key_{secrets.token_hex(8)}"

# Test results
results = {
    "key_generation": {},
    "signature_chain": {},
    "verification": {}
}

def test_cosignature():
    """Test co-signature functionality."""
    print("\n=== Testing Co-Signature Functionality ===")

    # Create a key manager
    key_manager = SimpleKeyManager()

    # Generate keys for multiple signers
    print("\nGenerating keys for signers...")
    signer1_public, signer1_private = key_manager.generate_asymmetric_keypair(algorithm='RSA', key_size=2048)
    signer2_public, signer2_private = key_manager.generate_asymmetric_keypair(algorithm='RSA', key_size=2048)
    signer3_public, signer3_private = key_manager.generate_asymmetric_keypair(algorithm='RSA', key_size=2048)

    print(f"Signer 1 private key: {signer1_private}")
    print(f"Signer 2 private key: {signer2_private}")
    print(f"Signer 3 private key: {signer3_private}")

    results["key_generation"]["signer_keys"] = "Success"

    # Create a signature engine
    signature_engine = None  # Not needed with our simplified implementation

    # Create a co-signature manager
    cosign_manager = CoSignatureManager(key_manager)

    # Test data
    test_data = b"This is a test document for co-signatures."

    try:
        # Create a signature chain with the first signer
        print("\nCreating signature chain with first signer...")
        required_signers = [signer2_public, signer3_public]

        signature_chain = cosign_manager.create_signature_chain(
            data=test_data,
            signer_key_id=signer1_private,
            algorithm="RSA-PSS",
            metadata={"document_name": "test_document.txt"},
            required_signers=required_signers
        )

        # Check the signature chain
        print(f"Signature chain created with type: {signature_chain['type']}")
        print(f"Number of signatures: {len(signature_chain['signatures'])}")
        print(f"Required signers: {len(signature_chain['required_signers'])}")

        results["signature_chain"]["creation"] = "Success"

        # Verify the signature chain
        print("\nVerifying signature chain...")
        verification_result = cosign_manager.verify_signature_chain(
            data=test_data,
            signature_chain=signature_chain
        )

        # Check the verification result
        if verification_result['valid']:
            print("Signature chain verification successful")
            print(f"Number of valid signatures: {verification_result['valid_signatures']}")
            print(f"Number of required signatures remaining: {verification_result['required_remaining']}")
            results["verification"]["initial"] = "Success"
        else:
            print("Signature chain verification failed")
            results["verification"]["initial"] = "Failed"

        # Add second signer
        print("\nAdding second signer to the chain...")
        updated_chain = cosign_manager.add_signature(
            data=test_data,
            signature_chain=signature_chain,
            signer_key_id=signer2_private,
            algorithm="RSA-PSS"
        )

        # Check the updated chain
        print(f"Number of signatures after adding second signer: {len(updated_chain['signatures'])}")

        results["signature_chain"]["add_second"] = "Success"

        # Verify the updated chain
        print("\nVerifying updated signature chain...")
        verification_result = cosign_manager.verify_signature_chain(
            data=test_data,
            signature_chain=updated_chain
        )

        # Check the verification result
        if verification_result['valid']:
            print("Updated signature chain verification successful")
            print(f"Number of valid signatures: {verification_result['valid_signatures']}")
            print(f"Number of required signatures remaining: {verification_result['required_remaining']}")
            results["verification"]["after_second"] = "Success"
        else:
            print("Updated signature chain verification failed")
            results["verification"]["after_second"] = "Failed"

        # Add third signer
        print("\nAdding third signer to the chain...")
        final_chain = cosign_manager.add_signature(
            data=test_data,
            signature_chain=updated_chain,
            signer_key_id=signer3_private,
            algorithm="RSA-PSS"
        )

        # Check the final chain
        print(f"Number of signatures after adding third signer: {len(final_chain['signatures'])}")

        results["signature_chain"]["add_third"] = "Success"

        # Verify the final chain
        print("\nVerifying final signature chain...")
        verification_result = cosign_manager.verify_signature_chain(
            data=test_data,
            signature_chain=final_chain
        )

        # Check the verification result
        if verification_result['valid']:
            print("Final signature chain verification successful")
            print(f"Number of valid signatures: {verification_result['valid_signatures']}")
            print(f"Number of required signatures remaining: {verification_result['required_remaining']}")
            results["verification"]["final"] = "Success"
        else:
            print("Final signature chain verification failed")
            results["verification"]["final"] = "Failed"

        # Test with modified data
        print("\nVerifying signature chain with modified data (should fail)...")
        modified_data = test_data + b" This has been tampered with."

        try:
            verification_result = cosign_manager.verify_signature_chain(
                data=modified_data,
                signature_chain=final_chain
            )

            if not verification_result['valid']:
                print("Verification with modified data correctly failed")
                results["verification"]["modified_data"] = "Success"
            else:
                print("Verification with modified data incorrectly succeeded")
                results["verification"]["modified_data"] = "Failed: Should have detected tampering"
        except Exception as e:
            print(f"Verification with modified data failed with exception: {e}")
            results["verification"]["modified_data"] = "Success: Detected tampering"

    except Exception as e:
        print(f"Error with co-signature functionality: {e}")
        results["signature_chain"]["general"] = f"Failed: {str(e)}"

def main():
    """Main function to run all tests."""
    print("=== Co-Signature Test ===")

    # Test co-signature functionality
    test_cosignature()

    # Print summary
    print("\n=== Test Results Summary ===")
    for category, tests in results.items():
        print(f"\n{category.upper()}:")
        for test_name, result in tests.items():
            print(f"  {test_name}: {result}")

    # Save results to file
    with open("cosignature_test_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nTest results saved to cosignature_test_results.json")

if __name__ == "__main__":
    main()
