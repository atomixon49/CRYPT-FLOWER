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

# Import the timestamp module
spec = importlib.util.spec_from_file_location("timestamp", os.path.join(os.getcwd(), "src (1)", "core", "timestamp.py"))
timestamp_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timestamp_module)

# Import the signatures module for the SignatureEngine
spec = importlib.util.spec_from_file_location("signatures", os.path.join(os.getcwd(), "src (1)", "core (1)", "signatures (1).py"))
signatures_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signatures_module)

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

# Test results
results = {
    "timestamp_data": {},
    "timestamp_signature": {},
    "verification": {}
}

def test_timestamp_data():
    """Test timestamping data."""
    print("\n=== Testing Data Timestamping ===")
    
    # Create a timestamp manager
    timestamp_manager = timestamp_module.TimestampManager()
    
    # Test data
    test_data = b"This is a test document for timestamping."
    
    try:
        # Create a local timestamp
        print("\nCreating local timestamp...")
        timestamp_result = timestamp_manager.timestamp_data(
            data=test_data,
            hash_algorithm="sha256",
            use_tsa=False
        )
        
        # Check the timestamp result
        print(f"Timestamp type: {timestamp_result['type']}")
        print(f"Hash algorithm: {timestamp_result['hash_algorithm']}")
        print(f"Timestamp: {timestamp_result['local_time']}")
        
        results["timestamp_data"]["local"] = "Success"
        
        # Verify the timestamp
        print("\nVerifying local timestamp...")
        verification_result = timestamp_manager.verify_timestamp(
            data=test_data,
            timestamp_data=timestamp_result
        )
        
        # Check the verification result
        if verification_result['valid']:
            print("Timestamp verification successful")
            print(f"Timestamp: {verification_result['timestamp_str']}")
            results["verification"]["local"] = "Success"
        else:
            print("Timestamp verification failed")
            results["verification"]["local"] = "Failed"
        
        # Test with modified data
        print("\nVerifying timestamp with modified data (should fail)...")
        modified_data = test_data + b" This has been tampered with."
        
        verification_result = timestamp_manager.verify_timestamp(
            data=modified_data,
            timestamp_data=timestamp_result
        )
        
        if not verification_result['valid']:
            print("Verification with modified data correctly failed")
            results["verification"]["modified_data"] = "Success"
        else:
            print("Verification with modified data incorrectly succeeded")
            results["verification"]["modified_data"] = "Failed: Should have detected tampering"
        
        # Try to create a TSA timestamp (this will likely fail without a real TSA server)
        print("\nTrying to create a TSA timestamp (may fail without a real TSA server)...")
        try:
            tsa_timestamp_result = timestamp_manager.timestamp_data(
                data=test_data,
                hash_algorithm="sha256",
                use_tsa=True
            )
            
            print(f"TSA timestamp type: {tsa_timestamp_result['type']}")
            print(f"TSA timestamp info: {tsa_timestamp_result.get('timestamp_info', {})}")
            
            results["timestamp_data"]["tsa"] = "Success"
        except Exception as e:
            print(f"TSA timestamping failed (expected without a real TSA server): {e}")
            results["timestamp_data"]["tsa"] = f"Failed (expected): {str(e)}"
    
    except Exception as e:
        print(f"Error with data timestamping: {e}")
        results["timestamp_data"]["general"] = f"Failed: {str(e)}"

def test_timestamp_signature():
    """Test timestamping a signature."""
    print("\n=== Testing Signature Timestamping ===")
    
    # Create a key manager
    key_manager = SimpleKeyManager()
    
    # Generate a key pair
    print("\nGenerating key pair...")
    public_key_id, private_key_id = key_manager.generate_asymmetric_keypair(algorithm='RSA', key_size=2048)
    
    # Create a signature engine
    signature_engine = signatures_module.SignatureEngine()
    
    # Create a timestamp manager
    timestamp_manager = timestamp_module.TimestampManager()
    
    # Test data
    test_data = b"This is a test document for signature timestamping."
    
    try:
        # Sign the data
        print("\nSigning data...")
        private_key = key_manager.get_key(private_key_id)
        
        signature_result = signature_engine.sign(
            data=test_data,
            private_key=private_key,
            algorithm="RSA-PSS"
        )
        
        print(f"Signature algorithm: {signature_result['algorithm']}")
        print(f"Signature size: {len(signature_result['signature'])} bytes")
        
        # Convert signature to base64 for JSON serialization
        signature_data = {
            'algorithm': signature_result['algorithm'],
            'signature': base64.b64encode(signature_result['signature']).decode('ascii'),
            'timestamp': signature_result['timestamp']
        }
        
        # Timestamp the signature
        print("\nTimestamping the signature...")
        timestamped_signature = timestamp_manager.timestamp_signature(
            signature_data=signature_data,
            hash_algorithm="sha256",
            use_tsa=False
        )
        
        # Check the timestamped signature
        print(f"Timestamp type: {timestamped_signature['timestamp']['type']}")
        print(f"Timestamp: {timestamped_signature['timestamp'].get('local_time')}")
        
        results["timestamp_signature"]["local"] = "Success"
        
        # Verify the signature timestamp
        print("\nVerifying signature timestamp...")
        verification_result = timestamp_manager.verify_signature_timestamp(
            signature_data=timestamped_signature
        )
        
        # Check the verification result
        if verification_result['valid']:
            print("Signature timestamp verification successful")
            print(f"Timestamp: {verification_result['timestamp_str']}")
            results["verification"]["signature"] = "Success"
        else:
            print("Signature timestamp verification failed")
            results["verification"]["signature"] = "Failed"
    
    except Exception as e:
        print(f"Error with signature timestamping: {e}")
        results["timestamp_signature"]["general"] = f"Failed: {str(e)}"

def main():
    """Main function to run all tests."""
    print("=== Timestamp Test ===")
    
    # Test data timestamping
    test_timestamp_data()
    
    # Test signature timestamping
    test_timestamp_signature()
    
    # Print summary
    print("\n=== Test Results Summary ===")
    for category, tests in results.items():
        print(f"\n{category.upper()}:")
        for test_name, result in tests.items():
            print(f"  {test_name}: {result}")
    
    # Save results to file
    with open("timestamp_test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\nTest results saved to timestamp_test_results.json")

if __name__ == "__main__":
    main()
