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

# Create a simple signature engine for testing
class SimpleSignatureEngine:
    def __init__(self):
        self.supported_algorithms = {
            'RSA-PSS': self._sign_rsa_pss,
            'RSA-PKCS1v15': self._sign_rsa_pkcs1v15,
        }
        
        self.supported_verification = {
            'RSA-PSS': self._verify_rsa_pss,
            'RSA-PKCS1v15': self._verify_rsa_pkcs1v15,
        }
    
    def _sign_rsa_pss(self, data, private_key):
        """Sign data using RSA-PSS."""
        if isinstance(private_key, bytes):
            private_key = serialization.load_der_private_key(
                private_key,
                password=None
            )
        
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def _sign_rsa_pkcs1v15(self, data, private_key):
        """Sign data using RSA-PKCS1v15."""
        if isinstance(private_key, bytes):
            private_key = serialization.load_der_private_key(
                private_key,
                password=None
            )
        
        signature = private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return signature
    
    def _verify_rsa_pss(self, data, signature, public_key):
        """Verify an RSA-PSS signature."""
        if isinstance(public_key, bytes):
            public_key = serialization.load_der_public_key(public_key)
        
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def _verify_rsa_pkcs1v15(self, data, signature, public_key):
        """Verify an RSA-PKCS1v15 signature."""
        if isinstance(public_key, bytes):
            public_key = serialization.load_der_public_key(public_key)
        
        try:
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def sign(self, data, private_key, algorithm='RSA-PSS'):
        """Sign data using the specified algorithm."""
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Call the appropriate signing function
        sign_func = self.supported_algorithms[algorithm]
        signature = sign_func(data, private_key)
        
        # Return a dictionary with all the necessary information for verification
        return {
            'algorithm': algorithm,
            'signature': signature,
            'timestamp': time.time()
        }
    
    def verify(self, data, signature_result, public_key):
        """Verify a signature."""
        algorithm = signature_result['algorithm']
        
        if algorithm not in self.supported_verification:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Call the appropriate verification function
        verify_func = self.supported_verification[algorithm]
        return verify_func(data, signature_result['signature'], public_key)

# Test results
results = {
    "key_generation": {},
    "signature": {},
    "verification": {}
}

def generate_rsa_keypair():
    """Generate an RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
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

def test_signature_verification():
    """Test signature creation and verification."""
    print("\n=== Testing Signature Creation/Verification ===")
    
    # Create a signature engine
    signature_engine = SimpleSignatureEngine()
    
    # Generate key pairs
    print("\nGenerating RSA key pair...")
    public_key, private_key = generate_rsa_keypair()
    print(f"RSA key pair generated: Public key {len(public_key)} bytes, Private key {len(private_key)} bytes")
    results["key_generation"]["rsa_2048"] = "Success"
    
    # Test data
    test_data = b"This is a test message for signature creation and verification."
    
    # Test RSA-PSS signature
    try:
        print("\nTesting RSA-PSS signature creation...")
        pss_signature = signature_engine.sign(
            data=test_data,
            private_key=private_key,
            algorithm='RSA-PSS'
        )
        print(f"RSA-PSS signature created: {len(pss_signature['signature'])} bytes")
        results["signature"]["rsa_pss"] = "Success"
    except Exception as e:
        print(f"Error creating RSA-PSS signature: {e}")
        results["signature"]["rsa_pss"] = f"Failed: {str(e)}"
        return
    
    # Test RSA-PSS verification
    try:
        print("\nTesting RSA-PSS signature verification...")
        is_valid = signature_engine.verify(
            data=test_data,
            signature_result=pss_signature,
            public_key=public_key
        )
        print(f"RSA-PSS signature verification: {is_valid}")
        results["verification"]["rsa_pss"] = "Success" if is_valid else "Failed: Invalid signature"
    except Exception as e:
        print(f"Error verifying RSA-PSS signature: {e}")
        results["verification"]["rsa_pss"] = f"Failed: {str(e)}"
    
    # Test RSA-PKCS1v15 signature
    try:
        print("\nTesting RSA-PKCS1v15 signature creation...")
        pkcs_signature = signature_engine.sign(
            data=test_data,
            private_key=private_key,
            algorithm='RSA-PKCS1v15'
        )
        print(f"RSA-PKCS1v15 signature created: {len(pkcs_signature['signature'])} bytes")
        results["signature"]["rsa_pkcs1v15"] = "Success"
    except Exception as e:
        print(f"Error creating RSA-PKCS1v15 signature: {e}")
        results["signature"]["rsa_pkcs1v15"] = f"Failed: {str(e)}"
        return
    
    # Test RSA-PKCS1v15 verification
    try:
        print("\nTesting RSA-PKCS1v15 signature verification...")
        is_valid = signature_engine.verify(
            data=test_data,
            signature_result=pkcs_signature,
            public_key=public_key
        )
        print(f"RSA-PKCS1v15 signature verification: {is_valid}")
        results["verification"]["rsa_pkcs1v15"] = "Success" if is_valid else "Failed: Invalid signature"
    except Exception as e:
        print(f"Error verifying RSA-PKCS1v15 signature: {e}")
        results["verification"]["rsa_pkcs1v15"] = f"Failed: {str(e)}"
    
    # Test verification with modified data
    try:
        print("\nTesting verification with modified data...")
        modified_data = test_data + b"modified"
        is_valid = signature_engine.verify(
            data=modified_data,
            signature_result=pss_signature,
            public_key=public_key
        )
        print(f"Verification with modified data: {is_valid}")
        results["verification"]["modified_data"] = "Success" if not is_valid else "Failed: Signature should be invalid"
    except Exception as e:
        print(f"Error verifying with modified data: {e}")
        results["verification"]["modified_data"] = f"Failed: {str(e)}"

def test_file_signature_verification():
    """Test file signature creation and verification."""
    print("\n=== Testing File Signature Creation/Verification ===")
    
    # Create a signature engine
    signature_engine = SimpleSignatureEngine()
    
    # Generate key pairs
    public_key, private_key = generate_rsa_keypair()
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create a test file
        test_file_path = os.path.join(temp_dir, "test_file.txt")
        with open(test_file_path, "w") as f:
            f.write("This is a test file for signature creation and verification.")
        
        # Signature file path
        signature_file_path = os.path.join(temp_dir, "test_file.txt.sig")
        
        # Sign the file
        print(f"\nSigning file: {test_file_path}")
        with open(test_file_path, "rb") as f:
            file_data = f.read()
        
        signature_result = signature_engine.sign(
            data=file_data,
            private_key=private_key,
            algorithm='RSA-PSS'
        )
        
        # Save the signature
        with open(signature_file_path, "w") as f:
            json.dump({
                "algorithm": signature_result["algorithm"],
                "signature": base64.b64encode(signature_result["signature"]).decode('utf-8'),
                "timestamp": signature_result["timestamp"]
            }, f)
        
        print(f"File signed successfully: {signature_file_path}")
        
        # Verify the signature
        print(f"\nVerifying signature: {signature_file_path}")
        with open(signature_file_path, "r") as f:
            signature_data = json.load(f)
        
        # Convert the data back to the format expected by the verification function
        verification_input = {
            "algorithm": signature_data["algorithm"],
            "signature": base64.b64decode(signature_data["signature"]),
            "timestamp": signature_data["timestamp"]
        }
        
        is_valid = signature_engine.verify(
            data=file_data,
            signature_result=verification_input,
            public_key=public_key
        )
        
        if is_valid:
            print("File signature verification successful")
            results["signature"]["file"] = "Success"
            results["verification"]["file"] = "Success"
        else:
            print("File signature verification failed")
            results["signature"]["file"] = "Success"
            results["verification"]["file"] = "Failed: Invalid signature"
    
    except Exception as e:
        print(f"Error with file signature/verification: {e}")
        results["signature"]["file"] = f"Failed: {str(e)}"
        results["verification"]["file"] = f"Failed: {str(e)}"
    
    finally:
        # Clean up
        for file in os.listdir(temp_dir):
            try:
                os.remove(os.path.join(temp_dir, file))
            except:
                pass
        os.rmdir(temp_dir)

def main():
    """Main function to run all tests."""
    print("=== Signature System Test ===")
    
    # Test signature and verification
    test_signature_verification()
    
    # Test file signature and verification
    test_file_signature_verification()
    
    # Print summary
    print("\n=== Test Results Summary ===")
    for category, tests in results.items():
        print(f"\n{category.upper()}:")
        for test_name, result in tests.items():
            print(f"  {test_name}: {result}")
    
    # Save results to file
    with open("signature_test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\nTest results saved to signature_test_results.json")

if __name__ == "__main__":
    main()
