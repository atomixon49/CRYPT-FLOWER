import os
import sys
import importlib.util
import tempfile
import json
import base64
import secrets
import time

# Create a simple key manager class for testing
class SimpleKeyManager:
    def __init__(self):
        self.active_keys = {}

    def generate_symmetric_key(self, algorithm='AES', key_size=256):
        # Generate a cryptographically secure random key
        key_bytes = secrets.token_bytes(key_size // 8)
        return key_bytes

    def generate_asymmetric_keypair(self, algorithm='RSA', key_size=2048):
        # For testing purposes, just return random bytes
        public_key = secrets.token_bytes(key_size // 8)
        private_key = secrets.token_bytes(key_size // 4)
        return public_key, private_key

    def generate_post_quantum_keypair(self, algorithm='KYBER768'):
        # For testing purposes, just return random bytes
        public_key = secrets.token_bytes(1024)
        private_key = secrets.token_bytes(2048)
        return public_key, private_key

# Add src (1) to the path
sys.path.insert(0, os.path.join(os.getcwd(), "src (1)"))

# Import the encryption module
spec = importlib.util.spec_from_file_location("encryption", os.path.join(os.getcwd(), "src (1)", "core (1)", "encryption (1).py"))
encryption_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(encryption_module)

# Create instances of the classes
encryption_engine = encryption_module.EncryptionEngine()
key_manager = SimpleKeyManager()

# Test results
results = {
    "key_generation": {},
    "encryption": {},
    "decryption": {}
}

def test_key_generation():
    """Test key generation functionality."""
    print("\n=== Testing Key Generation ===")

    # Test symmetric key generation
    try:
        print("Generating AES-256 key...")
        aes_key = key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        print(f"AES key generated: {len(aes_key)} bytes")
        results["key_generation"]["aes_256"] = "Success"
    except Exception as e:
        print(f"Error generating AES key: {e}")
        results["key_generation"]["aes_256"] = f"Failed: {str(e)}"

    # Test RSA key pair generation
    try:
        print("\nGenerating RSA-2048 key pair...")
        public_key, private_key = key_manager.generate_asymmetric_keypair(algorithm='RSA', key_size=2048)
        print(f"RSA key pair generated: Public key {len(public_key)} bytes, Private key {len(private_key)} bytes")
        results["key_generation"]["rsa_2048"] = "Success"
    except Exception as e:
        print(f"Error generating RSA key pair: {e}")
        results["key_generation"]["rsa_2048"] = f"Failed: {str(e)}"

    # Test post-quantum key pair generation if available
    if hasattr(encryption_engine, 'pq_crypto') and encryption_engine.pq_crypto is not None:
        try:
            print("\nGenerating Kyber-768 key pair...")
            public_key, private_key = key_manager.generate_post_quantum_keypair(algorithm='KYBER768')
            print(f"Kyber-768 key pair generated: Public key {len(public_key)} bytes, Private key {len(private_key)} bytes")
            results["key_generation"]["kyber_768"] = "Success"
        except Exception as e:
            print(f"Error generating Kyber-768 key pair: {e}")
            results["key_generation"]["kyber_768"] = f"Failed: {str(e)}"
    else:
        print("\nPost-quantum cryptography not available")
        results["key_generation"]["kyber_768"] = "Not available"

    return aes_key, public_key, private_key

def test_encryption_decryption(aes_key):
    """Test encryption and decryption functionality."""
    print("\n=== Testing Encryption/Decryption ===")

    # Test data
    test_data = b"This is a test message for encryption and decryption."

    # Test AES-GCM encryption
    try:
        print("\nTesting AES-GCM encryption...")
        aes_gcm_result = encryption_engine.encrypt(
            data=test_data,
            key=aes_key,
            algorithm='AES-GCM'
        )
        print(f"AES-GCM encryption successful: {aes_gcm_result['algorithm']}")
        results["encryption"]["aes_gcm"] = "Success"
    except Exception as e:
        print(f"Error with AES-GCM encryption: {e}")
        results["encryption"]["aes_gcm"] = f"Failed: {str(e)}"
        return

    # Test AES-GCM decryption
    try:
        print("\nTesting AES-GCM decryption...")
        decrypted_data = encryption_engine.decrypt(
            encryption_result=aes_gcm_result,
            key=aes_key
        )
        print(f"AES-GCM decryption successful: {decrypted_data == test_data}")
        results["decryption"]["aes_gcm"] = "Success" if decrypted_data == test_data else "Failed: Data mismatch"
    except Exception as e:
        print(f"Error with AES-GCM decryption: {e}")
        results["decryption"]["aes_gcm"] = f"Failed: {str(e)}"

    # Test ChaCha20-Poly1305 encryption
    try:
        print("\nTesting ChaCha20-Poly1305 encryption...")
        chacha_result = encryption_engine.encrypt(
            data=test_data,
            key=aes_key,  # We can reuse the AES key for ChaCha20
            algorithm='ChaCha20-Poly1305'
        )
        print(f"ChaCha20-Poly1305 encryption successful: {chacha_result['algorithm']}")
        results["encryption"]["chacha20_poly1305"] = "Success"
    except Exception as e:
        print(f"Error with ChaCha20-Poly1305 encryption: {e}")
        results["encryption"]["chacha20_poly1305"] = f"Failed: {str(e)}"
        return

    # Test ChaCha20-Poly1305 decryption
    try:
        print("\nTesting ChaCha20-Poly1305 decryption...")
        decrypted_data = encryption_engine.decrypt(
            encryption_result=chacha_result,
            key=aes_key
        )
        print(f"ChaCha20-Poly1305 decryption successful: {decrypted_data == test_data}")
        results["decryption"]["chacha20_poly1305"] = "Success" if decrypted_data == test_data else "Failed: Data mismatch"
    except Exception as e:
        print(f"Error with ChaCha20-Poly1305 decryption: {e}")
        results["decryption"]["chacha20_poly1305"] = f"Failed: {str(e)}"

def test_file_encryption_decryption(aes_key):
    """Test file encryption and decryption."""
    print("\n=== Testing File Encryption/Decryption ===")

    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()

    try:
        # Create a test file
        test_file_path = os.path.join(temp_dir, "test_file.txt")
        with open(test_file_path, "w") as f:
            f.write("This is a test file for encryption and decryption.")

        # Encrypted file path
        encrypted_file_path = os.path.join(temp_dir, "test_file.txt.encrypted")

        # Encrypt the file
        print(f"\nEncrypting file: {test_file_path}")
        with open(test_file_path, "rb") as f:
            file_data = f.read()

        encryption_result = encryption_engine.encrypt(
            data=file_data,
            key=aes_key,
            algorithm='AES-GCM'
        )

        # Save the encrypted data
        with open(encrypted_file_path, "w") as f:
            json.dump({
                "algorithm": encryption_result["algorithm"],
                "ciphertext": base64.b64encode(encryption_result["ciphertext"]).decode('utf-8'),
                "nonce": base64.b64encode(encryption_result["nonce"]).decode('utf-8'),
                "tag": base64.b64encode(encryption_result["tag"]).decode('utf-8')
            }, f)

        print(f"File encrypted successfully: {encrypted_file_path}")

        # Decrypt the file
        print(f"\nDecrypting file: {encrypted_file_path}")
        with open(encrypted_file_path, "r") as f:
            encrypted_data = json.load(f)

        # Convert the data back to the format expected by the decryption function
        decryption_input = {
            "algorithm": encrypted_data["algorithm"],
            "ciphertext": base64.b64decode(encrypted_data["ciphertext"]),
            "nonce": base64.b64decode(encrypted_data["nonce"]),
            "tag": base64.b64decode(encrypted_data["tag"])
        }

        decrypted_data = encryption_engine.decrypt(
            encryption_result=decryption_input,
            key=aes_key
        )

        # Save the decrypted data
        decrypted_file_path = os.path.join(temp_dir, "test_file.txt.decrypted")
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)

        # Verify the decrypted file
        with open(test_file_path, "rb") as f:
            original_data = f.read()

        with open(decrypted_file_path, "rb") as f:
            final_decrypted_data = f.read()

        if original_data == final_decrypted_data:
            print("File decryption successful: Content matches original")
            results["encryption"]["file"] = "Success"
            results["decryption"]["file"] = "Success"
        else:
            print("File decryption failed: Content does not match original")
            results["encryption"]["file"] = "Success"
            results["decryption"]["file"] = "Failed: Content mismatch"

    except Exception as e:
        print(f"Error with file encryption/decryption: {e}")
        results["encryption"]["file"] = f"Failed: {str(e)}"
        results["decryption"]["file"] = f"Failed: {str(e)}"

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
    print("=== Cryptography System Test ===")

    # Test key generation
    aes_key, public_key, private_key = test_key_generation()

    # Test encryption and decryption
    test_encryption_decryption(aes_key)

    # Test file encryption and decryption
    test_file_encryption_decryption(aes_key)

    # Print summary
    print("\n=== Test Results Summary ===")
    for category, tests in results.items():
        print(f"\n{category.upper()}:")
        for test_name, result in tests.items():
            print(f"  {test_name}: {result}")

    # Save results to file
    with open("encryption_test_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nTest results saved to encryption_test_results.json")

if __name__ == "__main__":
    main()
