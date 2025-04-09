import os
import sys
import importlib.util
import tempfile
import json
import base64
import secrets
import time
import shutil

# Create a simple file handler for testing
class SimpleTextFileHandler:
    def __init__(self, encryption_engine):
        self.encryption_engine = encryption_engine
    
    def encrypt_file(self, input_path, output_path, key=None, password=None, algorithm='AES-GCM'):
        """Encrypt a text file."""
        # Read the file
        with open(input_path, 'rb') as f:
            file_data = f.read()
        
        # Use password-based encryption if a password is provided
        if password:
            # For testing purposes, derive a key from the password
            # In a real implementation, this would use a proper key derivation function
            key = self._derive_key_from_password(password)
        
        # Encrypt the data
        encryption_result = self.encryption_engine.encrypt(
            data=file_data,
            key=key,
            algorithm=algorithm
        )
        
        # Save the encrypted data
        with open(output_path, 'w') as f:
            json.dump({
                'algorithm': encryption_result['algorithm'],
                'ciphertext': base64.b64encode(encryption_result['ciphertext']).decode('utf-8'),
                'nonce': base64.b64encode(encryption_result['nonce']).decode('utf-8'),
                'tag': base64.b64encode(encryption_result['tag']).decode('utf-8')
            }, f)
        
        return True
    
    def decrypt_file(self, input_path, output_path, key=None, password=None):
        """Decrypt a text file."""
        # Read the encrypted file
        with open(input_path, 'r') as f:
            encrypted_data = json.load(f)
        
        # Use password-based encryption if a password is provided
        if password:
            # For testing purposes, derive a key from the password
            key = self._derive_key_from_password(password)
        
        # Convert the data back to the format expected by the decryption function
        decryption_input = {
            'algorithm': encrypted_data['algorithm'],
            'ciphertext': base64.b64decode(encrypted_data['ciphertext']),
            'nonce': base64.b64decode(encrypted_data['nonce']),
            'tag': base64.b64decode(encrypted_data['tag'])
        }
        
        # Decrypt the data
        decrypted_data = self.encryption_engine.decrypt(
            encryption_result=decryption_input,
            key=key
        )
        
        # Save the decrypted data
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        return True
    
    def _derive_key_from_password(self, password, key_size=256):
        """Derive a key from a password."""
        # For testing purposes, use a simple key derivation
        # In a real implementation, this would use a proper key derivation function
        import hashlib
        key = hashlib.sha256(password.encode()).digest()
        return key

# Add src (1) to the path
sys.path.insert(0, os.path.join(os.getcwd(), "src (1)"))

# Import the encryption module
spec = importlib.util.spec_from_file_location("encryption", os.path.join(os.getcwd(), "src (1)", "core (1)", "encryption (1).py"))
encryption_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(encryption_module)

# Create instances of the classes
encryption_engine = encryption_module.EncryptionEngine()
text_file_handler = SimpleTextFileHandler(encryption_engine)

# Test results
results = {
    "file_encryption": {},
    "file_decryption": {},
    "encoding_preservation": {}
}

def test_text_file_encryption_decryption():
    """Test text file encryption and decryption."""
    print("\n=== Testing Text File Encryption/Decryption ===")
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create a test file
        test_file_path = os.path.join(temp_dir, "test_file.txt")
        with open(test_file_path, "w") as f:
            f.write("This is a test file for encryption and decryption.")
        
        # Generate a key
        key = secrets.token_bytes(32)  # 256 bits
        
        # Encrypted file path
        encrypted_file_path = os.path.join(temp_dir, "test_file.txt.encrypted")
        
        # Encrypt the file
        print(f"\nEncrypting file: {test_file_path}")
        success = text_file_handler.encrypt_file(
            input_path=test_file_path,
            output_path=encrypted_file_path,
            key=key,
            algorithm='AES-GCM'
        )
        
        if success:
            print(f"File encrypted successfully: {encrypted_file_path}")
            results["file_encryption"]["text_file"] = "Success"
        else:
            print("File encryption failed")
            results["file_encryption"]["text_file"] = "Failed"
            return
        
        # Decrypt the file
        decrypted_file_path = os.path.join(temp_dir, "test_file.txt.decrypted")
        print(f"\nDecrypting file: {encrypted_file_path}")
        success = text_file_handler.decrypt_file(
            input_path=encrypted_file_path,
            output_path=decrypted_file_path,
            key=key
        )
        
        if success:
            print(f"File decrypted successfully: {decrypted_file_path}")
            results["file_decryption"]["text_file"] = "Success"
        else:
            print("File decryption failed")
            results["file_decryption"]["text_file"] = "Failed"
            return
        
        # Verify the decrypted file
        with open(test_file_path, "r") as f:
            original_content = f.read()
        
        with open(decrypted_file_path, "r") as f:
            decrypted_content = f.read()
        
        if original_content == decrypted_content:
            print("File content matches original")
            results["file_decryption"]["content_verification"] = "Success"
        else:
            print("File content does not match original")
            results["file_decryption"]["content_verification"] = "Failed"
    
    finally:
        # Clean up
        shutil.rmtree(temp_dir)

def test_empty_file_handling():
    """Test empty file handling."""
    print("\n=== Testing Empty File Handling ===")
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create an empty test file
        test_file_path = os.path.join(temp_dir, "empty_file.txt")
        with open(test_file_path, "w") as f:
            pass
        
        # Generate a key
        key = secrets.token_bytes(32)  # 256 bits
        
        # Encrypted file path
        encrypted_file_path = os.path.join(temp_dir, "empty_file.txt.encrypted")
        
        # Encrypt the file
        print(f"\nEncrypting empty file: {test_file_path}")
        success = text_file_handler.encrypt_file(
            input_path=test_file_path,
            output_path=encrypted_file_path,
            key=key,
            algorithm='AES-GCM'
        )
        
        if success:
            print(f"Empty file encrypted successfully: {encrypted_file_path}")
            results["file_encryption"]["empty_file"] = "Success"
        else:
            print("Empty file encryption failed")
            results["file_encryption"]["empty_file"] = "Failed"
            return
        
        # Decrypt the file
        decrypted_file_path = os.path.join(temp_dir, "empty_file.txt.decrypted")
        print(f"\nDecrypting file: {encrypted_file_path}")
        success = text_file_handler.decrypt_file(
            input_path=encrypted_file_path,
            output_path=decrypted_file_path,
            key=key
        )
        
        if success:
            print(f"Empty file decrypted successfully: {decrypted_file_path}")
            results["file_decryption"]["empty_file"] = "Success"
        else:
            print("Empty file decryption failed")
            results["file_decryption"]["empty_file"] = "Failed"
            return
        
        # Verify the decrypted file
        with open(test_file_path, "rb") as f:
            original_content = f.read()
        
        with open(decrypted_file_path, "rb") as f:
            decrypted_content = f.read()
        
        if original_content == decrypted_content:
            print("Empty file content matches original (both empty)")
            results["file_decryption"]["empty_file_verification"] = "Success"
        else:
            print("Empty file content does not match original")
            results["file_decryption"]["empty_file_verification"] = "Failed"
    
    finally:
        # Clean up
        shutil.rmtree(temp_dir)

def test_large_file_handling():
    """Test large file handling."""
    print("\n=== Testing Large File Handling ===")
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create a large test file (1 MB)
        test_file_path = os.path.join(temp_dir, "large_file.bin")
        with open(test_file_path, "wb") as f:
            f.write(os.urandom(1024 * 1024))
        
        # Generate a key
        key = secrets.token_bytes(32)  # 256 bits
        
        # Encrypted file path
        encrypted_file_path = os.path.join(temp_dir, "large_file.bin.encrypted")
        
        # Encrypt the file
        print(f"\nEncrypting large file: {test_file_path}")
        success = text_file_handler.encrypt_file(
            input_path=test_file_path,
            output_path=encrypted_file_path,
            key=key,
            algorithm='AES-GCM'
        )
        
        if success:
            print(f"Large file encrypted successfully: {encrypted_file_path}")
            results["file_encryption"]["large_file"] = "Success"
        else:
            print("Large file encryption failed")
            results["file_encryption"]["large_file"] = "Failed"
            return
        
        # Decrypt the file
        decrypted_file_path = os.path.join(temp_dir, "large_file.bin.decrypted")
        print(f"\nDecrypting file: {encrypted_file_path}")
        success = text_file_handler.decrypt_file(
            input_path=encrypted_file_path,
            output_path=decrypted_file_path,
            key=key
        )
        
        if success:
            print(f"Large file decrypted successfully: {decrypted_file_path}")
            results["file_decryption"]["large_file"] = "Success"
        else:
            print("Large file decryption failed")
            results["file_decryption"]["large_file"] = "Failed"
            return
        
        # Verify the decrypted file
        with open(test_file_path, "rb") as f:
            original_content = f.read()
        
        with open(decrypted_file_path, "rb") as f:
            decrypted_content = f.read()
        
        if original_content == decrypted_content:
            print("Large file content matches original")
            results["file_decryption"]["large_file_verification"] = "Success"
        else:
            print("Large file content does not match original")
            results["file_decryption"]["large_file_verification"] = "Failed"
    
    finally:
        # Clean up
        shutil.rmtree(temp_dir)

def test_utf8_encoding_preservation():
    """Test UTF-8 encoding preservation."""
    print("\n=== Testing UTF-8 Encoding Preservation ===")
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create a test file with UTF-8 content
        test_file_path = os.path.join(temp_dir, "utf8_file.txt")
        utf8_content = "This is a UTF-8 test file with special characters: áéíóú ñ € 你好 😊"
        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write(utf8_content)
        
        # Generate a key
        key = secrets.token_bytes(32)  # 256 bits
        
        # Encrypted file path
        encrypted_file_path = os.path.join(temp_dir, "utf8_file.txt.encrypted")
        
        # Encrypt the file
        print(f"\nEncrypting UTF-8 file: {test_file_path}")
        success = text_file_handler.encrypt_file(
            input_path=test_file_path,
            output_path=encrypted_file_path,
            key=key,
            algorithm='AES-GCM'
        )
        
        if success:
            print(f"UTF-8 file encrypted successfully: {encrypted_file_path}")
            results["file_encryption"]["utf8_file"] = "Success"
        else:
            print("UTF-8 file encryption failed")
            results["file_encryption"]["utf8_file"] = "Failed"
            return
        
        # Decrypt the file
        decrypted_file_path = os.path.join(temp_dir, "utf8_file.txt.decrypted")
        print(f"\nDecrypting file: {encrypted_file_path}")
        success = text_file_handler.decrypt_file(
            input_path=encrypted_file_path,
            output_path=decrypted_file_path,
            key=key
        )
        
        if success:
            print(f"UTF-8 file decrypted successfully: {decrypted_file_path}")
            results["file_decryption"]["utf8_file"] = "Success"
        else:
            print("UTF-8 file decryption failed")
            results["file_decryption"]["utf8_file"] = "Failed"
            return
        
        # Verify the decrypted file
        with open(test_file_path, "r", encoding="utf-8") as f:
            original_content = f.read()
        
        with open(decrypted_file_path, "r", encoding="utf-8") as f:
            decrypted_content = f.read()
        
        if original_content == decrypted_content:
            print("UTF-8 file content matches original")
            results["encoding_preservation"]["utf8"] = "Success"
        else:
            print("UTF-8 file content does not match original")
            results["encoding_preservation"]["utf8"] = "Failed"
    
    finally:
        # Clean up
        shutil.rmtree(temp_dir)

def main():
    """Main function to run all tests."""
    print("=== File Handling Test ===")
    
    # Test text file encryption and decryption
    test_text_file_encryption_decryption()
    
    # Test empty file handling
    test_empty_file_handling()
    
    # Test large file handling
    test_large_file_handling()
    
    # Test UTF-8 encoding preservation
    test_utf8_encoding_preservation()
    
    # Print summary
    print("\n=== Test Results Summary ===")
    for category, tests in results.items():
        print(f"\n{category.upper()}:")
        for test_name, result in tests.items():
            print(f"  {test_name}: {result}")
    
    # Save results to file
    with open("file_handling_test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\nTest results saved to file_handling_test_results.json")

if __name__ == "__main__":
    main()
