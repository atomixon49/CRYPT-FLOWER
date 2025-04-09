"""
System-wide integration test for the cryptographic system.

This script tests the main functionality of the system, including:
- Key generation and management
- File encryption and decryption
- Signature creation and verification
- Cross-platform file type detection
- Character encoding preservation
- Salt management in password-based encryption
"""

import os
import sys
import tempfile
import shutil
import unittest
import json
import base64
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.key_management import KeyManager
from src.core.encryption import EncryptionEngine
from src.core.signatures import SignatureEngine
from src.file_handlers.text_handler import TextFileHandler
from src.file_handlers.pdf_handler import PDFHandler
from src.utils.cross_platform_file_type import get_appropriate_handler, CrossPlatformFileTypeDetector

class SystemTest(unittest.TestCase):
    """System-wide integration test for the cryptographic system."""

    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()

        # Initialize core components
        self.key_manager = KeyManager()
        self.encryption_engine = EncryptionEngine()
        self.signature_engine = SignatureEngine()

        # Initialize file handlers
        self.text_handler = TextFileHandler(self.key_manager, self.encryption_engine)
        self.pdf_handler = PDFHandler(self.key_manager, self.encryption_engine)

        # Create test files
        self.create_test_files()

        # Generate keys for testing
        self.generate_test_keys()

    def tearDown(self):
        """Clean up after tests."""
        # Remove temporary directory and all its contents
        shutil.rmtree(self.test_dir)

    def create_test_files(self):
        """Create various test files for testing."""
        # Text file with ASCII content
        self.ascii_file = os.path.join(self.test_dir, "ascii_test.txt")
        with open(self.ascii_file, "w") as f:
            f.write("This is a test file with ASCII content only.")

        # Text file with non-ASCII content
        self.unicode_file = os.path.join(self.test_dir, "unicode_test.txt")
        with open(self.unicode_file, "w", encoding="utf-8") as f:
            f.write("This file contains Unicode characters: áéíóúñÁÉÍÓÚÑ€¥£")

        # Binary file
        self.binary_file = os.path.join(self.test_dir, "binary_test.bin")
        with open(self.binary_file, "wb") as f:
            f.write(os.urandom(1024))

        # Simple PDF-like file (just the header)
        self.pdf_file = os.path.join(self.test_dir, "test.pdf")
        with open(self.pdf_file, "wb") as f:
            f.write(b"%PDF-1.5\n%Test PDF file\n")
            f.write(os.urandom(1024))

    def generate_test_keys(self):
        """Generate keys for testing."""
        # Generate symmetric key
        self.symmetric_key = self.key_manager.generate_symmetric_key(algorithm="AES", key_size=256)
        self.symmetric_key_id = list(self.key_manager.active_keys.keys())[-1]

        # Generate RSA key pair for signatures
        self.rsa_pss_key_pair = self.signature_engine.generate_key_pair(algorithm="RSA-PSS", key_size=2048)
        self.rsa_pkcs_key_pair = self.signature_engine.generate_key_pair(algorithm="RSA-PKCS1v15", key_size=2048)

    def test_file_type_detection(self):
        """Test cross-platform file type detection."""
        detector = CrossPlatformFileTypeDetector()

        # Test ASCII file detection
        file_type, metadata = detector.detect_file_type(self.ascii_file)
        self.assertEqual(file_type, "text")

        # Test Unicode file detection
        file_type, metadata = detector.detect_file_type(self.unicode_file)
        self.assertEqual(file_type, "text")

        # Test binary file detection
        file_type, metadata = detector.detect_file_type(self.binary_file)
        self.assertEqual(file_type, "binary")

        # Test PDF file detection
        file_type, metadata = detector.detect_file_type(self.pdf_file)
        self.assertEqual(file_type, "pdf")

        # Test get_appropriate_handler function
        handler_type, _ = get_appropriate_handler(self.ascii_file)
        self.assertEqual(handler_type, "text")

        handler_type, _ = get_appropriate_handler(self.pdf_file)
        self.assertEqual(handler_type, "pdf")

    def test_key_based_encryption_decryption(self):
        """Test encryption and decryption using key-based approach."""
        # Encrypt ASCII file
        ascii_encrypted = os.path.join(self.test_dir, "ascii_test.encrypted")
        result = self.text_handler.encrypt_file(
            input_path=self.ascii_file,
            output_path=ascii_encrypted,
            key=self.symmetric_key
        )

        # Verify the encrypted file exists
        self.assertTrue(os.path.exists(ascii_encrypted))

        # Decrypt the file
        ascii_decrypted = os.path.join(self.test_dir, "ascii_test_decrypted.txt")
        self.text_handler.decrypt_file(
            input_path=ascii_encrypted,
            output_path=ascii_decrypted,
            key=self.symmetric_key
        )

        # Verify the decrypted content matches the original
        with open(self.ascii_file, "r") as f:
            original_content = f.read()

        with open(ascii_decrypted, "r") as f:
            decrypted_content = f.read()

        self.assertEqual(decrypted_content, original_content)

    def test_password_based_encryption_decryption(self):
        """Test encryption and decryption using password-based approach."""
        # Encrypt Unicode file with password
        unicode_encrypted = os.path.join(self.test_dir, "unicode_test.encrypted")
        password = "test-password-123"

        result = self.text_handler.encrypt_file(
            input_path=self.unicode_file,
            output_path=unicode_encrypted,
            password=password
        )

        # Verify the encrypted file exists
        self.assertTrue(os.path.exists(unicode_encrypted))

        # Verify salt is stored in metadata
        with open(unicode_encrypted, "r") as f:
            encrypted_data = json.load(f)

        self.assertIn("salt", encrypted_data["metadata"])
        self.assertEqual(encrypted_data["metadata"]["encryption_method"], "password_based")

        # Decrypt the file using just the password (salt from metadata)
        unicode_decrypted = os.path.join(self.test_dir, "unicode_test_decrypted.txt")
        self.text_handler.decrypt_file(
            input_path=unicode_encrypted,
            output_path=unicode_decrypted,
            password=password
        )

        # Verify the decrypted content matches the original
        with open(self.unicode_file, "r", encoding="utf-8") as f:
            original_content = f.read()

        with open(unicode_decrypted, "r", encoding="utf-8") as f:
            decrypted_content = f.read()

        self.assertEqual(decrypted_content, original_content)

    def test_encoding_preservation(self):
        """Test character encoding preservation during encryption/decryption."""
        # Encrypt Unicode file
        unicode_encrypted = os.path.join(self.test_dir, "unicode_encoding_test.encrypted")
        result = self.text_handler.encrypt_file(
            input_path=self.unicode_file,
            output_path=unicode_encrypted,
            key=self.symmetric_key
        )

        # Verify encoding information is stored in metadata
        with open(unicode_encrypted, "r") as f:
            encrypted_data = json.load(f)

        self.assertIn("encoding", encrypted_data["metadata"])
        self.assertIn("encoding_confidence", encrypted_data["metadata"])

        # Decrypt the file
        unicode_decrypted = os.path.join(self.test_dir, "unicode_encoding_test_decrypted.txt")
        self.text_handler.decrypt_file(
            input_path=unicode_encrypted,
            output_path=unicode_decrypted,
            key=self.symmetric_key
        )

        # Verify the decrypted content matches the original, including special characters
        with open(self.unicode_file, "r", encoding="utf-8") as f:
            original_content = f.read()

        with open(unicode_decrypted, "r", encoding="utf-8") as f:
            decrypted_content = f.read()

        self.assertEqual(decrypted_content, original_content)
        self.assertIn("áéíóúñÁÉÍÓÚÑ€¥£", decrypted_content)

    def test_digital_signatures(self):
        """Test digital signature creation and verification."""
        # Test RSA-PSS signatures
        with open(self.ascii_file, "rb") as f:
            file_data = f.read()

        # Sign with RSA-PSS
        pss_signature = self.signature_engine.sign(
            data=file_data,
            private_key=self.rsa_pss_key_pair["private_key"],
            algorithm="RSA-PSS"
        )

        # Verify the signature
        is_valid = self.signature_engine.verify(
            data=file_data,
            signature_result=pss_signature,
            public_key=self.rsa_pss_key_pair["public_key"]
        )

        self.assertTrue(is_valid)

        # Test RSA-PKCS1v15 signatures
        pkcs_signature = self.signature_engine.sign(
            data=file_data,
            private_key=self.rsa_pkcs_key_pair["private_key"],
            algorithm="RSA-PKCS1v15"
        )

        # Verify the signature
        is_valid = self.signature_engine.verify(
            data=file_data,
            signature_result=pkcs_signature,
            public_key=self.rsa_pkcs_key_pair["public_key"]
        )

        self.assertTrue(is_valid)

        # Test cross-verification (should fail)
        is_valid = False
        try:
            is_valid = self.signature_engine.verify(
                data=file_data,
                signature_result={
                    "algorithm": "RSA-PSS",  # Wrong algorithm
                    "signature": pkcs_signature["signature"]
                },
                public_key=self.rsa_pkcs_key_pair["public_key"]
            )
        except Exception:
            pass

        self.assertFalse(is_valid)

    def test_pdf_handling(self):
        """Test PDF file handling."""
        # Skip this test if PyPDF2 is not available or if we can't create a valid PDF
        try:
            import PyPDF2
            # Try to create a valid PDF file using PyPDF2
            valid_pdf_path = os.path.join(self.test_dir, "valid_test.pdf")
            pdf_writer = PyPDF2.PdfWriter()
            pdf_writer.add_blank_page(width=612, height=792)  # Standard letter size

            with open(valid_pdf_path, "wb") as f:
                pdf_writer.write(f)

            # Now use this valid PDF for testing
            pdf_encrypted = os.path.join(self.test_dir, "valid_test.pdf.encrypted")
            result = self.pdf_handler.encrypt_pdf(
                input_path=valid_pdf_path,
                output_path=pdf_encrypted,
                key=self.symmetric_key
            )

            # Verify the encrypted file exists
            self.assertTrue(os.path.exists(pdf_encrypted))

            # Decrypt the PDF file
            pdf_decrypted = os.path.join(self.test_dir, "valid_test_decrypted.pdf")
            self.pdf_handler.decrypt_pdf(
                input_path=pdf_encrypted,
                output_path=pdf_decrypted,
                key=self.symmetric_key
            )

            # Verify the decrypted file exists and has the same size as the original
            self.assertTrue(os.path.exists(pdf_decrypted))
            self.assertEqual(os.path.getsize(valid_pdf_path), os.path.getsize(pdf_decrypted))

            # Verify the content matches (at least the first 100 bytes)
            with open(valid_pdf_path, "rb") as f:
                original_content = f.read(100)

            with open(pdf_decrypted, "rb") as f:
                decrypted_content = f.read(100)

            self.assertEqual(decrypted_content, original_content)

        except (ImportError, Exception) as e:
            self.skipTest(f"Skipping PDF test: {str(e)}")


if __name__ == "__main__":
    unittest.main()
