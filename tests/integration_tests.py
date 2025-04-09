"""
Integration Tests

This module contains integration tests for the cryptographic system.
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
import base64
import time

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import the necessary modules
from src.core.key_management import KeyManager
from src.core.encryption import EncryptionEngine
from src.core.signatures import SignatureEngine
from src.core.cert_revocation import CertificateRevocationChecker
from src.file_handlers.text_handler import TextFileHandler
from src.file_handlers.pdf_handler import PDFHandler
from src.file_handlers.pdf_section_handler import PDFSectionHandler
from src.file_handlers.directory_handler import DirectoryHandler


class IntegrationTest(unittest.TestCase):
    """Integration tests for the cryptographic system."""

    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a key manager
        self.key_manager = KeyManager()
        
        # Create an encryption engine
        self.encryption_engine = EncryptionEngine(self.key_manager)
        
        # Create a signature engine
        self.signature_engine = SignatureEngine()
        
        # Create a certificate revocation checker
        self.revocation_checker = CertificateRevocationChecker(
            cache_dir=os.path.join(self.temp_dir, "crl_cache")
        )
        
        # Create file handlers
        self.text_handler = TextFileHandler(self.key_manager, self.encryption_engine)
        self.pdf_handler = PDFHandler(self.key_manager, self.encryption_engine)
        self.pdf_section_handler = PDFSectionHandler(self.key_manager, self.encryption_engine)
        self.directory_handler = DirectoryHandler(self.key_manager, self.encryption_engine)
        
        # Create test files
        self.create_test_files()
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove the temporary directory
        shutil.rmtree(self.temp_dir)
    
    def create_test_files(self):
        """Create test files."""
        # Create a text file
        self.text_file_path = os.path.join(self.temp_dir, "test.txt")
        with open(self.text_file_path, "w") as f:
            f.write("This is a test file.")
        
        # Create a directory with multiple files
        self.test_dir_path = os.path.join(self.temp_dir, "test_dir")
        os.makedirs(self.test_dir_path, exist_ok=True)
        
        for i in range(5):
            file_path = os.path.join(self.test_dir_path, f"file{i}.txt")
            with open(file_path, "w") as f:
                f.write(f"This is test file {i}.")
    
    def test_encryption_decryption_workflow(self):
        """Test the encryption and decryption workflow."""
        # Generate a key
        key_id = self.key_manager.generate_symmetric_key(algorithm="AES", key_size=256)
        
        # Encrypt the text file
        encrypted_path = os.path.join(self.temp_dir, "test.encrypted")
        encryption_result = self.text_handler.encrypt_file(
            input_path=self.text_file_path,
            output_path=encrypted_path,
            key_id=key_id
        )
        
        # Verify the encryption result
        self.assertTrue(os.path.exists(encrypted_path))
        self.assertEqual(encryption_result["key_id"], key_id)
        
        # Decrypt the file
        decrypted_path = os.path.join(self.temp_dir, "test.decrypted")
        decryption_result = self.text_handler.decrypt_file(
            input_path=encrypted_path,
            output_path=decrypted_path,
            key_id=key_id
        )
        
        # Verify the decryption result
        self.assertTrue(os.path.exists(decrypted_path))
        
        # Compare the original and decrypted files
        with open(self.text_file_path, "r") as f:
            original_content = f.read()
        
        with open(decrypted_path, "r") as f:
            decrypted_content = f.read()
        
        self.assertEqual(original_content, decrypted_content)
    
    def test_signature_verification_workflow(self):
        """Test the signature and verification workflow."""
        # Generate a key pair
        key_pair = self.signature_engine.generate_key_pair(algorithm="RSA-PSS", key_size=2048)
        
        # Sign the text file
        signature_path = os.path.join(self.temp_dir, "test.sig")
        signature_result = self.signature_engine.sign_file(
            file_path=self.text_file_path,
            output_path=signature_path,
            private_key=key_pair["private_key"]
        )
        
        # Verify the signature result
        self.assertTrue(os.path.exists(signature_path))
        
        # Verify the signature
        verification_result = self.signature_engine.verify_file(
            file_path=self.text_file_path,
            signature_path=signature_path,
            public_key=key_pair["public_key"]
        )
        
        # Verify the verification result
        self.assertTrue(verification_result)
        
        # Modify the file and verify that the signature is invalid
        modified_path = os.path.join(self.temp_dir, "test.modified.txt")
        with open(self.text_file_path, "r") as f:
            content = f.read()
        
        with open(modified_path, "w") as f:
            f.write(content + " Modified.")
        
        # Verify the signature with the modified file
        verification_result = self.signature_engine.verify_file(
            file_path=modified_path,
            signature_path=signature_path,
            public_key=key_pair["public_key"]
        )
        
        # Verify that the verification fails
        self.assertFalse(verification_result)
    
    def test_directory_encryption_workflow(self):
        """Test the directory encryption and decryption workflow."""
        # Generate a key
        key_id = self.key_manager.generate_symmetric_key(algorithm="AES", key_size=256)
        
        # Encrypt the directory
        encrypted_dir_path = os.path.join(self.temp_dir, "encrypted_dir")
        encryption_result = self.directory_handler.encrypt_directory(
            input_path=self.test_dir_path,
            output_path=encrypted_dir_path,
            key_id=key_id
        )
        
        # Verify the encryption result
        self.assertTrue(os.path.exists(encrypted_dir_path))
        self.assertEqual(encryption_result["key_id"], key_id)
        
        # Verify that the encrypted directory contains the expected number of files
        encrypted_files = [f for f in os.listdir(encrypted_dir_path) if f.endswith(".encrypted")]
        self.assertEqual(len(encrypted_files), 5)
        
        # Decrypt the directory
        decrypted_dir_path = os.path.join(self.temp_dir, "decrypted_dir")
        decryption_result = self.directory_handler.decrypt_directory(
            input_path=encrypted_dir_path,
            output_path=decrypted_dir_path,
            key_id=key_id
        )
        
        # Verify the decryption result
        self.assertTrue(os.path.exists(decrypted_dir_path))
        
        # Verify that the decrypted directory contains the expected number of files
        decrypted_files = os.listdir(decrypted_dir_path)
        self.assertEqual(len(decrypted_files), 5)
        
        # Compare the original and decrypted files
        for i in range(5):
            original_path = os.path.join(self.test_dir_path, f"file{i}.txt")
            decrypted_path = os.path.join(decrypted_dir_path, f"file{i}.txt")
            
            with open(original_path, "r") as f:
                original_content = f.read()
            
            with open(decrypted_path, "r") as f:
                decrypted_content = f.read()
            
            self.assertEqual(original_content, decrypted_content)
    
    def test_pdf_section_encryption_workflow(self):
        """Test the PDF section encryption and decryption workflow."""
        # Skip if PyPDF2 is not available
        try:
            import PyPDF2
        except ImportError:
            self.skipTest("PyPDF2 library not available")
        
        # Create a simple PDF file for testing
        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter
            
            # Create a PDF with multiple pages
            pdf_path = os.path.join(self.temp_dir, "test.pdf")
            
            # Create a PDF with 5 pages
            c = canvas.Canvas(pdf_path, pagesize=letter)
            
            for i in range(5):
                c.drawString(100, 750, f"This is page {i+1}")
                c.drawString(100, 700, "This is a test PDF file.")
                c.drawString(100, 650, f"Page content for page {i+1}")
                c.showPage()
            
            c.save()
            
        except ImportError:
            self.skipTest("ReportLab library not available")
        
        # Generate a key
        key_id = self.key_manager.generate_symmetric_key(algorithm="AES", key_size=256)
        
        # Encrypt specific sections of the PDF
        encrypted_pdf_path = os.path.join(self.temp_dir, "test.sections.pdf")
        
        # Encrypt pages 1-2 and 4
        sections = [(0, 1), (3, 3)]  # 0-indexed
        
        encryption_result = self.pdf_handler.encrypt_pdf_sections(
            input_path=pdf_path,
            output_path=encrypted_pdf_path,
            sections=sections,
            key_id=key_id
        )
        
        # Verify the encryption result
        self.assertTrue(os.path.exists(encrypted_pdf_path))
        
        # Decrypt the PDF sections
        decrypted_pdf_path = os.path.join(self.temp_dir, "test.decrypted.pdf")
        
        decryption_result = self.pdf_handler.decrypt_pdf_sections(
            input_path=encrypted_pdf_path,
            output_path=decrypted_pdf_path,
            key_id=key_id
        )
        
        # Verify the decryption result
        self.assertTrue(os.path.exists(decrypted_pdf_path))
        
        # Verify that the decrypted PDF has the expected number of pages
        with open(decrypted_pdf_path, "rb") as f:
            pdf_reader = PyPDF2.PdfReader(f)
            self.assertEqual(len(pdf_reader.pages), 5)


if __name__ == "__main__":
    unittest.main()
