"""
Tests for the PDF section handler.
"""

import unittest
import os
import tempfile
import json
import base64
from pathlib import Path

try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

from src.core.key_management import KeyManager
from src.core.encryption import EncryptionEngine
from src.file_handlers.pdf_section_handler import PDFSectionHandler

@unittest.skipIf(not PYPDF_AVAILABLE, "pypdf not available")
class TestPDFSectionHandler(unittest.TestCase):
    """Test cases for the PDF section handler."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key_manager = KeyManager()
        self.encryption_engine = EncryptionEngine()
        self.pdf_section_handler = PDFSectionHandler(self.key_manager, self.encryption_engine)
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a test PDF file
        self.create_test_pdf()
        
        # Generate a key for testing
        self.key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        self.key_id = list(self.key_manager.active_keys.keys())[-1]
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        for root, dirs, files in os.walk(self.test_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.test_dir)
    
    def create_test_pdf(self):
        """Create a test PDF file with multiple pages."""
        self.pdf_path = os.path.join(self.test_dir, "test.pdf")
        
        # Create a PDF with 5 pages
        pdf_writer = pypdf.PdfWriter()
        for i in range(5):
            page = pypdf.PageObject.create_blank_page(width=612, height=792)
            pdf_writer.add_page(page)
        
        with open(self.pdf_path, "wb") as f:
            pdf_writer.write(f)
    
    def test_encrypt_decrypt_pages_with_key(self):
        """Test encrypting and decrypting specific pages with a key."""
        # Skip if pypdf is not available
        if not PYPDF_AVAILABLE:
            self.skipTest("pypdf not available")
        
        # Encrypt pages 1, 3, and 5
        encrypted_path = os.path.join(self.test_dir, "encrypted.pdf")
        result = self.pdf_section_handler.encrypt_pages(
            input_path=self.pdf_path,
            output_path=encrypted_path,
            pages="1,3,5",
            key=self.key
        )
        
        # Verify the encrypted file exists
        self.assertTrue(os.path.exists(encrypted_path))
        
        # Verify the metadata file exists
        metadata_path = encrypted_path + '.metadata.json'
        self.assertTrue(os.path.exists(metadata_path))
        
        # Verify the encrypted pages
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        encrypted_sections = metadata.get('encrypted_sections', [])
        self.assertEqual(len(encrypted_sections), 3)
        
        encrypted_page_numbers = [section['page_number'] for section in encrypted_sections]
        self.assertIn(1, encrypted_page_numbers)
        self.assertIn(3, encrypted_page_numbers)
        self.assertIn(5, encrypted_page_numbers)
        
        # Decrypt the PDF
        decrypted_path = os.path.join(self.test_dir, "decrypted.pdf")
        result = self.pdf_section_handler.decrypt_pages(
            input_path=encrypted_path,
            output_path=decrypted_path,
            key=self.key
        )
        
        # Verify the decrypted file exists
        self.assertTrue(os.path.exists(decrypted_path))
        
        # Verify the decrypted pages
        self.assertEqual(len(result['decrypted_pages']), 3)
        self.assertIn(1, result['decrypted_pages'])
        self.assertIn(3, result['decrypted_pages'])
        self.assertIn(5, result['decrypted_pages'])
        
        # Verify the PDF structure
        with open(self.pdf_path, 'rb') as f:
            original_pdf = pypdf.PdfReader(f)
            original_page_count = len(original_pdf.pages)
        
        with open(decrypted_path, 'rb') as f:
            decrypted_pdf = pypdf.PdfReader(f)
            decrypted_page_count = len(decrypted_pdf.pages)
        
        self.assertEqual(original_page_count, decrypted_page_count)
    
    def test_encrypt_decrypt_pages_with_password(self):
        """Test encrypting and decrypting specific pages with a password."""
        # Skip if pypdf is not available
        if not PYPDF_AVAILABLE:
            self.skipTest("pypdf not available")
        
        # Encrypt pages 2 and 4
        encrypted_path = os.path.join(self.test_dir, "encrypted_password.pdf")
        password = "test-password-123"
        
        result = self.pdf_section_handler.encrypt_pages(
            input_path=self.pdf_path,
            output_path=encrypted_path,
            pages="2,4",
            password=password
        )
        
        # Verify the encrypted file exists
        self.assertTrue(os.path.exists(encrypted_path))
        
        # Verify the metadata file exists
        metadata_path = encrypted_path + '.metadata.json'
        self.assertTrue(os.path.exists(metadata_path))
        
        # Verify the encrypted pages
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        encrypted_sections = metadata.get('encrypted_sections', [])
        self.assertEqual(len(encrypted_sections), 2)
        
        encrypted_page_numbers = [section['page_number'] for section in encrypted_sections]
        self.assertIn(2, encrypted_page_numbers)
        self.assertIn(4, encrypted_page_numbers)
        
        # Verify salt is stored in metadata
        for section in encrypted_sections:
            self.assertEqual(section['encryption_method'], 'password_based')
            self.assertIn('salt', section)
            
            # Verify salt is valid base64
            salt_base64 = section['salt']
            salt = base64.b64decode(salt_base64)
            self.assertEqual(len(salt), 16)  # Salt should be 16 bytes
        
        # Decrypt the PDF
        decrypted_path = os.path.join(self.test_dir, "decrypted_password.pdf")
        result = self.pdf_section_handler.decrypt_pages(
            input_path=encrypted_path,
            output_path=decrypted_path,
            password=password
        )
        
        # Verify the decrypted file exists
        self.assertTrue(os.path.exists(decrypted_path))
        
        # Verify the decrypted pages
        self.assertEqual(len(result['decrypted_pages']), 2)
        self.assertIn(2, result['decrypted_pages'])
        self.assertIn(4, result['decrypted_pages'])
    
    def test_decrypt_with_wrong_key(self):
        """Test decrypting with the wrong key."""
        # Skip if pypdf is not available
        if not PYPDF_AVAILABLE:
            self.skipTest("pypdf not available")
        
        # Encrypt page 1
        encrypted_path = os.path.join(self.test_dir, "encrypted_wrong_key.pdf")
        result = self.pdf_section_handler.encrypt_pages(
            input_path=self.pdf_path,
            output_path=encrypted_path,
            pages="1",
            key=self.key
        )
        
        # Generate a different key
        wrong_key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        
        # Try to decrypt with the wrong key
        decrypted_path = os.path.join(self.test_dir, "decrypted_wrong_key.pdf")
        with self.assertRaises(ValueError):
            self.pdf_section_handler.decrypt_pages(
                input_path=encrypted_path,
                output_path=decrypted_path,
                key=wrong_key
            )
    
    def test_parse_pages(self):
        """Test the _parse_pages method."""
        # Test with a string
        pages = "1,3-5,7"
        page_set = self.pdf_section_handler._parse_pages(pages)
        self.assertEqual(page_set, {1, 3, 4, 5, 7})
        
        # Test with a list
        pages = [1, 3, 5, 7]
        page_set = self.pdf_section_handler._parse_pages(pages)
        self.assertEqual(page_set, {1, 3, 5, 7})
        
        # Test with None
        pages = None
        page_set = self.pdf_section_handler._parse_pages(pages)
        self.assertEqual(page_set, set())
        
        # Test with invalid string
        with self.assertRaises(ValueError):
            self.pdf_section_handler._parse_pages("1,a,3")


if __name__ == "__main__":
    unittest.main()
