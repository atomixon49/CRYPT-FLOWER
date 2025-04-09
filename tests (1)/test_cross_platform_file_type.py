"""
Tests for the cross-platform file type detection.
"""

import unittest
import os
import tempfile
import json
from src.utils.cross_platform_file_type import CrossPlatformFileTypeDetector, get_appropriate_handler

class TestCrossPlatformFileTypeDetector(unittest.TestCase):
    """Test cases for cross-platform file type detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = CrossPlatformFileTypeDetector()
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create test files of different types
        self.create_test_files()
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        for root, dirs, files in os.walk(self.test_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.test_dir)
    
    def create_test_files(self):
        """Create test files of different types."""
        # Text file
        self.text_file_path = os.path.join(self.test_dir, "test_file.txt")
        with open(self.text_file_path, "w") as f:
            f.write("This is a test text file.")
        
        # PDF file (just the header, not a valid PDF)
        self.pdf_file_path = os.path.join(self.test_dir, "test_file.pdf")
        with open(self.pdf_file_path, "wb") as f:
            f.write(b"%PDF-1.5\n%Test PDF file")
        
        # Binary file
        self.binary_file_path = os.path.join(self.test_dir, "test_file.bin")
        with open(self.binary_file_path, "wb") as f:
            f.write(os.urandom(100))
        
        # File with no extension
        self.no_ext_file_path = os.path.join(self.test_dir, "test_file_no_ext")
        with open(self.no_ext_file_path, "w") as f:
            f.write("This is a file with no extension.")
        
        # JSON file (for encrypted file simulation)
        self.encrypted_file_path = os.path.join(self.test_dir, "test_file.encrypted")
        encrypted_data = {
            "metadata": {
                "filename": "original.txt",
                "original_size": 100,
                "encryption_algorithm": "AES-GCM"
            },
            "ciphertext": "base64_encoded_data",
            "nonce": "base64_encoded_nonce",
            "tag": "base64_encoded_tag"
        }
        with open(self.encrypted_file_path, "w") as f:
            json.dump(encrypted_data, f)
        
        # PDF encrypted file
        self.pdf_encrypted_file_path = os.path.join(self.test_dir, "test_pdf.encrypted")
        pdf_encrypted_data = {
            "metadata": {
                "filename": "original.pdf",
                "original_size": 100,
                "encryption_algorithm": "AES-GCM"
            },
            "ciphertext": "base64_encoded_data",
            "nonce": "base64_encoded_nonce",
            "tag": "base64_encoded_tag"
        }
        with open(self.pdf_encrypted_file_path, "w") as f:
            json.dump(pdf_encrypted_data, f)
    
    def test_detect_text_file(self):
        """Test detection of text files."""
        file_type, metadata = self.detector.detect_file_type(self.text_file_path)
        self.assertEqual(file_type, "text")
        self.assertIn("detection_method", metadata)
    
    def test_detect_pdf_file(self):
        """Test detection of PDF files."""
        file_type, metadata = self.detector.detect_file_type(self.pdf_file_path)
        self.assertEqual(file_type, "pdf")
        self.assertIn("detection_method", metadata)
    
    def test_detect_binary_file(self):
        """Test detection of binary files."""
        file_type, metadata = self.detector.detect_file_type(self.binary_file_path)
        self.assertEqual(file_type, "binary")
        self.assertIn("detection_method", metadata)
    
    def test_detect_file_no_extension(self):
        """Test detection of files with no extension."""
        file_type, metadata = self.detector.detect_file_type(self.no_ext_file_path)
        self.assertEqual(file_type, "text")  # Should detect as text based on content
        self.assertIn("detection_method", metadata)
    
    def test_get_appropriate_handler(self):
        """Test the get_appropriate_handler function."""
        # Test with text file
        handler_type, metadata = get_appropriate_handler(self.text_file_path)
        self.assertEqual(handler_type, "text")
        
        # Test with PDF file
        handler_type, metadata = get_appropriate_handler(self.pdf_file_path)
        self.assertEqual(handler_type, "pdf")
        
        # Test with binary file
        handler_type, metadata = get_appropriate_handler(self.binary_file_path)
        self.assertEqual(handler_type, "binary")
        
        # Test with encrypted text file
        handler_type, metadata = get_appropriate_handler(self.encrypted_file_path)
        self.assertEqual(handler_type, "text")
        
        # Test with encrypted PDF file
        handler_type, metadata = get_appropriate_handler(self.pdf_encrypted_file_path)
        self.assertEqual(handler_type, "pdf")
    
    def test_nonexistent_file(self):
        """Test handling of nonexistent files."""
        nonexistent_path = os.path.join(self.test_dir, "nonexistent.txt")
        with self.assertRaises(FileNotFoundError):
            self.detector.detect_file_type(nonexistent_path)


if __name__ == "__main__":
    unittest.main()
