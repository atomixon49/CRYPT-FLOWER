"""
File Utilities

This module provides utility functions for working with files.
"""

import os
import mimetypes
from typing import Optional, Dict, Any, Tuple

# Try to import magic, but don't fail if it's not available
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

# Initialize mimetypes
mimetypes.init()

class FileTypeDetector:
    """
    Detects file types based on content and extension.
    """

    def __init__(self):
        """Initialize the file type detector."""
        # Use the global flag for magic availability
        self.magic_available = MAGIC_AVAILABLE

    def detect_file_type(self, file_path: str) -> Dict[str, Any]:
        """
        Detect the type of a file.

        Args:
            file_path: Path to the file

        Returns:
            A dictionary containing file type information
        """
        result = {
            'path': file_path,
            'extension': os.path.splitext(file_path)[1].lower(),
            'size': os.path.getsize(file_path) if os.path.exists(file_path) else None,
        }

        # Get mimetype based on extension
        mimetype, encoding = mimetypes.guess_type(file_path)
        result['mimetype_from_extension'] = mimetype
        result['encoding'] = encoding

        # Try to detect mimetype from content if magic is available
        if self.magic_available and os.path.exists(file_path):
            try:
                result['mimetype_from_content'] = magic.from_file(file_path, mime=True)
            except Exception:
                result['mimetype_from_content'] = None

        # Determine the most likely file type
        result['is_text'] = self._is_text_file(result)
        result['is_pdf'] = self._is_pdf_file(result)
        result['is_encrypted'] = self._is_encrypted_file(result)

        return result

    def _is_text_file(self, file_info: Dict[str, Any]) -> bool:
        """
        Determine if a file is a text file.

        Args:
            file_info: File information from detect_file_type

        Returns:
            True if the file is likely a text file, False otherwise
        """
        # Check mimetype from content first
        mimetype = file_info.get('mimetype_from_content')
        if mimetype and mimetype.startswith('text/'):
            return True

        # Check mimetype from extension
        mimetype = file_info.get('mimetype_from_extension')
        if mimetype and mimetype.startswith('text/'):
            return True

        # Check common text extensions
        text_extensions = ['.txt', '.md', '.csv', '.json', '.xml', '.html', '.htm', '.css', '.js']
        if file_info.get('extension') in text_extensions:
            return True

        return False

    def _is_pdf_file(self, file_info: Dict[str, Any]) -> bool:
        """
        Determine if a file is a PDF file.

        Args:
            file_info: File information from detect_file_type

        Returns:
            True if the file is likely a PDF file, False otherwise
        """
        # Check mimetype from content first
        mimetype = file_info.get('mimetype_from_content')
        if mimetype == 'application/pdf':
            return True

        # Check mimetype from extension
        mimetype = file_info.get('mimetype_from_extension')
        if mimetype == 'application/pdf':
            return True

        # Check extension
        if file_info.get('extension') == '.pdf':
            return True

        return False

    def _is_encrypted_file(self, file_info: Dict[str, Any]) -> bool:
        """
        Determine if a file is likely one of our encrypted files.

        Args:
            file_info: File information from detect_file_type

        Returns:
            True if the file is likely an encrypted file, False otherwise
        """
        # Check for our custom encrypted extensions
        encrypted_extensions = ['.encrypted', '.pdf.encrypted']
        if any(file_info.get('extension', '').endswith(ext) for ext in encrypted_extensions):
            return True

        # If the file exists, try to read it as JSON and check for our format
        if os.path.exists(file_info.get('path', '')):
            try:
                with open(file_info['path'], 'r') as f:
                    import json
                    data = json.load(f)
                    # Check for our encrypted file structure
                    if all(key in data for key in ['metadata', 'ciphertext', 'nonce', 'tag']):
                        return True
            except (json.JSONDecodeError, UnicodeDecodeError, IOError):
                pass

        return False


# This function has been moved to cross_platform_file_type.py
# Keeping this here for backward compatibility
from .cross_platform_file_type import get_appropriate_handler
