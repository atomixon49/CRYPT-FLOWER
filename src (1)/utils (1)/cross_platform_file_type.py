"""
Cross-Platform File Type Detection

This module provides functionality for detecting file types in a cross-platform manner,
without relying on platform-specific dependencies like libmagic.
"""

import os
import json
import mimetypes
import filetype
from typing import Tuple, Optional, Dict, Any, List

# Initialize mimetypes database
mimetypes.init()

# Define common text file extensions
TEXT_EXTENSIONS = {
    '.txt', '.md', '.csv', '.json', '.xml', '.html', '.htm', '.css', '.js',
    '.py', '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.php', '.rb', '.pl',
    '.sh', '.bat', '.ps1', '.log', '.ini', '.cfg', '.conf', '.yaml', '.yml',
    '.toml', '.rst'
}

# Define common binary file extensions
BINARY_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    '.exe', '.dll', '.so', '.dylib',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',
    '.mp3', '.wav', '.ogg', '.flac', '.mp4', '.avi', '.mov', '.mkv'
}

class CrossPlatformFileTypeDetector:
    """
    A file type detector that works across different platforms.

    This class uses multiple methods to detect file types:
    1. Binary signature detection using filetype
    2. Extension-based detection using mimetypes
    3. Custom heuristics for text files
    4. Optional fallback to python-magic if available
    """

    def __init__(self):
        """Initialize the file type detector."""
        self.magic_available = False

        # Try to import python-magic as an optional dependency
        try:
            import magic
            self.magic = magic
            self.magic_available = True
        except (ImportError, ModuleNotFoundError):
            self.magic = None

    def detect_file_type(self, file_path: str) -> Tuple[str, Dict[str, Any]]:
        """
        Detect the type of a file using multiple methods.

        Args:
            file_path: Path to the file

        Returns:
            A tuple containing (file_type, metadata)
            where file_type is one of: 'text', 'pdf', 'binary', 'unknown'
            and metadata contains additional information about the file
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        metadata = {
            'filename': os.path.basename(file_path),
            'extension': os.path.splitext(file_path)[1].lower(),
            'size': os.path.getsize(file_path),
            'detection_method': None
        }

        # Try each detection method in order
        file_type = None

        # 1. Try filetype (signature-based detection)
        file_type, metadata = self._detect_with_filetype(file_path, metadata)
        if file_type:
            return file_type, metadata

        # 2. Try extension-based detection
        file_type, metadata = self._detect_with_extension(file_path, metadata)
        if file_type:
            return file_type, metadata

        # 3. Try custom heuristics
        file_type, metadata = self._detect_with_heuristics(file_path, metadata)
        if file_type:
            return file_type, metadata

        # 4. Try python-magic if available
        if self.magic_available:
            file_type, metadata = self._detect_with_magic(file_path, metadata)
            if file_type:
                return file_type, metadata

        # If all methods fail, return 'unknown'
        return 'unknown', metadata

    def _detect_with_filetype(self, file_path: str, metadata: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Detect file type using filetype library (signature-based).

        Args:
            file_path: Path to the file
            metadata: Existing metadata dictionary

        Returns:
            Tuple of (file_type or None, updated metadata)
        """
        kind = filetype.guess(file_path)
        if kind is None:
            return None, metadata

        metadata['detection_method'] = 'signature'
        metadata['mime_type'] = kind.mime
        metadata['filetype_extension'] = kind.extension

        # Map to our file type categories
        if kind.mime == 'application/pdf':
            return 'pdf', metadata
        elif kind.mime.startswith('text/'):
            return 'text', metadata
        else:
            return 'binary', metadata

    def _detect_with_extension(self, file_path: str, metadata: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Detect file type based on file extension.

        Args:
            file_path: Path to the file
            metadata: Existing metadata dictionary

        Returns:
            Tuple of (file_type or None, updated metadata)
        """
        extension = metadata['extension']
        if not extension:
            return None, metadata

        # Check for specific extensions
        if extension.lower() == '.pdf':
            metadata['detection_method'] = 'extension'
            metadata['mime_type'] = 'application/pdf'
            return 'pdf', metadata

        # Use mimetypes for general mapping
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type:
            metadata['detection_method'] = 'extension'
            metadata['mime_type'] = mime_type

            if mime_type.startswith('text/'):
                return 'text', metadata
            elif mime_type == 'application/pdf':
                return 'pdf', metadata
            else:
                return 'binary', metadata

        # Check against our extension sets
        if extension.lower() in TEXT_EXTENSIONS:
            metadata['detection_method'] = 'extension'
            metadata['mime_type'] = 'text/plain'
            return 'text', metadata

        if extension.lower() in BINARY_EXTENSIONS:
            metadata['detection_method'] = 'extension'
            metadata['mime_type'] = 'application/octet-stream'
            return 'binary', metadata

        return None, metadata

    def _detect_with_heuristics(self, file_path: str, metadata: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Detect file type using custom heuristics.

        Args:
            file_path: Path to the file
            metadata: Existing metadata dictionary

        Returns:
            Tuple of (file_type or None, updated metadata)
        """
        # Check if file is likely text by reading a sample
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(4096)  # Read first 4KB

            # Check for common text file characteristics
            if self._is_likely_text(sample):
                metadata['detection_method'] = 'heuristic'
                metadata['mime_type'] = 'text/plain'
                return 'text', metadata

            # Check for PDF signature
            if sample.startswith(b'%PDF-'):
                metadata['detection_method'] = 'heuristic'
                metadata['mime_type'] = 'application/pdf'
                return 'pdf', metadata
        except Exception:
            # If we can't read the file or an error occurs, skip heuristics
            pass

        return None, metadata

    def _detect_with_magic(self, file_path: str, metadata: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Detect file type using python-magic if available.

        Args:
            file_path: Path to the file
            metadata: Existing metadata dictionary

        Returns:
            Tuple of (file_type or None, updated metadata)
        """
        try:
            mime_type = self.magic.from_file(file_path, mime=True)
            metadata['detection_method'] = 'magic'
            metadata['mime_type'] = mime_type

            if mime_type.startswith('text/'):
                return 'text', metadata
            elif mime_type == 'application/pdf':
                return 'pdf', metadata
            else:
                return 'binary', metadata
        except Exception:
            # If magic fails, return None
            return None, metadata

    def _is_likely_text(self, sample: bytes) -> bool:
        """
        Check if a byte sample is likely to be text.

        Args:
            sample: Byte sample from the file

        Returns:
            True if the sample is likely text, False otherwise
        """
        # If empty, consider it text
        if not sample:
            return True

        # Check for null bytes (common in binary files)
        if b'\x00' in sample:
            return False

        # Count printable ASCII characters
        printable_count = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))  # Tab, LF, CR

        # If more than 90% of characters are printable ASCII, likely text
        return printable_count / len(sample) > 0.9


def get_appropriate_handler(file_path: str) -> Tuple[str, Dict[str, Any]]:
    """
    Determine the appropriate handler for a file based on its type.

    This is a drop-in replacement for the original function that used python-magic.

    Args:
        file_path: Path to the file

    Returns:
        A tuple containing (handler_type, metadata)
        where handler_type is one of: 'text', 'pdf', 'binary', 'unknown'
    """
    detector = CrossPlatformFileTypeDetector()

    # Check if this is an encrypted file
    try:
        with open(file_path, 'r') as f:
            try:
                data = json.loads(f.read())
                # Check if this looks like our encrypted file format
                if all(key in data for key in ['metadata', 'ciphertext', 'nonce', 'tag']):
                    # Check if the original file was a PDF
                    original_filename = data.get('metadata', {}).get('filename', '')
                    if original_filename.lower().endswith('.pdf'):
                        return 'pdf', {'detection_method': 'encrypted_metadata'}
                    # Default to text for encrypted files
                    return 'text', {'detection_method': 'encrypted_metadata'}
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    # If not encrypted, use normal detection
    return detector.detect_file_type(file_path)
