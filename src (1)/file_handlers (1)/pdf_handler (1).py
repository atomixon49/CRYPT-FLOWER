"""
PDF File Handler

This module provides functionality for encrypting and decrypting PDF files.
"""

import os
import json
import base64
import io
from typing import Dict, Any, Optional, Union, BinaryIO, List, Tuple
from ..core.encryption import EncryptionEngine
from ..core.key_management import KeyManager

class PDFHandler:
    """
    Handles encryption and decryption of PDF files.
    
    This class provides methods for securely encrypting and decrypting
    PDF files using the core encryption engine, with special handling
    for PDF structure and metadata.
    """
    
    def __init__(self, key_manager: KeyManager, encryption_engine: EncryptionEngine):
        """
        Initialize the PDF handler.
        
        Args:
            key_manager: The key manager to use for key operations
            encryption_engine: The encryption engine to use for encryption/decryption
        """
        self.key_manager = key_manager
        self.encryption_engine = encryption_engine
        self.file_extension = '.pdf.encrypted'
        
        # Try to import PyPDF2, but don't fail if it's not available
        # We'll check for its availability before using it
        try:
            import PyPDF2
            self.pypdf2_available = True
        except ImportError:
            self.pypdf2_available = False
    
    def _check_pdf_library(self):
        """
        Check if the required PDF library is available.
        
        Raises:
            ImportError: If PyPDF2 is not available
        """
        if not self.pypdf2_available:
            raise ImportError(
                "PyPDF2 is required for PDF operations. "
                "Please install it with 'pip install PyPDF2'."
            )
    
    def encrypt_pdf(self, 
                    input_path: str, 
                    output_path: Optional[str] = None, 
                    key: Optional[bytes] = None,
                    algorithm: str = 'AES-GCM',
                    metadata: Optional[Dict[str, Any]] = None,
                    encrypt_metadata: bool = True) -> Dict[str, Any]:
        """
        Encrypt a PDF file.
        
        Args:
            input_path: Path to the PDF file to encrypt
            output_path: Path to save the encrypted file (if None, uses input_path + .pdf.encrypted)
            key: The encryption key (if None, generates a new key)
            algorithm: The encryption algorithm to use
            metadata: Optional metadata to include with the encrypted file
            encrypt_metadata: Whether to encrypt PDF metadata (title, author, etc.)
            
        Returns:
            A dictionary containing encryption metadata including the key ID
            
        Raises:
            FileNotFoundError: If the input file doesn't exist
            PermissionError: If the output file can't be written
            ImportError: If PyPDF2 is not available
        """
        self._check_pdf_library()
        import PyPDF2
        
        # Determine output path if not provided
        if output_path is None:
            output_path = input_path + self.file_extension
        
        # Generate a key if not provided
        if key is None:
            key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
            key_id = list(self.key_manager.active_keys.keys())[-1]  # Get the ID of the key we just generated
        else:
            # For externally provided keys, we don't track them in the key manager
            key_id = None
        
        # Read the PDF file
        with open(input_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            
            # Extract PDF metadata if we're encrypting it
            pdf_metadata = {}
            if encrypt_metadata and pdf_reader.metadata:
                for key, value in pdf_reader.metadata.items():
                    if key.startswith('/'):
                        pdf_metadata[key[1:]] = value
            
            # Read the PDF content
            pdf_writer = PyPDF2.PdfWriter()
            for page in pdf_reader.pages:
                pdf_writer.add_page(page)
            
            # Write the PDF to a bytes buffer
            pdf_bytes_buffer = io.BytesIO()
            pdf_writer.write(pdf_bytes_buffer)
            pdf_bytes = pdf_bytes_buffer.getvalue()
        
        # Encrypt the PDF data
        encryption_result = self.encryption_engine.encrypt(
            data=pdf_bytes,
            key=key,
            algorithm=algorithm,
            associated_data=None
        )
        
        # Prepare metadata
        file_metadata = {
            'filename': os.path.basename(input_path),
            'original_size': len(pdf_bytes),
            'encryption_algorithm': algorithm,
            'key_id': key_id,
            'pdf_metadata': pdf_metadata if encrypt_metadata else {},
            'user_metadata': metadata or {}
        }
        
        # Prepare the encrypted file structure
        encrypted_file_data = {
            'metadata': file_metadata,
            'ciphertext': base64.b64encode(encryption_result['ciphertext']).decode('ascii'),
            'nonce': base64.b64encode(encryption_result['nonce']).decode('ascii'),
            'tag': base64.b64encode(encryption_result['tag']).decode('ascii')
        }
        
        # Write the encrypted file
        with open(output_path, 'w') as f:
            json.dump(encrypted_file_data, f, indent=2)
        
        return {
            'key_id': key_id,
            'output_path': output_path,
            'algorithm': algorithm,
            'metadata': file_metadata
        }
    
    def decrypt_pdf(self, 
                   input_path: str, 
                   output_path: Optional[str] = None, 
                   key: Optional[bytes] = None,
                   key_id: Optional[str] = None,
                   restore_metadata: bool = True) -> Dict[str, Any]:
        """
        Decrypt a PDF file.
        
        Args:
            input_path: Path to the encrypted PDF file
            output_path: Path to save the decrypted file (if None, uses original filename)
            key: The decryption key (if None, uses key_id to get key from key manager)
            key_id: The ID of the key to use (if key is None)
            restore_metadata: Whether to restore PDF metadata (title, author, etc.)
            
        Returns:
            A dictionary containing decryption metadata
            
        Raises:
            FileNotFoundError: If the input file doesn't exist
            PermissionError: If the output file can't be written
            ValueError: If the key can't be determined or the file format is invalid
            ImportError: If PyPDF2 is not available
        """
        self._check_pdf_library()
        import PyPDF2
        
        # Read the encrypted file
        with open(input_path, 'r') as f:
            try:
                encrypted_file_data = json.load(f)
            except json.JSONDecodeError:
                raise ValueError(f"Invalid encrypted file format: {input_path}")
        
        # Extract metadata and encrypted data
        try:
            metadata = encrypted_file_data['metadata']
            ciphertext = base64.b64decode(encrypted_file_data['ciphertext'])
            nonce = base64.b64decode(encrypted_file_data['nonce'])
            tag = base64.b64decode(encrypted_file_data['tag'])
        except (KeyError, base64.binascii.Error):
            raise ValueError(f"Invalid encrypted file structure: {input_path}")
        
        # Determine the key to use
        if key is None:
            if key_id is None:
                # Try to get key_id from metadata
                key_id = metadata.get('key_id')
                if key_id is None:
                    raise ValueError("No key or key_id provided and no key_id in file metadata")
            
            # Get the key from the key manager
            key = self.key_manager.get_key(key_id)
            if key is None:
                raise ValueError(f"Key with ID {key_id} not found in key manager")
        
        # Determine output path if not provided
        if output_path is None:
            # Use the original filename from metadata if available
            original_filename = metadata.get('filename')
            if original_filename:
                output_path = os.path.join(os.path.dirname(input_path), original_filename)
            else:
                # Remove the .pdf.encrypted extension if present
                if input_path.endswith(self.file_extension):
                    output_path = input_path[:-len(self.file_extension)]
                else:
                    output_path = input_path + '.decrypted.pdf'
        
        # Prepare the encryption result for decryption
        encryption_result = {
            'algorithm': metadata.get('encryption_algorithm', 'AES-GCM'),
            'ciphertext': ciphertext,
            'nonce': nonce,
            'tag': tag,
            'associated_data': None
        }
        
        # Decrypt the data
        try:
            pdf_bytes = self.encryption_engine.decrypt(
                encryption_result=encryption_result,
                key=key
            )
        except ValueError as e:
            raise ValueError(f"Decryption failed: {str(e)}")
        
        # If we need to restore metadata, modify the PDF
        if restore_metadata and metadata.get('pdf_metadata'):
            pdf_metadata = metadata.get('pdf_metadata', {})
            if pdf_metadata:
                # Read the decrypted PDF
                pdf_reader = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
                
                # Create a new PDF with the same content
                pdf_writer = PyPDF2.PdfWriter()
                for page in pdf_reader.pages:
                    pdf_writer.add_page(page)
                
                # Add the metadata
                pdf_writer.add_metadata(pdf_metadata)
                
                # Write to a new buffer
                pdf_bytes_buffer = io.BytesIO()
                pdf_writer.write(pdf_bytes_buffer)
                pdf_bytes = pdf_bytes_buffer.getvalue()
        
        # Write the decrypted PDF file
        with open(output_path, 'wb') as f:
            f.write(pdf_bytes)
        
        return {
            'output_path': output_path,
            'original_size': len(pdf_bytes),
            'metadata': metadata
        }
    
    def encrypt_pdf_sections(self,
                            input_path: str,
                            output_path: str,
                            sections: List[Tuple[int, int]],
                            key: Optional[bytes] = None,
                            algorithm: str = 'AES-GCM') -> Dict[str, Any]:
        """
        Encrypt specific sections of a PDF file.
        
        This is a placeholder for a more advanced feature that would allow
        encrypting only specific pages or sections of a PDF.
        
        Args:
            input_path: Path to the PDF file to encrypt
            output_path: Path to save the partially encrypted file
            sections: List of (start_page, end_page) tuples to encrypt
            key: The encryption key (if None, generates a new key)
            algorithm: The encryption algorithm to use
            
        Returns:
            A dictionary containing encryption metadata
            
        Raises:
            NotImplementedError: This feature is not yet implemented
        """
        raise NotImplementedError(
            "Selective PDF encryption is not yet implemented. "
            "Please use encrypt_pdf to encrypt the entire PDF."
        )
