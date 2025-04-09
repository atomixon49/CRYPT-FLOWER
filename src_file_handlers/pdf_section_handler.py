"""
PDF Section Handler

This module provides functionality for encrypting and decrypting specific sections of PDF files.
"""

import os
import json
import base64
import io
from typing import Dict, Any, Optional, Union, List, Tuple, Set
from datetime import datetime
from ..core.encryption import EncryptionEngine
from ..core.key_management import KeyManager

class PDFSectionHandler:
    """
    Handles encryption and decryption of specific sections of PDF files.

    This class provides methods for securely encrypting and decrypting
    selected sections of PDF files, such as specific pages or regions.
    """

    def __init__(self, key_manager: KeyManager, encryption_engine: EncryptionEngine):
        """
        Initialize the PDF section handler.

        Args:
            key_manager: The key manager to use for key operations
            encryption_engine: The encryption engine to use for encryption/decryption
        """
        self.key_manager = key_manager
        self.encryption_engine = encryption_engine
        self.file_extension = '.section-encrypted.pdf'

        # Try to import pypdf, but don't fail if it's not available
        # We'll check for its availability before using it
        try:
            import pypdf
            self.pypdf_available = True
            self.pypdf = pypdf
        except ImportError:
            self.pypdf_available = False
            self.pypdf = None

    def _check_pdf_library(self):
        """
        Check if the required PDF library is available.

        Raises:
            ImportError: If pypdf is not available
        """
        if not self.pypdf_available:
            raise ImportError(
                "pypdf is required for PDF operations. "
                "Please install it with 'pip install pypdf'."
            )

    def encrypt_pages(self,
                     input_path: str,
                     output_path: Optional[str] = None,
                     pages: Optional[Union[List[int], str]] = None,
                     key: Optional[bytes] = None,
                     key_id: Optional[str] = None,
                     password: Optional[str] = None,
                     algorithm: str = 'AES-GCM',
                     metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Encrypt specific pages of a PDF file.

        Args:
            input_path: Path to the PDF file
            output_path: Path to save the encrypted PDF (if None, uses input_path + .section-encrypted.pdf)
            pages: List of page numbers to encrypt (1-based) or string like "1,3-5,7"
            key: The encryption key (if None, uses key_id to get key from key manager)
            key_id: The ID of the key to use (if key is None)
            password: Password for password-based encryption (if key and key_id are None)
            algorithm: The encryption algorithm to use
            metadata: Optional metadata to include with the encrypted file

        Returns:
            A dictionary containing encryption metadata

        Raises:
            ImportError: If pypdf is not available
            FileNotFoundError: If the input file doesn't exist
            ValueError: If no pages are specified or the key can't be determined
        """
        self._check_pdf_library()

        # Determine output path if not provided
        if output_path is None:
            output_path = input_path + self.file_extension

        # Parse pages parameter
        page_set = self._parse_pages(pages)
        if not page_set:
            raise ValueError("No pages specified for encryption")

        # Determine the key to use
        encryption_key, encryption_method, key_identifier, salt = self._determine_key(
            key, key_id, password
        )

        # Open the PDF file
        with open(input_path, 'rb') as f:
            pdf_reader = self.pypdf.PdfReader(f)
            pdf_writer = self.pypdf.PdfWriter()

            # Process each page
            encrypted_pages_info = []
            for i, page in enumerate(pdf_reader.pages):
                page_number = i + 1  # Convert to 1-based page numbering

                if page_number in page_set:
                    # This page should be encrypted
                    # Extract the page content as bytes
                    page_buffer = io.BytesIO()
                    page_writer = self.pypdf.PdfWriter()
                    page_writer.add_page(page)
                    page_writer.write(page_buffer)
                    page_buffer.seek(0)
                    page_content = page_buffer.read()

                    # Encrypt the page content
                    encryption_result = self.encryption_engine.encrypt(
                        data=page_content,
                        key=encryption_key,
                        algorithm=algorithm,
                        associated_data=None
                    )

                    # Create a blank page with the same dimensions
                    blank_page = self.pypdf.PageObject.create_blank_page(
                        width=page.mediabox.width,
                        height=page.mediabox.height
                    )

                    # Add a note that this page is encrypted
                    pdf_writer.add_page(blank_page)

                    # Store encryption information for this page
                    page_info = {
                        "type": "page",
                        "page_number": page_number,
                        "algorithm": algorithm,
                        "encryption_method": encryption_method,
                        "ciphertext": base64.b64encode(encryption_result["ciphertext"]).decode('ascii'),
                        "nonce": base64.b64encode(encryption_result["nonce"]).decode('ascii'),
                        "tag": base64.b64encode(encryption_result["tag"]).decode('ascii')
                    }

                    # Add method-specific information
                    if encryption_method == "key_manager":
                        page_info["key_id"] = key_identifier
                    elif encryption_method == "password_based" and salt:
                        page_info["salt"] = base64.b64encode(salt).decode('ascii')

                    encrypted_pages_info.append(page_info)
                else:
                    # This page should remain as is
                    pdf_writer.add_page(page)

            # Prepare document metadata
            document_metadata = {
                "original_filename": os.path.basename(input_path),
                "encryption_date": datetime.now().isoformat(),
                "software_version": "1.0.0",
                "user_metadata": metadata or {}
            }

            # Create the complete encryption metadata
            encryption_metadata = {
                "encrypted_sections": encrypted_pages_info,
                "document_metadata": document_metadata
            }

            # Add encryption metadata to the PDF
            metadata_str = json.dumps(encryption_metadata)
            pdf_writer.add_metadata({
                "/SectionEncryptionMetadata": metadata_str
            })

            # Save the encrypted PDF
            with open(output_path, 'wb') as output_file:
                pdf_writer.write(output_file)

            # Also save metadata to a separate JSON file for easier access
            metadata_path = output_path + '.metadata.json'
            with open(metadata_path, 'w') as metadata_file:
                json.dump(encryption_metadata, metadata_file, indent=2)

        return {
            "output_path": output_path,
            "metadata_path": metadata_path,
            "encrypted_pages": list(page_set),
            "encryption_method": encryption_method,
            "algorithm": algorithm
        }

    def decrypt_pages(self,
                     input_path: str,
                     output_path: Optional[str] = None,
                     key: Optional[bytes] = None,
                     key_id: Optional[str] = None,
                     password: Optional[str] = None) -> Dict[str, Any]:
        """
        Decrypt specific pages of a PDF file.

        Args:
            input_path: Path to the encrypted PDF file
            output_path: Path to save the decrypted PDF (if None, uses input_path + .decrypted.pdf)
            key: The decryption key (if None, uses key_id to get key from key manager)
            key_id: The ID of the key to use (if key is None)
            password: Password for password-based decryption (if key and key_id are None)

        Returns:
            A dictionary containing decryption metadata

        Raises:
            ImportError: If pypdf is not available
            FileNotFoundError: If the input file doesn't exist
            ValueError: If the file doesn't contain encrypted sections or the key can't be determined
        """
        self._check_pdf_library()

        # Determine output path if not provided
        if output_path is None:
            output_path = os.path.splitext(input_path)[0] + '.decrypted.pdf'

        # Try to load encryption metadata from the PDF
        encryption_metadata = None

        # First try to read from the separate metadata file
        metadata_path = input_path + '.metadata.json'
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r') as metadata_file:
                    encryption_metadata = json.load(metadata_file)
            except (json.JSONDecodeError, IOError):
                pass

        # If that fails, try to extract from the PDF itself
        if encryption_metadata is None:
            with open(input_path, 'rb') as f:
                pdf_reader = self.pypdf.PdfReader(f)
                if "/SectionEncryptionMetadata" in pdf_reader.metadata:
                    try:
                        metadata_str = pdf_reader.metadata["/SectionEncryptionMetadata"]
                        encryption_metadata = json.loads(metadata_str)
                    except (json.JSONDecodeError, TypeError):
                        pass

        if encryption_metadata is None:
            raise ValueError("No encryption metadata found in the PDF file")

        # Extract encrypted sections information
        encrypted_sections = encryption_metadata.get("encrypted_sections", [])
        if not encrypted_sections:
            raise ValueError("No encrypted sections found in the PDF file")

        # Open the PDF file
        with open(input_path, 'rb') as f:
            pdf_reader = self.pypdf.PdfReader(f)
            pdf_writer = self.pypdf.PdfWriter()

            # Copy all pages first
            for page in pdf_reader.pages:
                pdf_writer.add_page(page)

            # Process each encrypted section
            decrypted_pages = []
            for section in encrypted_sections:
                if section["type"] != "page":
                    # Currently only supporting page-level encryption
                    continue

                # Get section information
                page_number = section["page_number"]
                algorithm = section["algorithm"]
                encryption_method = section.get("encryption_method", "key_manager")  # Default for backward compatibility

                # Determine the key to use
                decryption_key = None

                if key is not None:
                    # Use the provided key
                    decryption_key = key
                elif encryption_method == "password_based":
                    if not password:
                        raise ValueError("Password required for password-based encryption")

                    # Get salt from metadata if available
                    metadata_salt = section.get("salt")
                    if metadata_salt:
                        # Salt is stored as base64 in metadata
                        salt = base64.b64decode(metadata_salt)
                        # Derive key from password and salt
                        decryption_key, _ = self.key_manager.derive_key_from_password(password, salt)
                    else:
                        raise ValueError("Salt not found in metadata")

                elif encryption_method == "key_manager" or encryption_method is None:
                    if key_id is None:
                        # Try to get key_id from metadata
                        key_id = section.get("key_id")
                        if key_id is None:
                            raise ValueError("No key or key_id provided and no key_id in section metadata")

                    # Get the key from the key manager
                    decryption_key = self.key_manager.get_key(key_id)
                    if decryption_key is None:
                        raise ValueError(f"Key with ID {key_id} not found in key manager")

                else:
                    raise ValueError(f"Unsupported encryption method: {encryption_method}")

                # Decrypt the page content
                ciphertext = base64.b64decode(section["ciphertext"])
                nonce = base64.b64decode(section["nonce"])
                tag = base64.b64decode(section["tag"])

                try:
                    # Create encryption result dictionary for the decryption function
                    encryption_result = {
                        'algorithm': algorithm,
                        'ciphertext': ciphertext,
                        'nonce': nonce,
                        'tag': tag,
                        'associated_data': None
                    }

                    # Decrypt the content
                    decrypted_content = self.encryption_engine.decrypt(
                        encryption_result=encryption_result,
                        key=decryption_key
                    )
                except ValueError as e:
                    raise ValueError(f"Failed to decrypt page {page_number}: {str(e)}")

                # Load the decrypted page
                page_buffer = io.BytesIO(decrypted_content)
                decrypted_reader = self.pypdf.PdfReader(page_buffer)
                if len(decrypted_reader.pages) > 0:
                    # Replace the placeholder page with the decrypted page
                    # In newer versions of pypdf, we need to use a different approach
                    # to replace pages
                    new_writer = self.pypdf.PdfWriter()

                    # Copy all pages from the original writer
                    for i, page in enumerate(pdf_writer.pages):
                        if i == page_number - 1:
                            # Replace this page with the decrypted one
                            new_writer.add_page(decrypted_reader.pages[0])
                        else:
                            # Keep the original page
                            new_writer.add_page(page)

                    # Replace the writer
                    pdf_writer = new_writer
                    decrypted_pages.append(page_number)

            # Save the decrypted PDF
            with open(output_path, 'wb') as output_file:
                pdf_writer.write(output_file)

        return {
            "output_path": output_path,
            "decrypted_pages": decrypted_pages,
            "total_sections": len(encrypted_sections)
        }

    def _parse_pages(self, pages: Optional[Union[List[int], str]]) -> Set[int]:
        """
        Parse the pages parameter into a set of page numbers.

        Args:
            pages: List of page numbers or string like "1,3-5,7"

        Returns:
            A set of page numbers
        """
        if pages is None:
            return set()

        if isinstance(pages, list):
            return set(pages)

        if not isinstance(pages, str):
            raise ValueError("Pages must be a list of integers or a string")

        result = set()
        parts = pages.split(',')

        for part in parts:
            part = part.strip()
            if '-' in part:
                # Range of pages
                try:
                    start, end = map(int, part.split('-'))
                    result.update(range(start, end + 1))
                except ValueError:
                    raise ValueError(f"Invalid page range: {part}")
            else:
                # Single page
                try:
                    result.add(int(part))
                except ValueError:
                    raise ValueError(f"Invalid page number: {part}")

        return result

    def _determine_key(self,
                      key: Optional[bytes],
                      key_id: Optional[str],
                      password: Optional[str]) -> Tuple[bytes, str, Optional[str], Optional[bytes]]:
        """
        Determine the key to use for encryption.

        Args:
            key: The encryption key
            key_id: The ID of the key to use
            password: Password for password-based encryption

        Returns:
            A tuple of (encryption_key, encryption_method, key_identifier, salt)

        Raises:
            ValueError: If the key can't be determined
        """
        if key is not None:
            # Use the provided key
            return key, "external_key", None, None

        if password is not None:
            # Derive key from password
            salt = os.urandom(16)
            derived_key, _ = self.key_manager.derive_key_from_password(password, salt)
            return derived_key, "password_based", None, salt

        if key_id is not None:
            # Get key from key manager
            key = self.key_manager.get_key(key_id)
            if key is None:
                raise ValueError(f"Key with ID {key_id} not found in key manager")
            return key, "key_manager", key_id, None

        # Generate a new key
        key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        key_id = list(self.key_manager.active_keys.keys())[-1]  # Get the ID of the key we just generated
        return key, "key_manager", key_id, None
