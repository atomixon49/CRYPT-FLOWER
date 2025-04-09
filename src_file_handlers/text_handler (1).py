"""
Text File Handler

This module provides functionality for encrypting and decrypting text files.
"""

import os
import json
import base64
import chardet
from typing import Dict, Any, Optional, Union, BinaryIO, Tuple
from ..core.encryption import EncryptionEngine
from ..core.key_management import KeyManager

class TextFileHandler:
    """
    Handles encryption and decryption of text files.

    This class provides methods for securely encrypting and decrypting
    text files using the core encryption engine.
    """

    def __init__(self, key_manager: KeyManager, encryption_engine: EncryptionEngine, buffer_size: int = 1024 * 1024):
        """
        Initialize the text file handler.

        Args:
            key_manager: The key manager to use for key operations
            encryption_engine: The encryption engine to use for encryption/decryption
            buffer_size: Size of the buffer for reading/writing large files (default: 1MB)
        """
        self.key_manager = key_manager
        self.encryption_engine = encryption_engine
        self.file_extension = '.encrypted'
        self.buffer_size = buffer_size

    def encrypt_file(self,
                     input_path: str,
                     output_path: Optional[str] = None,
                     key: Optional[bytes] = None,
                     algorithm: str = 'AES-GCM',
                     metadata: Optional[Dict[str, Any]] = None,
                     password: Optional[str] = None,
                     salt: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Encrypt a text file.

        Args:
            input_path: Path to the file to encrypt
            output_path: Path to save the encrypted file (if None, uses input_path + .encrypted)
            key: The encryption key (if None, generates a new key)
            algorithm: The encryption algorithm to use
            metadata: Optional metadata to include with the encrypted file

        Returns:
            A dictionary containing encryption metadata including the key ID

        Raises:
            FileNotFoundError: If the input file doesn't exist
            PermissionError: If the output file can't be written
        """
        # Determine output path if not provided
        if output_path is None:
            output_path = input_path + self.file_extension

        # Handle key generation based on password or key manager
        key_id = None
        encryption_method = None
        password_salt = None

        if key is None:
            if password:
                # Password-based encryption
                encryption_method = 'password_based'
                # Generate a salt if not provided
                if salt is None:
                    password_salt = os.urandom(16)
                else:
                    password_salt = salt
                # Derive key from password and salt
                key, _ = self.key_manager.derive_key_from_password(password, password_salt)
            else:
                # Key manager-based encryption
                encryption_method = 'key_manager'
                key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
                key_id = list(self.key_manager.active_keys.keys())[-1]  # Get the ID of the key we just generated
        else:
            # For externally provided keys
            encryption_method = 'external_key'

        # Detect encoding from a sample of the file
        encoding_info = self._detect_encoding(input_path)
        encoding = encoding_info['encoding']
        confidence = encoding_info['confidence']

        # Get file size
        file_size = os.path.getsize(input_path)

        # For small files, read the entire content at once
        if file_size <= self.buffer_size:
            with open(input_path, 'rb') as f:
                plaintext = f.read()
        else:
            # For large files, use buffered reading
            return self._encrypt_large_file(
                input_path=input_path,
                output_path=output_path,
                key=key,
                algorithm=algorithm,
                metadata=metadata,
                password=password,
                salt=salt,
                encoding=encoding,
                confidence=confidence,
                encryption_method=encryption_method,
                key_id=key_id,
                password_salt=password_salt
            )

        # Encrypt the data
        encryption_result = self.encryption_engine.encrypt(
            data=plaintext,
            key=key,
            algorithm=algorithm,
            associated_data=None
        )

        # Prepare metadata
        file_metadata = {
            'filename': os.path.basename(input_path),
            'original_size': len(plaintext),
            'encryption_algorithm': algorithm,
            'encryption_method': encryption_method,
            'user_metadata': metadata or {}
        }

        # Add method-specific metadata
        if encryption_method == 'key_manager':
            file_metadata['key_id'] = key_id
        elif encryption_method == 'password_based' and password_salt:
            # Store salt in metadata (base64 encoded)
            file_metadata['salt'] = base64.b64encode(password_salt).decode('ascii')

        # Add encoding information to metadata
        file_metadata['encoding'] = encoding
        file_metadata['encoding_confidence'] = confidence

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

    def decrypt_file(self,
                     input_path: str,
                     output_path: Optional[str] = None,
                     key: Optional[bytes] = None,
                     key_id: Optional[str] = None,
                     password: Optional[str] = None,
                     salt: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Decrypt a text file.

        Args:
            input_path: Path to the encrypted file
            output_path: Path to save the decrypted file (if None, uses original filename)
            key: The decryption key (if None, uses key_id to get key from key manager)
            key_id: The ID of the key to use (if key is None)

        Returns:
            A dictionary containing decryption metadata

        Raises:
            FileNotFoundError: If the input file doesn't exist
            PermissionError: If the output file can't be written
            ValueError: If the key can't be determined or the file format is invalid
        """
        # Read the encrypted file
        with open(input_path, 'r') as f:
            try:
                encrypted_file_data = json.load(f)
            except json.JSONDecodeError:
                raise ValueError(f"Invalid encrypted file format: {input_path}")

        # Extract metadata
        try:
            metadata = encrypted_file_data['metadata']

            # Check if this is a chunked file
            if metadata.get('chunked', False):
                # Handle large file decryption
                chunks = encrypted_file_data.get('chunks', [])
                if not chunks:
                    raise ValueError(f"Invalid chunked file structure: no chunks found in {input_path}")
            else:
                # Regular file decryption
                ciphertext = base64.b64decode(encrypted_file_data['ciphertext'])
                nonce = base64.b64decode(encrypted_file_data['nonce'])
                tag = base64.b64decode(encrypted_file_data['tag'])
        except (KeyError, base64.binascii.Error):
            raise ValueError(f"Invalid encrypted file structure: {input_path}")

        # Determine the key to use based on encryption method
        encryption_method = metadata.get('encryption_method', 'key_manager')  # Default for backward compatibility

        if key is None:
            if encryption_method == 'password_based':
                if not password:
                    raise ValueError("Password required for password-based encryption")

                # Get salt from metadata if available, otherwise use provided salt
                metadata_salt = metadata.get('salt')
                if metadata_salt:
                    # Salt is stored as base64 in metadata
                    password_salt = base64.b64decode(metadata_salt)
                elif salt:
                    password_salt = salt
                else:
                    raise ValueError("Salt not found in metadata and not provided")

                # Derive key from password and salt
                key, _ = self.key_manager.derive_key_from_password(password, password_salt)

            elif encryption_method == 'key_manager' or encryption_method is None:  # None for backward compatibility
                # If salt is provided, assume it's for backward compatibility
                if salt and password:
                    # Derive key from password and provided salt
                    key, _ = self.key_manager.derive_key_from_password(password, salt)
                else:
                    if key_id is None:
                        # Try to get key_id from metadata
                        key_id = metadata.get('key_id')
                        if key_id is None:
                            raise ValueError("No key or key_id provided and no key_id in file metadata")

                    # Get the key from the key manager
                    key = self.key_manager.get_key(key_id)
                    if key is None:
                        raise ValueError(f"Key with ID {key_id} not found in key manager")

            else:
                raise ValueError(f"Unsupported encryption method: {encryption_method}")

        # Determine output path if not provided
        if output_path is None:
            # Use the original filename from metadata if available
            original_filename = metadata.get('filename')
            if original_filename:
                output_path = os.path.join(os.path.dirname(input_path), original_filename)
            else:
                # Remove the .encrypted extension if present
                if input_path.endswith(self.file_extension):
                    output_path = input_path[:-len(self.file_extension)]
                else:
                    output_path = input_path + '.decrypted'

        # Handle decryption based on file type (chunked or regular)
        if metadata.get('chunked', False):
            # Decrypt large file in chunks
            try:
                self._decrypt_large_file(
                    input_path=input_path,
                    output_path=output_path,
                    key=key,
                    metadata=metadata,
                    chunks=encrypted_file_data['chunks']
                )
            except ValueError as e:
                raise ValueError(f"Decryption failed: {str(e)}")
        else:
            # Regular file decryption
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
                plaintext = self.encryption_engine.decrypt(
                    encryption_result=encryption_result,
                    key=key
                )
            except ValueError as e:
                raise ValueError(f"Decryption failed: {str(e)}")

            # Get encoding information from metadata
            encoding = metadata.get('encoding', 'utf-8')  # Default to UTF-8 if not specified

            # Write the decrypted file using the original encoding
            try:
                # Try to write with the detected encoding
                with open(output_path, 'wb') as f:
                    f.write(plaintext)
            except Exception as e:
                # If that fails, try UTF-8
                print(f"Warning: Failed to write with encoding {encoding}: {str(e)}. Falling back to binary mode.")

        # Get original size from metadata
        original_size = metadata.get('original_size', 0)
        encoding = metadata.get('encoding', 'utf-8')

        return {
            'output_path': output_path,
            'original_size': original_size,
            'metadata': metadata,
            'encoding': encoding
        }

    def _encrypt_large_file(self,
                         input_path: str,
                         output_path: str,
                         key: bytes,
                         algorithm: str,
                         metadata: Optional[Dict[str, Any]],
                         password: Optional[str],
                         salt: Optional[bytes],
                         encoding: str,
                         confidence: float,
                         encryption_method: str,
                         key_id: Optional[str],
                         password_salt: Optional[bytes]) -> Dict[str, Any]:
        """
        Encrypt a large file using buffered reading/writing.

        Args:
            input_path: Path to the file to encrypt
            output_path: Path to save the encrypted file
            key: The encryption key
            algorithm: The encryption algorithm to use
            metadata: Optional metadata to include with the encrypted file
            password: Password used for encryption (if applicable)
            salt: Salt used for password-based encryption (if applicable)
            encoding: Detected encoding of the input file
            confidence: Confidence level of the encoding detection
            encryption_method: Method used for encryption (key_manager, password_based, external_key)
            key_id: ID of the key used (if applicable)
            password_salt: Salt used for password-based encryption (if applicable)

        Returns:
            A dictionary containing encryption metadata
        """
        # Get file size for metadata
        file_size = os.path.getsize(input_path)

        # Create a temporary file for the encrypted content
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name

        try:
            # Process the file in chunks
            chunks = []
            total_size = 0
            chunk_count = 0

            # Read and encrypt the file in chunks
            with open(input_path, 'rb') as f:
                while True:
                    chunk = f.read(self.buffer_size)
                    if not chunk:
                        break

                    # Encrypt the chunk
                    encryption_result = self.encryption_engine.encrypt(
                        data=chunk,
                        key=key,
                        algorithm=algorithm,
                        associated_data=None
                    )

                    # Store chunk metadata
                    chunk_info = {
                        'index': chunk_count,
                        'size': len(chunk),
                        'ciphertext': base64.b64encode(encryption_result['ciphertext']).decode('ascii'),
                        'nonce': base64.b64encode(encryption_result['nonce']).decode('ascii'),
                        'tag': base64.b64encode(encryption_result['tag']).decode('ascii')
                    }
                    chunks.append(chunk_info)
                    total_size += len(chunk)
                    chunk_count += 1

            # Prepare metadata
            file_metadata = {
                'filename': os.path.basename(input_path),
                'original_size': file_size,
                'encryption_algorithm': algorithm,
                'encryption_method': encryption_method,
                'chunked': True,
                'chunk_size': self.buffer_size,
                'chunk_count': chunk_count,
                'user_metadata': metadata or {}
            }

            # Add method-specific metadata
            if encryption_method == 'key_manager':
                file_metadata['key_id'] = key_id
            elif encryption_method == 'password_based' and password_salt:
                # Store salt in metadata (base64 encoded)
                file_metadata['salt'] = base64.b64encode(password_salt).decode('ascii')

            # Add encoding information to metadata
            file_metadata['encoding'] = encoding
            file_metadata['encoding_confidence'] = confidence

            # Prepare the encrypted file structure
            encrypted_file_data = {
                'metadata': file_metadata,
                'chunks': chunks
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

        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _decrypt_large_file(self,
                         input_path: str,
                         output_path: str,
                         key: bytes,
                         metadata: Dict[str, Any],
                         chunks: List[Dict[str, Any]]) -> None:
        """
        Decrypt a large file that was encrypted in chunks.

        Args:
            input_path: Path to the encrypted file
            output_path: Path to save the decrypted file
            key: The decryption key
            metadata: Metadata from the encrypted file
            chunks: List of chunk information

        Raises:
            ValueError: If decryption fails
        """
        # Get the algorithm from metadata
        algorithm = metadata.get('encryption_algorithm', 'AES-GCM')

        # Open the output file for writing
        with open(output_path, 'wb') as out_f:
            # Process each chunk
            for chunk_info in chunks:
                # Extract chunk data
                ciphertext = base64.b64decode(chunk_info['ciphertext'])
                nonce = base64.b64decode(chunk_info['nonce'])
                tag = base64.b64decode(chunk_info['tag'])

                # Prepare the encryption result for decryption
                encryption_result = {
                    'algorithm': algorithm,
                    'ciphertext': ciphertext,
                    'nonce': nonce,
                    'tag': tag,
                    'associated_data': None
                }

                # Decrypt the chunk
                try:
                    plaintext = self.encryption_engine.decrypt(
                        encryption_result=encryption_result,
                        key=key
                    )
                except ValueError as e:
                    raise ValueError(f"Decryption failed for chunk {chunk_info['index']}: {str(e)}")

                # Write the decrypted chunk to the output file
                out_f.write(plaintext)

    def _detect_encoding(self, file_path: str) -> Dict[str, Any]:
        """
        Detect the encoding of a text file.

        Args:
            file_path: Path to the file

        Returns:
            Dictionary with encoding information
        """
        # Read a sample of the file (first 4KB should be enough for most files)
        sample_size = 4096
        with open(file_path, 'rb') as f:
            sample = f.read(sample_size)

        # Detect encoding
        result = chardet.detect(sample)

        # If confidence is low, default to UTF-8
        if result['confidence'] < 0.7:
            return {
                'encoding': 'utf-8',
                'confidence': 1.0,
                'detected': result
            }

        return {
            'encoding': result['encoding'],
            'confidence': result['confidence'],
            'detected': result
        }
