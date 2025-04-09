"""
Directory Handler

This module provides functionality for encrypting and decrypting entire directories.
"""

import os
import json
import time
import shutil
import multiprocessing
import concurrent.futures
from datetime import datetime
from typing import Dict, Any, Optional, Union, List, Callable, Tuple, Set
from pathlib import Path

from ..core.encryption import EncryptionEngine
from ..core.key_management import KeyManager
from ..utils.cross_platform_file_type import get_appropriate_handler
from .text_handler import TextFileHandler
from .pdf_handler import PDFHandler
from .pdf_section_handler import PDFSectionHandler

class DirectoryHandler:
    """
    Handles encryption and decryption of entire directories.

    This class provides methods for securely encrypting and decrypting
    directories recursively, preserving the directory structure.
    """

    def __init__(self, key_manager: KeyManager, encryption_engine: EncryptionEngine):
        """
        Initialize the directory handler.

        Args:
            key_manager: The key manager to use for key operations
            encryption_engine: The encryption engine to use for encryption/decryption
        """
        self.key_manager = key_manager
        self.encryption_engine = encryption_engine
        self.file_extension = '.dir.encrypted'

        # Initialize file handlers for different file types
        self.text_handler = TextFileHandler(key_manager, encryption_engine)
        self.pdf_handler = PDFHandler(key_manager, encryption_engine)
        self.pdf_section_handler = PDFSectionHandler(key_manager, encryption_engine)

        # Try to import pypdf, but don't fail if it's not available
        try:
            import pypdf
            self.pypdf_available = True
        except ImportError:
            self.pypdf_available = False

        # Set default number of workers for parallel processing
        self.max_workers = multiprocessing.cpu_count()

    def encrypt_directory(self,
                         input_path: str,
                         output_path: Optional[str] = None,
                         key: Optional[bytes] = None,
                         key_id: Optional[str] = None,
                         password: Optional[str] = None,
                         algorithm: str = 'AES-GCM',
                         progress_callback: Optional[Callable[[int, int, str], None]] = None,
                         metadata: Optional[Dict[str, Any]] = None,
                         use_parallel: bool = True,
                         max_workers: Optional[int] = None) -> Dict[str, Any]:
        """
        Encrypt a directory recursively.

        Args:
            input_path: Path to the directory to encrypt
            output_path: Path to save the encrypted directory (if None, uses input_path + .dir.encrypted)
            key: The encryption key (if None, uses key_id to get key or generates a new key)
            key_id: The ID of the key to use (if None and key not provided, generates a new key)
            password: Password to use for encryption (if provided, key and key_id are ignored)
            algorithm: The encryption algorithm to use
            progress_callback: Optional callback function to report progress
            metadata: Optional metadata to include with the encrypted directory
            use_parallel: Whether to use parallel processing for encrypting files (default: True)
            max_workers: Maximum number of worker threads to use (default: number of CPU cores)

        Returns:
            A dictionary containing encryption metadata and statistics

        Raises:
            FileNotFoundError: If the input directory doesn't exist
            ValueError: If the key can't be determined
        """
        # Validate input path
        input_path = os.path.abspath(input_path)
        if not os.path.isdir(input_path):
            raise FileNotFoundError(f"Directory not found: {input_path}")

        # Determine output path if not provided
        if output_path is None:
            output_path = input_path + self.file_extension
        output_path = os.path.abspath(output_path)

        # Create output directory if it doesn't exist
        os.makedirs(output_path, exist_ok=True)

        # Determine the key to use
        encryption_key = None
        if password:
            # For password-based encryption, we'll generate a key for each file
            # So we don't need a key here
            pass
        elif key:
            # Use the provided key
            encryption_key = key
        elif key_id:
            # Get the key from the key manager
            encryption_key = self.key_manager.get_key(key_id)
            if encryption_key is None:
                raise ValueError(f"Key not found: {key_id}")
        else:
            # Generate a new key
            if not hasattr(self.key_manager, 'generate_symmetric_key'):
                raise ValueError("Key manager doesn't support key generation")

            encryption_key = self.key_manager.generate_symmetric_key(algorithm=algorithm)
            key_id = list(self.key_manager.active_keys.keys())[-1]

        # Initialize metadata
        dir_metadata = {
            "version": "1.0",
            "encrypted_at": datetime.now().isoformat(),
            "algorithm": algorithm,
            "directory_structure": {
                "original_path": input_path,
                "encrypted_path": output_path,
                "files": [],
                "directories": []
            }
        }

        if metadata:
            dir_metadata.update(metadata)

        # Count total files for progress reporting
        total_files = sum([len(files) for _, _, files in os.walk(input_path)])
        processed_files = 0

        # Start encryption
        start_time = time.time()

        # Set max_workers if not provided
        if max_workers is None:
            max_workers = self.max_workers

        # Encrypt the directory recursively
        if use_parallel and total_files > 1:
            self._encrypt_directory_parallel(
                input_path=input_path,
                output_path=output_path,
                key=encryption_key,
                key_id=key_id,
                password=password,
                algorithm=algorithm,
                dir_metadata=dir_metadata["directory_structure"],
                progress_callback=progress_callback,
                total_files=total_files,
                max_workers=max_workers
            )
        else:
            # Use sequential processing for small directories
            self._encrypt_directory_recursive(
                input_path=input_path,
                output_path=output_path,
                key=encryption_key,
                key_id=key_id,
                password=password,
                algorithm=algorithm,
                dir_metadata=dir_metadata["directory_structure"],
                progress_callback=progress_callback,
                total_files=total_files,
                processed_files=processed_files
            )

        # Add encryption statistics
        dir_metadata["statistics"] = {
            "total_files": total_files,
            "processed_files": processed_files,
            "encryption_time": time.time() - start_time
        }

        # Save metadata
        metadata_path = os.path.join(output_path, ".metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(dir_metadata, f, indent=2)

        return {
            "output_path": output_path,
            "metadata_path": metadata_path,
            "key_id": key_id,
            "algorithm": algorithm,
            "total_files": total_files,
            "processed_files": processed_files,
            "encryption_time": time.time() - start_time
        }

    def _encrypt_directory_parallel(self,
                                  input_path: str,
                                  output_path: str,
                                  key: Optional[bytes],
                                  key_id: Optional[str],
                                  password: Optional[str],
                                  algorithm: str,
                                  dir_metadata: Dict[str, Any],
                                  progress_callback: Optional[Callable[[int, int, str], None]],
                                  total_files: int,
                                  max_workers: int) -> None:
        """
        Encrypt a directory using parallel processing.

        Args:
            input_path: Path to the directory to encrypt
            output_path: Path to save the encrypted directory
            key: The encryption key
            key_id: The ID of the key to use
            password: Password to use for encryption
            algorithm: The encryption algorithm to use
            dir_metadata: Dictionary to store metadata
            progress_callback: Callback function to report progress
            total_files: Total number of files to process
            max_workers: Maximum number of worker threads
        """
        # Collect all files to encrypt
        files_to_encrypt = []
        for root, _, files in os.walk(input_path):
            for file in files:
                file_path = os.path.join(root, file)
                # Skip the output directory if it's a subdirectory of the input
                if os.path.abspath(file_path) == os.path.abspath(output_path):
                    continue

                # Get relative path for output
                rel_path = os.path.relpath(root, input_path)
                output_dir = os.path.join(output_path, rel_path)

                # Create output directory if it doesn't exist
                os.makedirs(output_dir, exist_ok=True)

                files_to_encrypt.append({
                    'file_path': file_path,
                    'output_dir': output_dir,
                    'file_name': file
                })

        # Create a lock for thread-safe progress updates
        progress_lock = multiprocessing.Lock()
        processed_files = multiprocessing.Value('i', 0)

        # Define the worker function
        def encrypt_file_worker(file_info):
            try:
                file_path = file_info['file_path']
                output_dir = file_info['output_dir']
                file_name = file_info['file_name']

                # Determine the appropriate handler
                handler_type, _ = get_appropriate_handler(file_path)

                # Get the appropriate handler
                if handler_type == "pdf":
                    handler = self.pdf_handler
                else:
                    handler = self.text_handler

                # Encrypt the file
                encrypted_path = os.path.join(output_dir, file_name + handler.file_extension)

                # Call encrypt_file with the appropriate parameters
                if password:
                    result = handler.encrypt_file(
                        input_path=file_path,
                        output_path=encrypted_path,
                        password=password,
                        algorithm=algorithm
                    )
                else:
                    result = handler.encrypt_file(
                        input_path=file_path,
                        output_path=encrypted_path,
                        key=key,
                        algorithm=algorithm
                    )

                # Update metadata
                file_metadata = {
                    "original_path": os.path.relpath(file_path, input_path),
                    "encrypted_path": os.path.relpath(encrypted_path, output_path),
                    "algorithm": algorithm,
                    "timestamp": time.time()
                }

                # Update progress
                with progress_lock:
                    with processed_files.get_lock():
                        processed_files.value += 1
                        current_progress = processed_files.value

                    if progress_callback:
                        progress_callback(current_progress, total_files, file_path)

                return file_metadata
            except Exception as e:
                print(f"Error encrypting {file_path}: {str(e)}")
                return None

        # Process files in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all encryption tasks
            future_to_file = {executor.submit(encrypt_file_worker, file_info): file_info for file_info in files_to_encrypt}

            # Collect results as they complete
            file_metadata_list = []
            for future in concurrent.futures.as_completed(future_to_file):
                file_info = future_to_file[future]
                try:
                    file_metadata = future.result()
                    if file_metadata:
                        file_metadata_list.append(file_metadata)
                except Exception as e:
                    print(f"Error processing {file_info['file_path']}: {str(e)}")

        # Update directory metadata
        dir_metadata["files"] = file_metadata_list

        # Process subdirectories (not in parallel to avoid race conditions with metadata)
        for item in os.listdir(input_path):
            item_path = os.path.join(input_path, item)

            # Skip the output directory if it's a subdirectory of the input
            if os.path.abspath(item_path) == os.path.abspath(output_path):
                continue

            if os.path.isdir(item_path):
                # Create subdirectory in output
                subdir_output = os.path.join(output_path, item)
                os.makedirs(subdir_output, exist_ok=True)

                # Initialize subdirectory metadata
                subdir_metadata = {
                    "original_path": os.path.relpath(item_path, input_path),
                    "encrypted_path": os.path.relpath(subdir_output, output_path),
                    "files": [],
                    "directories": []
                }

                # Add subdirectory to parent metadata
                dir_metadata["directories"].append(subdir_metadata)

                # Recursively encrypt the subdirectory
                self._encrypt_directory_parallel(
                    input_path=item_path,
                    output_path=subdir_output,
                    key=key,
                    key_id=key_id,
                    password=password,
                    algorithm=algorithm,
                    dir_metadata=subdir_metadata,
                    progress_callback=progress_callback,
                    total_files=total_files,
                    max_workers=max_workers
                )

    def _encrypt_directory_recursive(self,
                                    input_path: str,
                                    output_path: str,
                                    key: Optional[bytes],
                                    key_id: Optional[str],
                                    password: Optional[str],
                                    algorithm: str,
                                    dir_metadata: Dict[str, Any],
                                    progress_callback: Optional[Callable[[int, int, str], None]],
                                    total_files: int,
                                    processed_files: int) -> int:
        """
        Recursively encrypt a directory.

        Args:
            input_path: Path to the directory to encrypt
            output_path: Path to save the encrypted directory
            key: The encryption key
            key_id: The ID of the key to use
            password: Password to use for encryption
            algorithm: The encryption algorithm to use
            dir_metadata: Dictionary to store metadata
            progress_callback: Callback function to report progress
            total_files: Total number of files to process
            processed_files: Number of files processed so far

        Returns:
            Number of files processed
        """
        # Process files in the current directory
        for item in os.listdir(input_path):
            item_path = os.path.join(input_path, item)

            # Skip the output directory if it's a subdirectory of the input
            if os.path.abspath(item_path) == os.path.abspath(output_path):
                continue

            if os.path.isfile(item_path):
                # Encrypt the file
                try:
                    # Determine the appropriate handler
                    handler_type, _ = get_appropriate_handler(item_path)

                    # Get the appropriate handler
                    if handler_type == "pdf":
                        handler = self.pdf_handler
                    else:
                        handler = self.text_handler

                    # Encrypt the file
                    encrypted_path = os.path.join(output_path, item + handler.file_extension)

                    # Call encrypt_file with the appropriate parameters
                    # Note: TextFileHandler.encrypt_file doesn't accept key_id parameter
                    if password:
                        result = handler.encrypt_file(
                            input_path=item_path,
                            output_path=encrypted_path,
                            password=password,
                            algorithm=algorithm
                        )
                    else:
                        result = handler.encrypt_file(
                            input_path=item_path,
                            output_path=encrypted_path,
                            key=key,
                            algorithm=algorithm
                        )

                    # Add file metadata
                    file_metadata = {
                        "original_path": os.path.relpath(item_path, input_path),
                        "encrypted_path": os.path.relpath(encrypted_path, output_path),
                        "size": os.path.getsize(item_path),
                        "encrypted_size": os.path.getsize(encrypted_path),
                        "key_id": result.get("key_id"),
                        "algorithm": result.get("algorithm")
                    }

                    dir_metadata["files"].append(file_metadata)

                    # Update progress
                    processed_files += 1
                    if progress_callback:
                        progress_callback(processed_files, total_files, item_path)

                except ValueError as e:
                    # Check if this is a critical error (like wrong password or key)
                    if "wrong password" in str(e).lower() or "decryption failed" in str(e).lower() or "invalid key" in str(e).lower():
                        error_message = f"Critical error encrypting file {item_path}: {str(e)}"
                        raise ValueError(error_message)
                    else:
                        # Log the error but continue with other files
                        print(f"Error encrypting file {item_path}: {str(e)}")

                except Exception as e:
                    # Log the error but continue with other files
                    print(f"Error encrypting file {item_path}: {str(e)}")

            elif os.path.isdir(item_path):
                # Create subdirectory in output
                subdir_output = os.path.join(output_path, item)
                os.makedirs(subdir_output, exist_ok=True)

                # Initialize subdirectory metadata
                subdir_metadata = {
                    "original_path": os.path.relpath(item_path, input_path),
                    "encrypted_path": os.path.relpath(subdir_output, output_path),
                    "files": [],
                    "directories": []
                }

                # Recursively encrypt the subdirectory
                processed_files = self._encrypt_directory_recursive(
                    input_path=item_path,
                    output_path=subdir_output,
                    key=key,
                    key_id=key_id,
                    password=password,
                    algorithm=algorithm,
                    dir_metadata=subdir_metadata,
                    progress_callback=progress_callback,
                    total_files=total_files,
                    processed_files=processed_files
                )

                # Add subdirectory metadata
                dir_metadata["directories"].append(subdir_metadata)

        return processed_files

    def decrypt_directory(self,
                         input_path: str,
                         output_path: Optional[str] = None,
                         key: Optional[bytes] = None,
                         key_id: Optional[str] = None,
                         password: Optional[str] = None,
                         progress_callback: Optional[Callable[[int, int, str], None]] = None) -> Dict[str, Any]:
        """
        Decrypt a directory that was encrypted with encrypt_directory.

        Args:
            input_path: Path to the encrypted directory
            output_path: Path to save the decrypted directory (if None, uses input_path without extension)
            key: The decryption key (if None, uses key_id to get key)
            key_id: The ID of the key to use (if None and key not provided, tries to get from metadata)
            password: Password to use for decryption (if provided, key and key_id are ignored)
            progress_callback: Optional callback function to report progress

        Returns:
            A dictionary containing decryption metadata and statistics

        Raises:
            FileNotFoundError: If the input directory doesn't exist
            ValueError: If the key can't be determined or the directory wasn't encrypted with this system
        """
        # Validate input path
        input_path = os.path.abspath(input_path)
        if not os.path.isdir(input_path):
            raise FileNotFoundError(f"Directory not found: {input_path}")

        # Determine output path if not provided
        if output_path is None:
            if input_path.endswith(self.file_extension):
                output_path = input_path[:-len(self.file_extension)]
            else:
                output_path = input_path + ".decrypted"
        output_path = os.path.abspath(output_path)

        # Create output directory if it doesn't exist
        os.makedirs(output_path, exist_ok=True)

        # Load metadata
        metadata_path = os.path.join(input_path, ".metadata.json")
        if not os.path.exists(metadata_path):
            raise ValueError(f"Metadata file not found: {metadata_path}. The directory may not have been encrypted with this system.")

        with open(metadata_path, 'r') as f:
            try:
                dir_metadata = json.load(f)
            except json.JSONDecodeError:
                raise ValueError(f"Invalid metadata file: {metadata_path}")

        # Validate metadata
        if "directory_structure" not in dir_metadata:
            raise ValueError(f"Invalid metadata file: {metadata_path}. Missing directory_structure.")

        # Determine the key to use
        decryption_key = None
        if not password:
            if key:
                # Use the provided key
                decryption_key = key
            elif key_id:
                # Get the key from the key manager
                decryption_key = self.key_manager.get_key(key_id)
                if decryption_key is None:
                    raise ValueError(f"Key not found: {key_id}")

        # Count total files for progress reporting
        total_files = len(dir_metadata["directory_structure"]["files"])
        for subdir in dir_metadata["directory_structure"]["directories"]:
            total_files += self._count_files_in_metadata(subdir)

        processed_files = 0

        # Start decryption
        start_time = time.time()

        # Decrypt the directory recursively
        processed_files = self._decrypt_directory_recursive(
            input_path=input_path,
            output_path=output_path,
            key=decryption_key,
            key_id=key_id,
            password=password,
            dir_metadata=dir_metadata["directory_structure"],
            progress_callback=progress_callback,
            total_files=total_files,
            processed_files=processed_files
        )

        return {
            "output_path": output_path,
            "total_files": total_files,
            "processed_files": processed_files,
            "decryption_time": time.time() - start_time
        }

    def _count_files_in_metadata(self, dir_metadata: Dict[str, Any]) -> int:
        """
        Count the number of files in a directory metadata structure.

        Args:
            dir_metadata: Directory metadata

        Returns:
            Number of files
        """
        count = len(dir_metadata["files"])
        for subdir in dir_metadata["directories"]:
            count += self._count_files_in_metadata(subdir)
        return count

    def _decrypt_directory_recursive(self,
                                    input_path: str,
                                    output_path: str,
                                    key: Optional[bytes],
                                    key_id: Optional[str],
                                    password: Optional[str],
                                    dir_metadata: Dict[str, Any],
                                    progress_callback: Optional[Callable[[int, int, str], None]],
                                    total_files: int,
                                    processed_files: int) -> int:
        """
        Recursively decrypt a directory.

        Args:
            input_path: Path to the encrypted directory
            output_path: Path to save the decrypted directory
            key: The decryption key
            key_id: The ID of the key to use
            password: Password to use for decryption
            dir_metadata: Directory metadata
            progress_callback: Callback function to report progress
            total_files: Total number of files to process
            processed_files: Number of files processed so far

        Returns:
            Number of files processed
        """
        # Process files in the current directory
        for file_metadata in dir_metadata["files"]:
            try:
                # Get file paths
                encrypted_path = os.path.join(input_path, file_metadata["encrypted_path"])
                original_path = os.path.join(output_path, file_metadata["original_path"])

                # Ensure the output directory exists
                os.makedirs(os.path.dirname(original_path), exist_ok=True)

                # Determine the appropriate handler
                if encrypted_path.endswith(self.text_handler.file_extension):
                    handler = self.text_handler
                elif encrypted_path.endswith(self.pdf_handler.file_extension):
                    handler = self.pdf_handler
                else:
                    # Default to text handler
                    handler = self.text_handler

                # Decrypt the file
                file_key_id = file_metadata.get("key_id", key_id)

                # Call decrypt_file with the appropriate parameters
                # Note: TextFileHandler.decrypt_file doesn't accept key_id parameter
                if password:
                    result = handler.decrypt_file(
                        input_path=encrypted_path,
                        output_path=original_path,
                        password=password
                    )
                else:
                    result = handler.decrypt_file(
                        input_path=encrypted_path,
                        output_path=original_path,
                        key=key
                    )

                # Update progress
                processed_files += 1
                if progress_callback:
                    progress_callback(processed_files, total_files, original_path)

            except ValueError as e:
                # Check if this is a critical error (like wrong password or key)
                if "wrong password" in str(e).lower() or "decryption failed" in str(e).lower() or "invalid key" in str(e).lower():
                    error_message = f"Critical error decrypting file {file_metadata.get('encrypted_path')}: {str(e)}"
                    raise ValueError(error_message)
                else:
                    # Log the error but continue with other files
                    print(f"Error decrypting file {file_metadata.get('encrypted_path')}: {str(e)}")

            except Exception as e:
                # Log the error but continue with other files
                print(f"Error decrypting file {file_metadata.get('encrypted_path')}: {str(e)}")

        # Process subdirectories
        for subdir_metadata in dir_metadata["directories"]:
            try:
                # Get directory paths
                encrypted_subdir = os.path.join(input_path, subdir_metadata["encrypted_path"])
                original_subdir = os.path.join(output_path, subdir_metadata["original_path"])

                # Ensure the output directory exists
                os.makedirs(original_subdir, exist_ok=True)

                # Recursively decrypt the subdirectory
                processed_files = self._decrypt_directory_recursive(
                    input_path=encrypted_subdir,
                    output_path=original_subdir,
                    key=key,
                    key_id=key_id,
                    password=password,
                    dir_metadata=subdir_metadata,
                    progress_callback=progress_callback,
                    total_files=total_files,
                    processed_files=processed_files
                )

            except Exception as e:
                # Log the error but continue with other directories
                print(f"Error decrypting directory {subdir_metadata.get('encrypted_path')}: {str(e)}")

        return processed_files
