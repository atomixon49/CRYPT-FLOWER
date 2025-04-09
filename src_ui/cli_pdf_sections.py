"""
Command Line Interface for PDF Section Encryption

This module provides handlers for the PDF section encryption commands.
"""

import os
import argparse
import getpass
from typing import Dict, Any, Optional

def handle_encrypt_pdf_sections(self, args: argparse.Namespace) -> int:
    """
    Handle the encrypt-pdf-sections command.
    
    Args:
        args: Parsed arguments
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Initialize handlers if using key storage (not password-based)
    if not args.password and not self._initialize_key_manager():
        return 1
    
    # If using password and key manager not initialized, create temporary one
    if args.password and not self.storage_initialized:
        self.key_manager = KeyManager()
        self.text_handler = TextFileHandler(self.key_manager, self.encryption_engine)
        self.pdf_handler = PDFHandler(self.key_manager, self.encryption_engine)
        self.pdf_section_handler = PDFSectionHandler(self.key_manager, self.encryption_engine)
    
    # Get the key to use
    key = None
    key_id = None
    password = None
    
    if args.key:
        # Read the key from file
        try:
            with open(args.key, 'rb') as f:
                key = f.read()
        except Exception as e:
            print(f"Error reading key file: {str(e)}")
            return 1
    elif args.password:
        # Get password from user
        password = getpass.getpass("Enter encryption password: ")
    
    # Encrypt the PDF sections
    try:
        result = self.pdf_section_handler.encrypt_pages(
            input_path=args.file,
            output_path=args.output,
            pages=args.pages,
            key=key,
            key_id=key_id,
            password=password,
            algorithm=args.algorithm
        )
        
        print(f"PDF sections encrypted successfully.")
        print(f"Output file: {result['output_path']}")
        print(f"Metadata file: {result['metadata_path']}")
        print(f"Encrypted pages: {result['encrypted_pages']}")
        return 0
    except Exception as e:
        print(f"Error encrypting PDF sections: {str(e)}")
        return 1

def handle_decrypt_pdf_sections(self, args: argparse.Namespace) -> int:
    """
    Handle the decrypt-pdf-sections command.
    
    Args:
        args: Parsed arguments
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Initialize handlers if using key storage (not password-based)
    if not args.password and not self._initialize_key_manager():
        return 1
    
    # If using password and key manager not initialized, create temporary one
    if args.password and not self.storage_initialized:
        self.key_manager = KeyManager()
        self.text_handler = TextFileHandler(self.key_manager, self.encryption_engine)
        self.pdf_handler = PDFHandler(self.key_manager, self.encryption_engine)
        self.pdf_section_handler = PDFSectionHandler(self.key_manager, self.encryption_engine)
    
    # Get the key to use
    key = None
    key_id = None
    password = None
    
    if args.key:
        # Read the key from file
        try:
            with open(args.key, 'rb') as f:
                key = f.read()
        except Exception as e:
            print(f"Error reading key file: {str(e)}")
            return 1
    elif args.password:
        # Get password from user
        password = getpass.getpass("Enter decryption password: ")
    
    # Decrypt the PDF sections
    try:
        result = self.pdf_section_handler.decrypt_pages(
            input_path=args.file,
            output_path=args.output,
            key=key,
            key_id=key_id,
            password=password
        )
        
        print(f"PDF sections decrypted successfully.")
        print(f"Output file: {result['output_path']}")
        print(f"Decrypted pages: {result['decrypted_pages']}")
        return 0
    except Exception as e:
        print(f"Error decrypting PDF sections: {str(e)}")
        return 1
