"""
Command Line Interface

This module provides a command-line interface for the cryptography system.
"""

import os
import sys
import time
import datetime
import argparse
import getpass
from typing import Dict, Any, List, Optional

from ..core.key_management import KeyManager
from ..core.encryption import EncryptionEngine
from ..core.signatures import SignatureEngine
from ..file_handlers.text_handler import TextFileHandler
from ..file_handlers.pdf_handler import PDFHandler
from ..file_handlers.pdf_section_handler import PDFSectionHandler
from ..file_handlers.directory_handler import DirectoryHandler
from ..utils.file_utils import get_appropriate_handler

# PDF section handlers are implemented directly in this file


class CLI:
    """
    Command-line interface for the cryptography system.
    """

    def __init__(self):
        """Initialize the CLI."""
        self.key_manager = None
        self.encryption_engine = EncryptionEngine()
        self.signature_engine = SignatureEngine()
        self.text_handler = None
        self.pdf_handler = None
        self.pdf_section_handler = None
        self.directory_handler = None
        self.storage_initialized = False

    def parse_args(self, args: List[str]) -> argparse.Namespace:
        """
        Parse command-line arguments.

        Args:
            args: Command-line arguments

        Returns:
            Parsed arguments
        """
        parser = argparse.ArgumentParser(
            description='Secure Cryptography System',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  # Encrypt a file
  python -m src.ui.cli encrypt myfile.txt

  # Decrypt a file
  python -m src.ui.cli decrypt myfile.txt.encrypted

  # Encrypt a PDF file
  python -m src.ui.cli encrypt --type pdf document.pdf

  # Generate a key pair for signatures
  python -m src.ui.cli genkey --output mykey

  # Sign a file
  python -m src.ui.cli sign --key mykey.private myfile.txt

  # Verify a signature
  python -m src.ui.cli verify --key mykey.public myfile.txt myfile.txt.sig

  # Initialize key storage
  python -m src.ui.cli init-storage

  # List stored keys
  python -m src.ui.cli list-keys
'''
        )

        subparsers = parser.add_subparsers(dest='command', help='Command to execute')

        # Encrypt command
        encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
        encrypt_parser.add_argument('file', help='File to encrypt')
        encrypt_parser.add_argument('--output', '-o', help='Output file')
        encrypt_parser.add_argument('--type', '-t', choices=['auto', 'text', 'pdf'],
                                   default='auto', help='File type')
        encrypt_parser.add_argument('--algorithm', '-a',
                                   choices=['AES-GCM', 'ChaCha20-Poly1305'],
                                   default='AES-GCM', help='Encryption algorithm')
        encrypt_parser.add_argument('--password', '-p', action='store_true',
                                   help='Use a password instead of generating a key')

        # Decrypt command
        decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
        decrypt_parser.add_argument('file', help='File to decrypt')
        decrypt_parser.add_argument('--output', '-o', help='Output file')
        decrypt_parser.add_argument('--type', '-t', choices=['auto', 'text', 'pdf'],
                                   default='auto', help='File type')
        decrypt_parser.add_argument('--password', '-p', action='store_true',
                                   help='Use a password for decryption')

        # Generate key command
        genkey_parser = subparsers.add_parser('genkey', help='Generate a key pair')
        genkey_parser.add_argument('--output', '-o', required=True,
                                  help='Output file prefix for key pair')
        genkey_parser.add_argument('--algorithm', '-a',
                                  choices=['RSA-PSS', 'RSA-PKCS1v15', 'DILITHIUM2', 'DILITHIUM3', 'DILITHIUM5', 'KYBER512', 'KYBER768', 'KYBER1024'],
                                  default='RSA-PSS', help='Signature or encryption algorithm')
        genkey_parser.add_argument('--key-size', '-s', type=int, default=3072,
                                  help='Key size in bits (for RSA/ECC only)')
        genkey_parser.add_argument('--post-quantum', '-pq', action='store_true',
                                  help='Generate a post-quantum key pair')

        # Sign command
        sign_parser = subparsers.add_parser('sign', help='Sign a file')
        sign_parser.add_argument('file', help='File to sign')
        sign_parser.add_argument('--key', '-k', required=True,
                                help='Private key file')
        sign_parser.add_argument('--output', '-o',
                                help='Output signature file')
        sign_parser.add_argument('--algorithm', '-a',
                                choices=['RSA-PSS', 'RSA-PKCS1v15'],
                                default='RSA-PSS', help='Signature algorithm')

        # Verify command
        verify_parser = subparsers.add_parser('verify', help='Verify a signature')
        verify_parser.add_argument('file', help='File that was signed')
        verify_parser.add_argument('signature', help='Signature file')
        verify_parser.add_argument('--key', '-k', required=True,
                                  help='Public key file')
        verify_parser.add_argument('--algorithm', '-a',
                                  choices=['RSA-PSS', 'RSA-PKCS1v15'],
                                  help='Signature algorithm (must match the algorithm used for signing)')

        # Initialize storage command
        init_storage_parser = subparsers.add_parser('init-storage', help='Initialize key storage')
        init_storage_parser.add_argument('--force', '-f', action='store_true',
                                      help='Force reinitialization if storage already exists')

        # X.509 certificate commands
        # Generate certificate command
        cert_parser = subparsers.add_parser('cert', help='X.509 certificate operations')
        cert_subparsers = cert_parser.add_subparsers(dest='cert_command', help='Certificate command')

        # Generate self-signed certificate
        gen_cert_parser = cert_subparsers.add_parser('generate', help='Generate a self-signed certificate')
        gen_cert_parser.add_argument('--key', '-k', required=True,
                                   help='Private key ID or file to use for signing')
        gen_cert_parser.add_argument('--key-file', '-kf', action='store_true',
                                   help='Indicates that --key is a file path, not a key ID')
        gen_cert_parser.add_argument('--common-name', '-cn', required=True,
                                   help='Common Name (CN) for the certificate')
        gen_cert_parser.add_argument('--organization', '-o',
                                   help='Organization (O) for the certificate')
        gen_cert_parser.add_argument('--country', '-c',
                                   help='Country (C) for the certificate')
        gen_cert_parser.add_argument('--state', '-st',
                                   help='State/Province (ST) for the certificate')
        gen_cert_parser.add_argument('--locality', '-l',
                                   help='Locality (L) for the certificate')
        gen_cert_parser.add_argument('--valid-days', '-d', type=int, default=365,
                                   help='Validity period in days')
        gen_cert_parser.add_argument('--dns-names', '-dns', nargs='+',
                                   help='DNS names for Subject Alternative Name')
        gen_cert_parser.add_argument('--ip-addresses', '-ip', nargs='+',
                                   help='IP addresses for Subject Alternative Name')
        gen_cert_parser.add_argument('--output', '-out',
                                   help='Output file for the certificate')

        # Create CSR
        csr_parser = cert_subparsers.add_parser('csr', help='Create a Certificate Signing Request')
        csr_parser.add_argument('--key', '-k', required=True,
                              help='Private key ID to use for signing')
        csr_parser.add_argument('--common-name', '-cn', required=True,
                              help='Common Name (CN) for the certificate')
        csr_parser.add_argument('--organization', '-o',
                              help='Organization (O) for the certificate')
        csr_parser.add_argument('--country', '-c',
                              help='Country (C) for the certificate')
        csr_parser.add_argument('--state', '-st',
                              help='State/Province (ST) for the certificate')
        csr_parser.add_argument('--locality', '-l',
                              help='Locality (L) for the certificate')
        csr_parser.add_argument('--dns-names', '-dns', nargs='+',
                              help='DNS names for Subject Alternative Name')
        csr_parser.add_argument('--ip-addresses', '-ip', nargs='+',
                              help='IP addresses for Subject Alternative Name')
        csr_parser.add_argument('--output', '-out', required=True,
                              help='Output file for the CSR')

        # Import certificate
        import_cert_parser = cert_subparsers.add_parser('import', help='Import a certificate')
        import_cert_parser.add_argument('--file', '-f', required=True,
                                     help='Certificate file to import')
        import_cert_parser.add_argument('--key-id', '-k',
                                     help='Key ID to associate with the certificate')

        # Verify certificate
        verify_cert_parser = cert_subparsers.add_parser('verify', help='Verify a certificate')
        verify_cert_parser.add_argument('--cert', '-c', required=True,
                                     help='Certificate ID to verify')
        verify_cert_parser.add_argument('--trusted', '-t', nargs='+', required=True,
                                     help='Trusted certificate IDs')

        # List keys command
        list_keys_parser = subparsers.add_parser('list-keys', help='List stored keys')

        # Change master password command
        change_password_parser = subparsers.add_parser('change-password',
                                                    help='Change master password for key storage')

        # Encrypt directory command
        encrypt_dir_parser = subparsers.add_parser('encrypt-dir',
                                                help='Encrypt a directory recursively')
        encrypt_dir_parser.add_argument('input', help='Directory to encrypt')
        encrypt_dir_parser.add_argument('--output', '-o', help='Output directory')
        encrypt_dir_parser.add_argument('--key', '-k', help='Key file to use')
        encrypt_dir_parser.add_argument('--password', action='store_true',
                                      help='Use password-based encryption')
        encrypt_dir_parser.add_argument('--algorithm', '-a',
                                      choices=['AES-GCM', 'ChaCha20-Poly1305'],
                                      default='AES-GCM',
                                      help='Encryption algorithm to use')

        # Decrypt directory command
        decrypt_dir_parser = subparsers.add_parser('decrypt-dir',
                                                help='Decrypt a directory recursively')
        decrypt_dir_parser.add_argument('input', help='Directory to decrypt')
        decrypt_dir_parser.add_argument('--output', '-o', help='Output directory')
        decrypt_dir_parser.add_argument('--key', '-k', help='Key file to use')
        decrypt_dir_parser.add_argument('--password', action='store_true',
                                      help='Use password-based decryption')

        # Encrypt PDF sections command
        encrypt_pdf_sections_parser = subparsers.add_parser('encrypt-pdf-sections',
                                                          help='Encrypt specific sections of a PDF file')
        encrypt_pdf_sections_parser.add_argument('file', help='PDF file to encrypt')
        encrypt_pdf_sections_parser.add_argument('--output', '-o', help='Output file')
        encrypt_pdf_sections_parser.add_argument('--pages', '-p', required=True,
                                               help='Pages to encrypt (e.g., "1,3-5,7")')
        encrypt_pdf_sections_parser.add_argument('--key', '-k', help='Key file to use')
        encrypt_pdf_sections_parser.add_argument('--password', action='store_true',
                                               help='Use password-based encryption')
        encrypt_pdf_sections_parser.add_argument('--algorithm', '-a',
                                               choices=['AES-GCM', 'ChaCha20-Poly1305'],
                                               default='AES-GCM',
                                               help='Encryption algorithm')

        # Decrypt PDF sections command
        decrypt_pdf_sections_parser = subparsers.add_parser('decrypt-pdf-sections',
                                                          help='Decrypt specific sections of a PDF file')
        decrypt_pdf_sections_parser.add_argument('file', help='Encrypted PDF file')
        decrypt_pdf_sections_parser.add_argument('--output', '-o', help='Output file')
        decrypt_pdf_sections_parser.add_argument('--key', '-k', help='Key file to use')
        decrypt_pdf_sections_parser.add_argument('--password', action='store_true',
                                               help='Use password-based decryption')

        return parser.parse_args(args)

    def run(self, args: Optional[List[str]] = None) -> int:
        """
        Run the CLI with the given arguments.

        Args:
            args: Command-line arguments (if None, uses sys.argv[1:])

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        if args is None:
            args = sys.argv[1:]

        parsed_args = self.parse_args(args)

        if not parsed_args.command:
            print("Error: No command specified")
            return 1

        try:
            if parsed_args.command == 'encrypt':
                return self.handle_encrypt(parsed_args)
            elif parsed_args.command == 'decrypt':
                return self.handle_decrypt(parsed_args)
            elif parsed_args.command == 'genkey':
                return self.handle_genkey(parsed_args)
            elif parsed_args.command == 'sign':
                return self.handle_sign(parsed_args)
            elif parsed_args.command == 'verify':
                return self.handle_verify(parsed_args)
            elif parsed_args.command == 'init-storage':
                return self.handle_init_storage(parsed_args)
            elif parsed_args.command == 'list-keys':
                return self.handle_list_keys(parsed_args)
            elif parsed_args.command == 'change-password':
                return self.handle_change_password(parsed_args)
            elif parsed_args.command == 'encrypt-pdf-sections':
                return self.handle_encrypt_pdf_sections(parsed_args)
            elif parsed_args.command == 'decrypt-pdf-sections':
                return self.handle_decrypt_pdf_sections(parsed_args)
            elif parsed_args.command == 'encrypt-dir':
                return self.handle_encrypt_dir(parsed_args)
            elif parsed_args.command == 'decrypt-dir':
                return self.handle_decrypt_dir(parsed_args)
            elif parsed_args.command == 'cert':
                return self.handle_cert(parsed_args)
            else:
                print(f"Error: Unknown command: {parsed_args.command}")
                return 1
        except Exception as e:
            print(f"Error: {str(e)}")
            return 1

    def _initialize_key_manager(self) -> bool:
        """
        Initialize the key manager with persistent storage if not already initialized.

        Returns:
            True if successful, False otherwise
        """
        if self.storage_initialized:
            return True

        # Check if key storage exists
        storage_path = os.path.join(os.path.expanduser("~"), ".secure_crypto", "key_storage.dat")
        storage_exists = os.path.exists(storage_path)

        if storage_exists:
            # Ask for master password
            master_password = getpass.getpass("Enter master password for key storage: ")

            # Initialize key manager with existing storage
            self.key_manager = KeyManager(storage_path, master_password)
            if not self.key_manager.persistent_storage:
                print("Error: Failed to unlock key storage. Check your password.")
                return False
        else:
            print("Key storage not initialized. Use 'init-storage' command first.")
            return False

        # Initialize handlers
        self.text_handler = TextFileHandler(self.key_manager, self.encryption_engine)
        self.pdf_handler = PDFHandler(self.key_manager, self.encryption_engine)
        self.pdf_section_handler = PDFSectionHandler(self.key_manager, self.encryption_engine)
        self.directory_handler = DirectoryHandler(self.key_manager, self.encryption_engine)

        self.storage_initialized = True
        return True

    def handle_encrypt(self, args: argparse.Namespace) -> int:
        """
        Handle the encrypt command.

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

        # Determine file type
        file_type = args.type
        if file_type == 'auto':
            file_type, _ = get_appropriate_handler(args.file)

        # Get the appropriate handler
        if file_type == 'pdf':
            handler = self.pdf_handler
        else:
            handler = self.text_handler

        # Get the key
        key = None
        if args.password:
            password = getpass.getpass("Enter encryption password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Error: Passwords do not match")
                return 1

            # We no longer need to derive the key here, as it will be done in the handler
            # with the salt stored in the file metadata

        # Encrypt the file
        result = handler.encrypt_file(
            input_path=args.file,
            output_path=args.output,
            key=key if not args.password else None,
            password=password if args.password else None,
            algorithm=args.algorithm
        )

        print(f"File encrypted successfully: {result['output_path']}")
        if result.get('key_id'):
            print(f"Key ID: {result['key_id']}")
            print("Keep this Key ID for decryption!")

        return 0

    def handle_decrypt(self, args: argparse.Namespace) -> int:
        """
        Handle the decrypt command.

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

        # Determine file type
        file_type = args.type
        if file_type == 'auto':
            file_type, _ = get_appropriate_handler(args.file)

        # Get the appropriate handler
        if file_type == 'pdf':
            handler = self.pdf_handler
        else:
            handler = self.text_handler

        # Get the key
        key = None
        key_id = None
        if args.password:
            password = getpass.getpass("Enter decryption password: ")
            # Salt will be extracted from file metadata automatically
        else:
            key_id = input("Enter the Key ID: ")

        # Decrypt the file
        result = handler.decrypt_file(
            input_path=args.file,
            output_path=args.output,
            key=key,
            key_id=key_id,
            password=password if args.password else None
        )

        print(f"File decrypted successfully: {result['output_path']}")

        return 0

    def handle_genkey(self, args: argparse.Namespace) -> int:
        """
        Handle the genkey command.

        Args:
            args: Parsed arguments

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        # Check if this is a post-quantum algorithm
        is_pq_algorithm = args.algorithm in ['DILITHIUM2', 'DILITHIUM3', 'DILITHIUM5', 'KYBER512', 'KYBER768', 'KYBER1024']

        if is_pq_algorithm or args.post_quantum:
            # Initialize key manager if not already initialized
            if not self._initialize_key_manager():
                return 1

            try:
                # Generate post-quantum key pair
                public_key, private_key = self.key_manager.generate_asymmetric_keypair(algorithm=args.algorithm)

                # Save the private key
                private_key_path = f"{args.output}.private"
                with open(private_key_path, 'wb') as f:
                    f.write(private_key)

                # Save the public key
                public_key_path = f"{args.output}.public"
                with open(public_key_path, 'wb') as f:
                    f.write(public_key)

                print(f"Post-quantum key pair ({args.algorithm}) generated successfully:")
                print(f"  Private key: {private_key_path}")
                print(f"  Public key: {public_key_path}")
                return 0
            except ValueError as e:
                print(f"Error generating post-quantum key pair: {str(e)}")
                return 1
        else:
            # Generate the key pair using the signature engine
            key_pair = self.signature_engine.generate_key_pair(
                algorithm=args.algorithm,
                key_size=args.key_size
            )

            # Save the private key
            private_key_path = f"{args.output}.private"
            with open(private_key_path, 'wb') as f:
                f.write(key_pair['private_pem'])

            # Save the public key
            public_key_path = f"{args.output}.public"
            with open(public_key_path, 'wb') as f:
                f.write(key_pair['public_pem'])

            print(f"Key pair generated successfully:")
            print(f"  Private key: {private_key_path}")
            print(f"  Public key: {public_key_path}")

            return 0

    def handle_sign(self, args: argparse.Namespace) -> int:
        """
        Handle the sign command.

        Args:
            args: Parsed arguments

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        # Read the private key
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        with open(args.key, 'rb') as f:
            private_key_data = f.read()
            private_key = load_pem_private_key(
                private_key_data,
                password=None
            )

        # Read the file to sign
        with open(args.file, 'rb') as f:
            file_data = f.read()

        # Sign the file
        signature_result = self.signature_engine.sign(
            data=file_data,
            private_key=private_key,
            algorithm=args.algorithm
        )

        # Determine the output path
        if args.output:
            output_path = args.output
        else:
            output_path = f"{args.file}.sig"

        # Save the signature
        with open(output_path, 'wb') as f:
            f.write(signature_result['signature'])

        print(f"File signed successfully: {output_path}")

        return 0

    def handle_verify(self, args: argparse.Namespace) -> int:
        """
        Handle the verify command.

        Args:
            args: Parsed arguments

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        # Read the public key
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        with open(args.key, 'rb') as f:
            public_key_data = f.read()
            public_key = load_pem_public_key(public_key_data)

        # Read the file that was signed
        with open(args.file, 'rb') as f:
            file_data = f.read()

        # Read the signature
        with open(args.signature, 'rb') as f:
            signature = f.read()

        # Verify the signature
        # Try to determine the algorithm from the command line arguments
        # If not specified, use the same algorithm that was used for signing
        if hasattr(args, 'algorithm') and args.algorithm:
            algorithm = args.algorithm
        else:
            # Default to RSA-PSS if not specified
            algorithm = 'RSA-PSS'

        signature_result = {
            'algorithm': algorithm,
            'signature': signature
        }

        is_valid = self.signature_engine.verify(
            data=file_data,
            signature_result=signature_result,
            public_key=public_key
        )

        if is_valid:
            print("Signature is valid")
            return 0
        else:
            print("Signature is invalid")
            return 1


    def handle_init_storage(self, args: argparse.Namespace) -> int:
        """
        Handle the init-storage command.

        Args:
            args: Parsed arguments

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        # Check if storage already exists
        storage_path = os.path.join(os.path.expanduser("~"), ".secure_crypto", "key_storage.dat")
        if os.path.exists(storage_path) and not args.force:
            print(f"Key storage already exists at {storage_path}")
            print("Use --force to reinitialize (this will erase all stored keys)")
            return 1

        # Get master password
        while True:
            master_password = getpass.getpass("Enter new master password: ")
            if len(master_password) < 8:
                print("Password must be at least 8 characters long")
                continue

            confirm_password = getpass.getpass("Confirm master password: ")
            if master_password != confirm_password:
                print("Passwords do not match")
                continue

            break

        # Initialize key manager with new storage
        self.key_manager = KeyManager(storage_path)
        if not self.key_manager.initialize_storage(master_password):
            print("Failed to initialize key storage")
            return 1

        # Initialize handlers
        self.text_handler = TextFileHandler(self.key_manager, self.encryption_engine)
        self.pdf_handler = PDFHandler(self.key_manager, self.encryption_engine)
        self.storage_initialized = True

        print(f"Key storage initialized at {storage_path}")
        print("Remember your master password! There is no way to recover it if lost.")
        return 0

    def handle_list_keys(self, args: argparse.Namespace) -> int:
        """
        Handle the list-keys command.

        Args:
            args: Parsed arguments

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        # Initialize key manager
        if not self._initialize_key_manager():
            return 1

        # Get list of keys
        keys = self.key_manager.list_keys()

        if not keys:
            print("No keys found in storage")
            return 0

        # Print keys
        print(f"Found {len(keys)} keys in storage:")
        print("-" * 80)
        for key in keys:
            print(f"ID: {key['id']}")
            print(f"Algorithm: {key['algorithm']}")
            print(f"Key Size: {key['key_size']} bits")
            print(f"Created: {time.ctime(key['created'])}")
            print(f"Purpose: {key['purpose']}")
            print("-" * 80)

        return 0

    def handle_change_password(self, args: argparse.Namespace) -> int:
        """
        Handle the change-password command.

        Args:
            args: Parsed arguments

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        # Initialize key manager
        if not self._initialize_key_manager():
            return 1

        # Get current password (already verified in _initialize_key_manager)
        current_password = getpass.getpass("Enter current master password: ")

        # Get new password
        while True:
            new_password = getpass.getpass("Enter new master password: ")
            if len(new_password) < 8:
                print("Password must be at least 8 characters long")
                continue

            confirm_password = getpass.getpass("Confirm new master password: ")
            if new_password != confirm_password:
                print("Passwords do not match")
                continue

            break

        # Change password
        if not self.key_manager.change_master_password(current_password, new_password):
            print("Failed to change master password. Check your current password.")
            return 1

        print("Master password changed successfully")
        return 0

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

    def handle_encrypt_dir(self, args: argparse.Namespace) -> int:
        """
        Handle the encrypt-dir command.

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
            self.directory_handler = DirectoryHandler(self.key_manager, self.encryption_engine)

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

        # Define progress callback
        def progress_callback(processed, total, current_file):
            percent = (processed / total) * 100 if total > 0 else 0
            print(f"Progress: {processed}/{total} files ({percent:.1f}%) - {current_file}", end='\r')

        # Encrypt the directory
        try:
            result = self.directory_handler.encrypt_directory(
                input_path=args.input,
                output_path=args.output,
                key=key,
                key_id=key_id,
                password=password,
                algorithm=args.algorithm,
                progress_callback=progress_callback
            )

            print("\nDirectory encrypted successfully.")
            print(f"Output directory: {result['output_path']}")
            print(f"Metadata file: {result['metadata_path']}")
            print(f"Total files: {result['total_files']}")
            print(f"Processed files: {result['processed_files']}")
            print(f"Encryption time: {result['encryption_time']:.2f} seconds")

            if result.get('key_id'):
                print(f"Key ID: {result['key_id']}")
                print("Keep this Key ID for decryption!")

            return 0
        except Exception as e:
            print(f"\nError encrypting directory: {str(e)}")
            return 1

    def handle_decrypt_dir(self, args: argparse.Namespace) -> int:
        """
        Handle the decrypt-dir command.

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
            self.directory_handler = DirectoryHandler(self.key_manager, self.encryption_engine)

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

        # Define progress callback
        def progress_callback(processed, total, current_file):
            percent = (processed / total) * 100 if total > 0 else 0
            print(f"Progress: {processed}/{total} files ({percent:.1f}%) - {current_file}", end='\r')

        # Decrypt the directory
        try:
            result = self.directory_handler.decrypt_directory(
                input_path=args.input,
                output_path=args.output,
                key=key,
                key_id=key_id,
                password=password,
                progress_callback=progress_callback
            )

            print("\nDirectory decrypted successfully.")
            print(f"Output directory: {result['output_path']}")
            print(f"Total files: {result['total_files']}")
            print(f"Processed files: {result['processed_files']}")
            print(f"Decryption time: {result['decryption_time']:.2f} seconds")

            return 0
        except Exception as e:
            print(f"\nError decrypting directory: {str(e)}")
            return 1

    def handle_cert(self, args: argparse.Namespace) -> int:
        """
        Handle the cert command and its subcommands.

        Args:
            args: Parsed arguments

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        # Initialize key manager
        if not self._initialize_key_manager():
            return 1

        # Check if X.509 support is available
        if not hasattr(self.key_manager, 'x509_manager') or not self.key_manager.x509_manager:
            print("Error: X.509 certificate support is not available")
            return 1

        # Handle subcommands
        if args.cert_command == 'generate':
            return self.handle_cert_generate(args)
        elif args.cert_command == 'csr':
            return self.handle_cert_csr(args)
        elif args.cert_command == 'import':
            return self.handle_cert_import(args)
        elif args.cert_command == 'verify':
            return self.handle_cert_verify(args)
        else:
            print(f"Error: Unknown certificate command: {args.cert_command}")
            return 1

    def handle_cert_generate(self, args: argparse.Namespace) -> int:
        """
        Handle the cert generate command.

        Args:
            args: Parsed arguments

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        try:
            # Check if we're using a key file or key ID
            if args.key_file:
                # Read the private key from file
                with open(args.key, 'rb') as f:
                    private_key_data = f.read()

                # Import the private key to the key manager
                from cryptography.hazmat.primitives.serialization import load_pem_private_key
                from cryptography.hazmat.backends import default_backend

                # Load the private key
                private_key = load_pem_private_key(
                    private_key_data,
                    password=None,
                    backend=default_backend()
                )

                # Generate the certificate directly
                certificate = self.key_manager.x509_manager.generate_self_signed_certificate(
                    private_key=private_key,
                    common_name=args.common_name,
                    organization=args.organization,
                    country=args.country,
                    state=args.state,
                    locality=args.locality,
                    valid_days=args.valid_days,
                    dns_names=args.dns_names,
                    ip_addresses=args.ip_addresses
                )

                # Convert to PEM format
                cert_pem = self.key_manager.x509_manager.certificate_to_pem(certificate)

                # Save to file if requested
                if args.output:
                    with open(args.output, 'wb') as f:
                        f.write(cert_pem)
                    print(f"Certificate generated successfully.")
                    print(f"Certificate saved to: {args.output}")
                else:
                    print(f"Certificate generated successfully.")
                    print(f"Certificate not saved (no output file specified).")

                return 0
            else:
                # Use key ID from key manager
                cert_id = self.key_manager.generate_x509_certificate(
                    private_key_id=args.key,
                    common_name=args.common_name,
                    organization=args.organization,
                    country=args.country,
                    state=args.state,
                    locality=args.locality,
                    valid_days=args.valid_days,
                    dns_names=args.dns_names,
                    ip_addresses=args.ip_addresses
                )

                print(f"Certificate generated successfully.")
                print(f"Certificate ID: {cert_id}")

                # Save to file if requested
                if args.output:
                    cert_data = self.key_manager.active_keys[cert_id]['key']
                    with open(args.output, 'wb') as f:
                        f.write(cert_data)
                    print(f"Certificate saved to: {args.output}")

                return 0
        except Exception as e:
            print(f"Error generating certificate: {str(e)}")
            return 1

    def handle_cert_csr(self, args: argparse.Namespace) -> int:
        """
        Handle the cert csr command.

        Args:
            args: Parsed arguments

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        try:
            # Create the CSR
            csr_pem = self.key_manager.create_certificate_signing_request(
                private_key_id=args.key,
                common_name=args.common_name,
                organization=args.organization,
                country=args.country,
                state=args.state,
                locality=args.locality,
                dns_names=args.dns_names,
                ip_addresses=args.ip_addresses
            )

            # Save to file
            with open(args.output, 'wb') as f:
                f.write(csr_pem)

            print(f"Certificate Signing Request (CSR) created successfully.")
            print(f"CSR saved to: {args.output}")

            return 0
        except Exception as e:
            print(f"Error creating CSR: {str(e)}")
            return 1

    def handle_cert_import(self, args: argparse.Namespace) -> int:
        """
        Handle the cert import command.

        Args:
            args: Parsed arguments

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        try:
            # Read the certificate file
            with open(args.file, 'rb') as f:
                cert_data = f.read()

            # Import the certificate
            cert_id = self.key_manager.import_certificate(
                certificate_data=cert_data,
                key_id_base=args.key_id
            )

            print(f"Certificate imported successfully.")
            print(f"Certificate ID: {cert_id}")

            return 0
        except Exception as e:
            print(f"Error importing certificate: {str(e)}")
            return 1

    def handle_cert_verify(self, args: argparse.Namespace) -> int:
        """
        Handle the cert verify command.

        Args:
            args: Parsed arguments

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        try:
            # Verify the certificate
            result = self.key_manager.verify_certificate(
                cert_id=args.cert,
                trusted_cert_ids=args.trusted
            )

            # Display the results
            print(f"Certificate verification results:")
            print(f"Valid: {result['valid']}")
            print(f"Chain valid: {result['chain_valid']}")
            print(f"Expired: {result['expired']}")
            print(f"Not yet valid: {result['not_yet_valid']}")

            # Display subject information
            print("\nSubject:")
            for key, value in result['subject'].items():
                print(f"  {key}: {value}")

            # Display issuer information
            print("\nIssuer:")
            for key, value in result['issuer'].items():
                print(f"  {key}: {value}")

            # Display validity period
            if 'not_valid_before' in result and result['not_valid_before']:
                not_valid_before = datetime.datetime.fromtimestamp(result['not_valid_before'])
                print(f"\nNot valid before: {not_valid_before}")

            if 'not_valid_after' in result and result['not_valid_after']:
                not_valid_after = datetime.datetime.fromtimestamp(result['not_valid_after'])
                print(f"Not valid after: {not_valid_after}")

            return 0 if result['valid'] else 1
        except Exception as e:
            print(f"Error verifying certificate: {str(e)}")
            return 1




if __name__ == '__main__':
    cli = CLI()
    sys.exit(cli.run())
