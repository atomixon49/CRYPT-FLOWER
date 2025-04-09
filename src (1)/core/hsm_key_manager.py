"""
HSM Key Manager Module

This module extends the key management system to support Hardware Security Modules (HSMs)
using the PKCS#11 standard. It provides a bridge between the KeyManager and PKCS11Interface
classes to enable seamless use of HSM-backed keys.
"""

import os
import time
import logging
import binascii
from typing import Dict, Any, Optional, Tuple, List, Union, Callable

from .key_management import KeyManager
from .pkcs11_interface import PKCS11Interface, PKCS11Error, PKCS11_AVAILABLE

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hsm_key_manager")

class HSMKeyManager:
    """
    Manages cryptographic keys stored on Hardware Security Modules (HSMs).

    This class extends the functionality of the KeyManager class to support
    keys stored on HSMs using the PKCS#11 standard. It provides methods for
    generating, using, and managing HSM-backed keys.
    """

    def __init__(self,
                key_manager: KeyManager,
                library_path: Optional[str] = None,
                token_label: Optional[str] = None,
                pin: Optional[str] = None,
                use_post_quantum: bool = True):
        """
        Initialize the HSM key manager.

        Args:
            key_manager: The main KeyManager instance
            library_path: Path to the PKCS#11 library (.so, .dll, .dylib)
            token_label: Label of the token to use (if None, use the first available token)
            pin: PIN for the token (if None, operations requiring authentication will fail)
            use_post_quantum: Whether to enable post-quantum algorithm support

        Raises:
            ValueError: If PKCS#11 support is not available
        """
        self.key_manager = key_manager
        self.pkcs11_interface = None
        self.hsm_keys: Dict[str, Dict[str, Any]] = {}
        self.use_post_quantum = use_post_quantum

        # Initialize PKCS#11 interface if library path is provided
        if library_path:
            self.initialize_pkcs11(library_path, token_label, pin, use_post_quantum)

    def initialize_pkcs11(self,
                         library_path: str,
                         token_label: Optional[str] = None,
                         pin: Optional[str] = None,
                         use_post_quantum: bool = True) -> bool:
        """
        Initialize the PKCS#11 interface.

        Args:
            library_path: Path to the PKCS#11 library (.so, .dll, .dylib)
            token_label: Label of the token to use (if None, use the first available token)
            pin: PIN for the token (if None, operations requiring authentication will fail)
            use_post_quantum: Whether to enable post-quantum algorithm support

        Returns:
            True if initialization was successful, False otherwise

        Raises:
            ValueError: If PKCS#11 support is not available
        """
        if not PKCS11_AVAILABLE:
            raise ValueError("PKCS#11 support is not available. Please install python-pkcs11.")

        try:
            self.pkcs11_interface = PKCS11Interface(library_path, token_label, pin, use_post_quantum)
            logger.info(f"Initialized PKCS#11 interface with library: {library_path}")

            if use_post_quantum and self.pkcs11_interface.use_post_quantum:
                logger.info("Post-quantum cryptography support enabled for HSM")

            # Load existing HSM keys
            self._load_hsm_keys()

            return True
        except PKCS11Error as e:
            logger.error(f"Failed to initialize PKCS#11 interface: {str(e)}")
            self.pkcs11_interface = None
            return False

    def _load_hsm_keys(self) -> None:
        """
        Load existing keys from the HSM.

        This method queries the HSM for all available keys and stores their
        metadata in the hsm_keys dictionary.
        """
        if not self.pkcs11_interface:
            return

        try:
            # List all keys on the HSM
            keys = self.pkcs11_interface.list_keys()

            # Store key metadata
            for key in keys:
                key_id = key.get('id')
                if key_id:
                    # Convert key ID to hex string for consistent handling
                    if isinstance(key_id, bytes):
                        key_id = binascii.hexlify(key_id).decode('ascii')

                    # Store key metadata
                    self.hsm_keys[key_id] = {
                        'label': key.get('label', ''),
                        'type': key.get('type', ''),
                        'class': key.get('class', ''),
                        'algorithm': key.get('algorithm', ''),
                        'size': key.get('size', 0),
                        'hsm_backed': True,
                        'created': key.get('created', time.time())
                    }

            logger.info(f"Loaded {len(self.hsm_keys)} keys from HSM")
        except PKCS11Error as e:
            logger.error(f"Failed to load HSM keys: {str(e)}")

    def generate_key(self,
                    key_type: str,
                    key_size: int,
                    key_label: str,
                    extractable: bool = False,
                    post_quantum: bool = False) -> str:
        """
        Generate a key on the HSM.

        Args:
            key_type: Type of key to generate ('AES', 'RSA', 'EC', 'KYBER', 'DILITHIUM', etc.)
            key_size: Size of the key in bits
            key_label: Label for the key
            extractable: Whether the key can be extracted from the HSM
            post_quantum: Whether to use post-quantum algorithms

        Returns:
            The ID of the generated key

        Raises:
            ValueError: If the PKCS#11 interface is not initialized or key generation fails
        """
        if not self.pkcs11_interface:
            raise ValueError("PKCS#11 interface not initialized")

        try:
            # Generate the key on the HSM
            key_info = self.pkcs11_interface.generate_key(
                key_type=key_type,
                key_size=key_size,
                key_label=key_label,
                extractable=extractable,
                post_quantum=post_quantum
            )

            # Get the key ID
            key_id = key_info.get('id')
            if isinstance(key_id, bytes):
                key_id = binascii.hexlify(key_id).decode('ascii')

            # Store key metadata
            self.hsm_keys[key_id] = {
                'label': key_label,
                'type': key_type,
                'algorithm': key_info.get('algorithm', key_type),
                'size': key_size,
                'hsm_backed': True,
                'created': time.time(),
                'extractable': extractable
            }

            # Register the key with the main key manager
            self._register_with_key_manager(key_id, key_type, key_size, key_label)

            logger.info(f"Generated {key_type} key on HSM with ID: {key_id}")
            return key_id

        except PKCS11Error as e:
            logger.error(f"Failed to generate key on HSM: {str(e)}")
            raise ValueError(f"Failed to generate key on HSM: {str(e)}")

    def _register_with_key_manager(self,
                                  key_id: str,
                                  key_type: str,
                                  key_size: int,
                                  key_label: str) -> None:
        """
        Register an HSM key with the main key manager.

        This method creates a reference to the HSM key in the main key manager,
        allowing it to be used with the rest of the system.

        Args:
            key_id: ID of the HSM key
            key_type: Type of the key
            key_size: Size of the key in bits
            key_label: Label of the key
        """
        # Create a reference key in the main key manager
        hsm_key_id = f"hsm:{key_id}"

        # Determine the purpose based on key type
        if key_type.upper() == 'AES':
            purpose = 'symmetric_encryption'
        elif key_type.upper() in ('RSA', 'EC'):
            purpose = 'asymmetric_encryption'
        else:
            purpose = 'general'

        # Create key metadata
        key_data = {
            'algorithm': key_type,
            'key_size': key_size,
            'created': time.time(),
            'hsm_backed': True,
            'hsm_key_id': key_id,
            'purpose': purpose,
            'label': key_label
        }

        # Add to active keys
        self.key_manager.active_keys[hsm_key_id] = key_data

        # Store in persistent storage if available
        if self.key_manager.persistent_storage and self.key_manager.key_storage:
            self.key_manager.key_storage.add_key(hsm_key_id, key_data)
            self.key_manager.key_storage.save()

    def encrypt(self,
               data: bytes,
               key_id: str,
               algorithm: str,
               params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Encrypt data using an HSM key.

        Args:
            data: Data to encrypt
            key_id: ID of the HSM key to use
            algorithm: Encryption algorithm to use
            params: Additional parameters for the algorithm

        Returns:
            Dictionary with encryption result

        Raises:
            ValueError: If the PKCS#11 interface is not initialized or encryption fails
        """
        if not self.pkcs11_interface:
            raise ValueError("PKCS#11 interface not initialized")

        try:
            # Extract the actual HSM key ID if using a reference
            if key_id.startswith("hsm:"):
                key_data = self.key_manager.active_keys.get(key_id)
                if not key_data:
                    raise ValueError(f"Key not found: {key_id}")
                key_id = key_data.get('hsm_key_id')

            # Encrypt the data on the HSM
            result = self.pkcs11_interface.encrypt(
                data=data,
                key_id=key_id,
                algorithm=algorithm,
                params=params
            )

            return result

        except PKCS11Error as e:
            logger.error(f"Failed to encrypt data with HSM key: {str(e)}")
            raise ValueError(f"Failed to encrypt data with HSM key: {str(e)}")

    def decrypt(self,
               ciphertext: bytes,
               key_id: str,
               algorithm: str,
               params: Optional[Dict[str, Any]] = None) -> bytes:
        """
        Decrypt data using an HSM key.

        Args:
            ciphertext: Data to decrypt
            key_id: ID of the HSM key to use
            algorithm: Decryption algorithm to use
            params: Additional parameters for the algorithm

        Returns:
            Decrypted data

        Raises:
            ValueError: If the PKCS#11 interface is not initialized or decryption fails
        """
        if not self.pkcs11_interface:
            raise ValueError("PKCS#11 interface not initialized")

        try:
            # Extract the actual HSM key ID if using a reference
            if key_id.startswith("hsm:"):
                key_data = self.key_manager.active_keys.get(key_id)
                if not key_data:
                    raise ValueError(f"Key not found: {key_id}")
                key_id = key_data.get('hsm_key_id')

            # Decrypt the data on the HSM
            result = self.pkcs11_interface.decrypt(
                ciphertext=ciphertext,
                key_id=key_id,
                algorithm=algorithm,
                params=params
            )

            return result

        except PKCS11Error as e:
            logger.error(f"Failed to decrypt data with HSM key: {str(e)}")
            raise ValueError(f"Failed to decrypt data with HSM key: {str(e)}")

    def sign(self,
            data: bytes,
            key_id: str,
            algorithm: str,
            params: Optional[Dict[str, Any]] = None) -> bytes:
        """
        Sign data using an HSM key.

        Args:
            data: Data to sign
            key_id: ID of the HSM key to use
            algorithm: Signature algorithm to use
            params: Additional parameters for the algorithm

        Returns:
            Signature

        Raises:
            ValueError: If the PKCS#11 interface is not initialized or signing fails
        """
        if not self.pkcs11_interface:
            raise ValueError("PKCS#11 interface not initialized")

        try:
            # Extract the actual HSM key ID if using a reference
            if key_id.startswith("hsm:"):
                key_data = self.key_manager.active_keys.get(key_id)
                if not key_data:
                    raise ValueError(f"Key not found: {key_id}")
                key_id = key_data.get('hsm_key_id')

            # Sign the data on the HSM
            result = self.pkcs11_interface.sign(
                data=data,
                key_id=key_id,
                algorithm=algorithm,
                params=params
            )

            return result.get('signature')

        except PKCS11Error as e:
            logger.error(f"Failed to sign data with HSM key: {str(e)}")
            raise ValueError(f"Failed to sign data with HSM key: {str(e)}")

    def verify(self,
              data: bytes,
              signature: bytes,
              key_id: str,
              algorithm: str,
              params: Optional[Dict[str, Any]] = None) -> bool:
        """
        Verify a signature using an HSM key.

        Args:
            data: Original data that was signed
            signature: Signature to verify
            key_id: ID of the HSM key to use
            algorithm: Signature algorithm to use
            params: Additional parameters for the algorithm

        Returns:
            True if the signature is valid, False otherwise

        Raises:
            ValueError: If the PKCS#11 interface is not initialized or verification fails
        """
        if not self.pkcs11_interface:
            raise ValueError("PKCS#11 interface not initialized")

        try:
            # Extract the actual HSM key ID if using a reference
            if key_id.startswith("hsm:"):
                key_data = self.key_manager.active_keys.get(key_id)
                if not key_data:
                    raise ValueError(f"Key not found: {key_id}")
                key_id = key_data.get('hsm_key_id')

            # Verify the signature on the HSM
            result = self.pkcs11_interface.verify(
                data=data,
                signature=signature,
                key_id=key_id,
                algorithm=algorithm,
                params=params
            )

            return result

        except PKCS11Error as e:
            logger.error(f"Failed to verify signature with HSM key: {str(e)}")
            raise ValueError(f"Failed to verify signature with HSM key: {str(e)}")

    def list_slots(self) -> List[Dict[str, Any]]:
        """
        List all available HSM slots.

        Returns:
            List of dictionaries with slot information

        Raises:
            ValueError: If the PKCS#11 interface is not initialized
        """
        if not self.pkcs11_interface:
            raise ValueError("PKCS#11 interface not initialized")

        try:
            return self.pkcs11_interface.list_slots()
        except PKCS11Error as e:
            logger.error(f"Failed to list HSM slots: {str(e)}")
            raise ValueError(f"Failed to list HSM slots: {str(e)}")

    def list_keys(self) -> List[Dict[str, Any]]:
        """
        List all keys on the HSM.

        Returns:
            List of dictionaries with key information

        Raises:
            ValueError: If the PKCS#11 interface is not initialized
        """
        if not self.pkcs11_interface:
            raise ValueError("PKCS#11 interface not initialized")

        try:
            return self.pkcs11_interface.list_keys()
        except PKCS11Error as e:
            logger.error(f"Failed to list HSM keys: {str(e)}")
            raise ValueError(f"Failed to list HSM keys: {str(e)}")

    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key from the HSM.

        Args:
            key_id: ID of the key to delete

        Returns:
            True if the key was deleted, False otherwise

        Raises:
            ValueError: If the PKCS#11 interface is not initialized
        """
        if not self.pkcs11_interface:
            raise ValueError("PKCS#11 interface not initialized")

        try:
            # Extract the actual HSM key ID if using a reference
            hsm_ref_id = None
            if key_id.startswith("hsm:"):
                hsm_ref_id = key_id
                key_data = self.key_manager.active_keys.get(key_id)
                if not key_data:
                    raise ValueError(f"Key not found: {key_id}")
                key_id = key_data.get('hsm_key_id')

            # Delete the key from the HSM
            result = self.pkcs11_interface.delete_key(key_id)

            # If successful and we have a reference, delete it from the key manager
            if result and hsm_ref_id:
                self.key_manager.secure_erase(hsm_ref_id)
                if key_id in self.hsm_keys:
                    del self.hsm_keys[key_id]

            return result

        except PKCS11Error as e:
            logger.error(f"Failed to delete HSM key: {str(e)}")
            raise ValueError(f"Failed to delete HSM key: {str(e)}")
