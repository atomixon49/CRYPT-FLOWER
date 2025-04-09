"""
Multi-Recipient Encryption Module

This module provides functionality for encrypting data for multiple recipients,
allowing each recipient to decrypt the data using their own private key.
"""

import os
import json
import base64
import secrets
import logging
from typing import Dict, List, Any, Optional, Union, Tuple

from .encryption import EncryptionEngine
from .key_management import KeyManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("multi_recipient_encryption")

class MultiRecipientEncryption:
    """
    Provides functionality for encrypting data for multiple recipients.
    
    This class implements a hybrid approach where:
    1. Data is encrypted once with a random symmetric key
    2. The symmetric key is encrypted separately for each recipient using their public key
    3. All encrypted keys are stored alongside the encrypted data
    """
    
    def __init__(self, key_manager: KeyManager = None):
        """
        Initialize the multi-recipient encryption module.
        
        Args:
            key_manager: KeyManager instance to use for key operations
        """
        self.encryption_engine = EncryptionEngine()
        self.key_manager = key_manager or KeyManager()
    
    def encrypt(self, 
               data: bytes, 
               recipient_key_ids: List[str], 
               symmetric_algorithm: str = "AES-GCM",
               metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Encrypt data for multiple recipients.
        
        Args:
            data: Data to encrypt
            recipient_key_ids: List of recipient public key IDs
            symmetric_algorithm: Algorithm to use for data encryption
            metadata: Optional metadata to include
        
        Returns:
            Dictionary containing the encrypted data and metadata
        
        Raises:
            ValueError: If any recipient key is invalid or encryption fails
        """
        if not recipient_key_ids:
            raise ValueError("At least one recipient key ID must be provided")
        
        try:
            # Generate a random symmetric key for data encryption
            symmetric_key_size = 256  # Use 256-bit key for AES-GCM
            symmetric_key = secrets.token_bytes(symmetric_key_size // 8)
            
            # Encrypt the data with the symmetric key
            encryption_result = self.encryption_engine.encrypt(
                data=data,
                key=symmetric_key,
                algorithm=symmetric_algorithm
            )
            
            # Encrypt the symmetric key for each recipient
            encrypted_keys = {}
            for key_id in recipient_key_ids:
                # Get the recipient's public key
                public_key = self.key_manager.get_key(key_id)
                if not public_key:
                    raise ValueError(f"Public key not found for recipient: {key_id}")
                
                # Determine the key encryption algorithm based on the key type
                key_info = self.key_manager.get_key_info(key_id)
                key_algorithm = key_info.get('algorithm', '').upper()
                
                if key_algorithm == 'RSA':
                    key_encryption_algorithm = 'RSA-OAEP'
                elif key_algorithm.startswith('EC'):
                    key_encryption_algorithm = 'ECDH-ES+A256KW'
                elif key_algorithm.startswith('KYBER'):
                    key_encryption_algorithm = 'KYBER'
                else:
                    raise ValueError(f"Unsupported key type for recipient: {key_id}")
                
                # Encrypt the symmetric key for this recipient
                encrypted_key_result = self._encrypt_key_for_recipient(
                    symmetric_key=symmetric_key,
                    recipient_key=public_key,
                    recipient_key_id=key_id,
                    algorithm=key_encryption_algorithm
                )
                
                encrypted_keys[key_id] = encrypted_key_result
            
            # Prepare the result
            result = {
                'version': '1.0',
                'type': 'multi_recipient_encrypted',
                'data_encryption': {
                    'algorithm': encryption_result['algorithm'],
                    'ciphertext': base64.b64encode(encryption_result['ciphertext']).decode('ascii'),
                    'nonce': base64.b64encode(encryption_result['nonce']).decode('ascii')
                },
                'recipients': encrypted_keys
            }
            
            # Add tag if present (for authenticated encryption)
            if 'tag' in encryption_result:
                result['data_encryption']['tag'] = base64.b64encode(encryption_result['tag']).decode('ascii')
            
            # Add metadata if provided
            if metadata:
                result['metadata'] = metadata
            
            return result
        
        except Exception as e:
            logger.error(f"Error encrypting data for multiple recipients: {str(e)}")
            raise ValueError(f"Failed to encrypt data for multiple recipients: {str(e)}")
    
    def decrypt(self, 
               encrypted_data: Dict[str, Any], 
               recipient_key_id: str) -> bytes:
        """
        Decrypt data as one of the recipients.
        
        Args:
            encrypted_data: Encrypted data from the encrypt method
            recipient_key_id: Key ID of the recipient trying to decrypt
        
        Returns:
            Decrypted data
        
        Raises:
            ValueError: If the recipient key is invalid or decryption fails
        """
        if not encrypted_data or not isinstance(encrypted_data, dict):
            raise ValueError("Invalid encrypted data format")
        
        if encrypted_data.get('type') != 'multi_recipient_encrypted':
            raise ValueError("Data is not multi-recipient encrypted")
        
        try:
            # Check if the recipient is in the list
            recipients = encrypted_data.get('recipients', {})
            if recipient_key_id not in recipients:
                raise ValueError(f"Recipient {recipient_key_id} is not authorized to decrypt this data")
            
            # Get the recipient's encrypted key
            encrypted_key_data = recipients[recipient_key_id]
            
            # Get the recipient's private key
            private_key_id = self._get_private_key_id(recipient_key_id)
            private_key = self.key_manager.get_key(private_key_id)
            if not private_key:
                raise ValueError(f"Private key not found for recipient: {recipient_key_id}")
            
            # Decrypt the symmetric key
            symmetric_key = self._decrypt_key_for_recipient(
                encrypted_key_data=encrypted_key_data,
                recipient_private_key=private_key,
                algorithm=encrypted_key_data.get('algorithm')
            )
            
            # Get the encrypted data
            data_encryption = encrypted_data.get('data_encryption', {})
            algorithm = data_encryption.get('algorithm')
            ciphertext = base64.b64decode(data_encryption.get('ciphertext', ''))
            nonce = base64.b64decode(data_encryption.get('nonce', ''))
            
            # Prepare the encryption result for decryption
            encryption_result = {
                'algorithm': algorithm,
                'ciphertext': ciphertext,
                'nonce': nonce
            }
            
            # Add tag if present
            if 'tag' in data_encryption:
                encryption_result['tag'] = base64.b64decode(data_encryption.get('tag', ''))
            
            # Decrypt the data
            decrypted_data = self.encryption_engine.decrypt(
                encryption_result=encryption_result,
                key=symmetric_key
            )
            
            return decrypted_data
        
        except Exception as e:
            logger.error(f"Error decrypting data: {str(e)}")
            raise ValueError(f"Failed to decrypt data: {str(e)}")
    
    def add_recipient(self, 
                     encrypted_data: Dict[str, Any], 
                     new_recipient_key_id: str,
                     admin_key_id: str) -> Dict[str, Any]:
        """
        Add a new recipient to already encrypted data.
        
        Args:
            encrypted_data: Encrypted data from the encrypt method
            new_recipient_key_id: Key ID of the new recipient to add
            admin_key_id: Key ID of an existing recipient with permission to add new recipients
        
        Returns:
            Updated encrypted data with the new recipient
        
        Raises:
            ValueError: If the admin key is invalid or adding the recipient fails
        """
        if not encrypted_data or not isinstance(encrypted_data, dict):
            raise ValueError("Invalid encrypted data format")
        
        if encrypted_data.get('type') != 'multi_recipient_encrypted':
            raise ValueError("Data is not multi-recipient encrypted")
        
        try:
            # First decrypt the data using the admin key
            decrypted_data = self.decrypt(encrypted_data, admin_key_id)
            
            # Get the list of current recipients
            current_recipients = list(encrypted_data.get('recipients', {}).keys())
            
            # Add the new recipient
            if new_recipient_key_id not in current_recipients:
                current_recipients.append(new_recipient_key_id)
            
            # Re-encrypt the data for all recipients
            metadata = encrypted_data.get('metadata')
            algorithm = encrypted_data.get('data_encryption', {}).get('algorithm', 'AES-GCM')
            
            return self.encrypt(
                data=decrypted_data,
                recipient_key_ids=current_recipients,
                symmetric_algorithm=algorithm,
                metadata=metadata
            )
        
        except Exception as e:
            logger.error(f"Error adding recipient: {str(e)}")
            raise ValueError(f"Failed to add recipient: {str(e)}")
    
    def remove_recipient(self, 
                        encrypted_data: Dict[str, Any], 
                        recipient_key_id_to_remove: str,
                        admin_key_id: str) -> Dict[str, Any]:
        """
        Remove a recipient from already encrypted data.
        
        Args:
            encrypted_data: Encrypted data from the encrypt method
            recipient_key_id_to_remove: Key ID of the recipient to remove
            admin_key_id: Key ID of an existing recipient with permission to remove recipients
        
        Returns:
            Updated encrypted data without the removed recipient
        
        Raises:
            ValueError: If the admin key is invalid or removing the recipient fails
        """
        if not encrypted_data or not isinstance(encrypted_data, dict):
            raise ValueError("Invalid encrypted data format")
        
        if encrypted_data.get('type') != 'multi_recipient_encrypted':
            raise ValueError("Data is not multi-recipient encrypted")
        
        try:
            # First decrypt the data using the admin key
            decrypted_data = self.decrypt(encrypted_data, admin_key_id)
            
            # Get the list of current recipients
            current_recipients = list(encrypted_data.get('recipients', {}).keys())
            
            # Remove the recipient
            if recipient_key_id_to_remove in current_recipients:
                current_recipients.remove(recipient_key_id_to_remove)
            
            # Make sure we still have at least one recipient
            if not current_recipients:
                raise ValueError("Cannot remove the last recipient")
            
            # Re-encrypt the data for the remaining recipients
            metadata = encrypted_data.get('metadata')
            algorithm = encrypted_data.get('data_encryption', {}).get('algorithm', 'AES-GCM')
            
            return self.encrypt(
                data=decrypted_data,
                recipient_key_ids=current_recipients,
                symmetric_algorithm=algorithm,
                metadata=metadata
            )
        
        except Exception as e:
            logger.error(f"Error removing recipient: {str(e)}")
            raise ValueError(f"Failed to remove recipient: {str(e)}")
    
    def _encrypt_key_for_recipient(self, 
                                  symmetric_key: bytes, 
                                  recipient_key: bytes,
                                  recipient_key_id: str,
                                  algorithm: str) -> Dict[str, Any]:
        """
        Encrypt the symmetric key for a specific recipient.
        
        Args:
            symmetric_key: The symmetric key to encrypt
            recipient_key: The recipient's public key
            recipient_key_id: The recipient's key ID
            algorithm: The algorithm to use for key encryption
        
        Returns:
            Dictionary with the encrypted key and metadata
        
        Raises:
            ValueError: If encryption fails
        """
        try:
            if algorithm == 'RSA-OAEP':
                # Import RSA module
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives.serialization import load_der_public_key
                
                # Load the public key
                public_key = load_der_public_key(recipient_key)
                
                # Encrypt the symmetric key
                encrypted_key = public_key.encrypt(
                    symmetric_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                return {
                    'algorithm': algorithm,
                    'encrypted_key': base64.b64encode(encrypted_key).decode('ascii')
                }
            
            elif algorithm == 'ECDH-ES+A256KW':
                # For ECDH, we would need to perform key agreement and key wrapping
                # This is a simplified implementation
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives.serialization import load_der_public_key
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                from cryptography.hazmat.primitives import hashes
                
                # Load the public key
                public_key = load_der_public_key(recipient_key)
                
                # Generate an ephemeral key pair
                ephemeral_private_key = ec.generate_private_key(
                    curve=ec.SECP256R1()
                )
                ephemeral_public_key = ephemeral_private_key.public_key()
                
                # Perform key agreement
                shared_key = ephemeral_private_key.exchange(
                    ec.ECDH(),
                    public_key
                )
                
                # Derive a wrapping key
                wrapping_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'ECDH-ES+A256KW'
                ).derive(shared_key)
                
                # Encrypt the symmetric key with AES-KW
                from cryptography.hazmat.primitives.keywrap import aes_key_wrap
                wrapped_key = aes_key_wrap(wrapping_key, symmetric_key)
                
                # Serialize the ephemeral public key
                from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
                ephemeral_public_bytes = ephemeral_public_key.public_bytes(
                    encoding=Encoding.DER,
                    format=PublicFormat.SubjectPublicKeyInfo
                )
                
                return {
                    'algorithm': algorithm,
                    'encrypted_key': base64.b64encode(wrapped_key).decode('ascii'),
                    'ephemeral_key': base64.b64encode(ephemeral_public_bytes).decode('ascii')
                }
            
            elif algorithm == 'KYBER':
                # For post-quantum KEM like Kyber
                # Import post-quantum module
                from .post_quantum import PostQuantumCrypto, LIBOQS_AVAILABLE
                
                if not LIBOQS_AVAILABLE:
                    raise ValueError("Post-quantum cryptography is not available")
                
                # Initialize post-quantum crypto
                pq_crypto = PostQuantumCrypto()
                
                # Determine the specific Kyber variant
                key_info = self.key_manager.get_key_info(recipient_key_id)
                kyber_variant = key_info.get('algorithm', 'KYBER768')
                
                # Encapsulate a shared secret
                ciphertext, shared_secret = pq_crypto.encapsulate(kyber_variant, recipient_key)
                
                # Encrypt the symmetric key with the shared secret
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                nonce = os.urandom(12)
                aesgcm = AESGCM(shared_secret)
                encrypted_key = aesgcm.encrypt(nonce, symmetric_key, None)
                
                return {
                    'algorithm': algorithm,
                    'variant': kyber_variant,
                    'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
                    'encrypted_key': base64.b64encode(encrypted_key).decode('ascii'),
                    'nonce': base64.b64encode(nonce).decode('ascii')
                }
            
            else:
                raise ValueError(f"Unsupported key encryption algorithm: {algorithm}")
        
        except Exception as e:
            logger.error(f"Error encrypting key for recipient: {str(e)}")
            raise ValueError(f"Failed to encrypt key for recipient: {str(e)}")
    
    def _decrypt_key_for_recipient(self, 
                                  encrypted_key_data: Dict[str, Any],
                                  recipient_private_key: bytes,
                                  algorithm: str) -> bytes:
        """
        Decrypt the symmetric key for a specific recipient.
        
        Args:
            encrypted_key_data: The encrypted key data
            recipient_private_key: The recipient's private key
            algorithm: The algorithm used for key encryption
        
        Returns:
            The decrypted symmetric key
        
        Raises:
            ValueError: If decryption fails
        """
        try:
            if algorithm == 'RSA-OAEP':
                # Import RSA module
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives.serialization import load_der_private_key
                
                # Load the private key
                private_key = load_der_private_key(recipient_private_key, password=None)
                
                # Decrypt the symmetric key
                encrypted_key = base64.b64decode(encrypted_key_data.get('encrypted_key', ''))
                symmetric_key = private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                return symmetric_key
            
            elif algorithm == 'ECDH-ES+A256KW':
                # For ECDH, we need to perform key agreement and key unwrapping
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                from cryptography.hazmat.primitives import hashes
                
                # Load the private key
                private_key = load_der_private_key(recipient_private_key, password=None)
                
                # Load the ephemeral public key
                ephemeral_public_bytes = base64.b64decode(encrypted_key_data.get('ephemeral_key', ''))
                ephemeral_public_key = load_der_public_key(ephemeral_public_bytes)
                
                # Perform key agreement
                shared_key = private_key.exchange(
                    ec.ECDH(),
                    ephemeral_public_key
                )
                
                # Derive the wrapping key
                wrapping_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'ECDH-ES+A256KW'
                ).derive(shared_key)
                
                # Decrypt the symmetric key with AES-KW
                from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
                wrapped_key = base64.b64decode(encrypted_key_data.get('encrypted_key', ''))
                symmetric_key = aes_key_unwrap(wrapping_key, wrapped_key)
                
                return symmetric_key
            
            elif algorithm == 'KYBER':
                # For post-quantum KEM like Kyber
                # Import post-quantum module
                from .post_quantum import PostQuantumCrypto, LIBOQS_AVAILABLE
                
                if not LIBOQS_AVAILABLE:
                    raise ValueError("Post-quantum cryptography is not available")
                
                # Initialize post-quantum crypto
                pq_crypto = PostQuantumCrypto()
                
                # Get the Kyber variant
                kyber_variant = encrypted_key_data.get('variant', 'KYBER768')
                
                # Decode the ciphertext
                ciphertext = base64.b64decode(encrypted_key_data.get('ciphertext', ''))
                
                # Decapsulate the shared secret
                shared_secret = pq_crypto.decapsulate(kyber_variant, ciphertext, recipient_private_key)
                
                # Decrypt the symmetric key with the shared secret
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                nonce = base64.b64decode(encrypted_key_data.get('nonce', ''))
                encrypted_key = base64.b64decode(encrypted_key_data.get('encrypted_key', ''))
                
                aesgcm = AESGCM(shared_secret)
                symmetric_key = aesgcm.decrypt(nonce, encrypted_key, None)
                
                return symmetric_key
            
            else:
                raise ValueError(f"Unsupported key encryption algorithm: {algorithm}")
        
        except Exception as e:
            logger.error(f"Error decrypting key for recipient: {str(e)}")
            raise ValueError(f"Failed to decrypt key for recipient: {str(e)}")
    
    def _get_private_key_id(self, public_key_id: str) -> str:
        """
        Get the private key ID corresponding to a public key ID.
        
        Args:
            public_key_id: The public key ID
        
        Returns:
            The corresponding private key ID
        """
        # If the key ID already ends with .private, return it as is
        if public_key_id.endswith('.private'):
            return public_key_id
        
        # If the key ID ends with .public, replace it with .private
        if public_key_id.endswith('.public'):
            return public_key_id.replace('.public', '.private')
        
        # Otherwise, assume it's a key ID base and append .private
        key_id_base = public_key_id.split('.')[0]
        return f"{key_id_base}.private"
