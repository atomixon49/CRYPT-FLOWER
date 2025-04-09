"""
Encryption Module

This module provides encryption and decryption functionality using modern
cryptographic algorithms with secure defaults.
"""

import os
import secrets
from typing import Tuple, Optional, Union, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Try to import post-quantum module
try:
    from .post_quantum import PostQuantumCrypto
    POSTQUANTUM_AVAILABLE = True
except ImportError:
    POSTQUANTUM_AVAILABLE = False

class EncryptionEngine:
    """
    Core encryption and decryption functionality.

    This class provides a high-level interface for encrypting and decrypting
    data using modern authenticated encryption algorithms.
    """

    def __init__(self):
        """Initialize the encryption engine."""
        self.supported_algorithms = {
            'AES-GCM': self._encrypt_aes_gcm,
            'ChaCha20-Poly1305': self._encrypt_chacha20_poly1305,
        }

        # Initialize post-quantum crypto if available
        self.pq_crypto = None
        if POSTQUANTUM_AVAILABLE:
            try:
                self.pq_crypto = PostQuantumCrypto()

                # Add post-quantum algorithms
                self.supported_algorithms.update({
                    'KYBER768': self._encrypt_kyber,
                    'KYBER512': self._encrypt_kyber,
                    'KYBER1024': self._encrypt_kyber,
                })

                # Add NTRU algorithms if available
                if hasattr(self.pq_crypto, 'NTRU_AVAILABLE') and self.pq_crypto.NTRU_AVAILABLE:
                    self.supported_algorithms.update({
                        'NTRU-HPS-2048-509': self._encrypt_kyber,  # We can reuse the same method
                        'NTRU-HPS-2048-677': self._encrypt_kyber,
                        'NTRU-HPS-4096-821': self._encrypt_kyber,
                        'NTRU-HRSS-701': self._encrypt_kyber,
                    })

                # Add post-quantum decryption algorithms
                self.supported_decryption_pq = {
                    'KYBER768': self._decrypt_kyber,
                    'KYBER512': self._decrypt_kyber,
                    'KYBER1024': self._decrypt_kyber,
                }

                # Add NTRU decryption algorithms if available
                if hasattr(self.pq_crypto, 'NTRU_AVAILABLE') and self.pq_crypto.NTRU_AVAILABLE:
                    self.supported_decryption_pq.update({
                        'NTRU-HPS-2048-509': self._decrypt_kyber,  # We can reuse the same method
                        'NTRU-HPS-2048-677': self._decrypt_kyber,
                        'NTRU-HPS-4096-821': self._decrypt_kyber,
                        'NTRU-HRSS-701': self._decrypt_kyber,
                    })
            except ImportError:
                # Post-quantum crypto is not available
                pass

        self.supported_decryption = {
            'AES-GCM': self._decrypt_aes_gcm,
            'ChaCha20-Poly1305': self._decrypt_chacha20_poly1305,
        }

    def encrypt(self,
                data: bytes,
                key: bytes,
                algorithm: str = 'AES-GCM',
                associated_data: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Encrypt data using the specified algorithm.

        Args:
            data: The data to encrypt
            key: The encryption key
            algorithm: The encryption algorithm to use
            associated_data: Optional associated data for authenticated encryption

        Returns:
            A dictionary containing the encrypted data and metadata

        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported algorithms: {list(self.supported_algorithms.keys())}")

        # Call the appropriate encryption function
        encrypt_func = self.supported_algorithms[algorithm]
        ciphertext, nonce, tag = encrypt_func(data, key, associated_data)

        # Return a dictionary with all the necessary information for decryption
        return {
            'algorithm': algorithm,
            'ciphertext': ciphertext,
            'nonce': nonce,
            'tag': tag,
            'associated_data': associated_data
        }

    def decrypt(self,
                encryption_result: Dict[str, Any],
                key: bytes) -> bytes:
        """
        Decrypt data using the information in the encryption result.

        Args:
            encryption_result: The result from the encrypt method
            key: The decryption key

        Returns:
            The decrypted data

        Raises:
            ValueError: If the algorithm is not supported or the data is invalid
        """
        algorithm = encryption_result.get('algorithm')

        # Check if this is a post-quantum algorithm
        if hasattr(self, 'supported_decryption_pq') and algorithm in self.supported_decryption_pq:
            # Handle post-quantum decryption
            decrypt_func = self.supported_decryption_pq[algorithm]
            return decrypt_func(
                encryption_result.get('ciphertext'),
                key,
                encryption_result.get('kem_ciphertext'),
                encryption_result.get('nonce'),
                algorithm
            )
        elif algorithm in self.supported_decryption:
            # Handle standard decryption
            decrypt_func = self.supported_decryption[algorithm]
            return decrypt_func(
                encryption_result.get('ciphertext'),
                key,
                encryption_result.get('nonce'),
                encryption_result.get('tag'),
                encryption_result.get('associated_data')
            )
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported algorithms: {list(self.supported_decryption.keys()) + (list(self.supported_decryption_pq.keys()) if hasattr(self, 'supported_decryption_pq') else [])}")

    def _encrypt_aes_gcm(self,
                         data: bytes,
                         key: bytes,
                         associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-GCM.

        Args:
            data: The data to encrypt
            key: The encryption key
            associated_data: Optional associated data

        Returns:
            A tuple of (ciphertext, nonce, tag)
        """
        # Generate a random 96-bit nonce (recommended for AES-GCM)
        nonce = os.urandom(12)

        # Create an AES-GCM cipher
        aesgcm = AESGCM(key)

        # Encrypt the data
        ciphertext = aesgcm.encrypt(nonce, data, associated_data)

        # In the cryptography library, the tag is appended to the ciphertext
        # For clarity, we'll separate them (last 16 bytes are the tag)
        tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]

        return ciphertext, nonce, tag

    def _decrypt_aes_gcm(self,
                         ciphertext: bytes,
                         key: bytes,
                         nonce: bytes,
                         tag: bytes,
                         associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using AES-GCM.

        Args:
            ciphertext: The encrypted data
            key: The decryption key
            nonce: The nonce used for encryption
            tag: The authentication tag
            associated_data: Optional associated data

        Returns:
            The decrypted data

        Raises:
            ValueError: If the data cannot be authenticated
        """
        # Create an AES-GCM cipher
        aesgcm = AESGCM(key)

        # In the cryptography library, the tag should be appended to the ciphertext
        ciphertext_with_tag = ciphertext + tag

        # Decrypt the data
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def _encrypt_chacha20_poly1305(self,
                                  data: bytes,
                                  key: bytes,
                                  associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using ChaCha20-Poly1305.

        Args:
            data: The data to encrypt
            key: The encryption key
            associated_data: Optional associated data

        Returns:
            A tuple of (ciphertext, nonce, tag)
        """
        # Generate a random 96-bit nonce (recommended for ChaCha20-Poly1305)
        nonce = os.urandom(12)

        # Create a ChaCha20-Poly1305 cipher
        chacha = ChaCha20Poly1305(key)

        # Encrypt the data
        ciphertext = chacha.encrypt(nonce, data, associated_data)

        # In the cryptography library, the tag is appended to the ciphertext
        # For clarity, we'll separate them (last 16 bytes are the tag)
        tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]

        return ciphertext, nonce, tag

    def _decrypt_chacha20_poly1305(self,
                                  ciphertext: bytes,
                                  key: bytes,
                                  nonce: bytes,
                                  tag: bytes,
                                  associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using ChaCha20-Poly1305.

        Args:
            ciphertext: The encrypted data
            key: The decryption key
            nonce: The nonce used for encryption
            tag: The authentication tag
            associated_data: Optional associated data

        Returns:
            The decrypted data

        Raises:
            ValueError: If the data cannot be authenticated
        """
        # Create a ChaCha20-Poly1305 cipher
        chacha = ChaCha20Poly1305(key)

        # In the cryptography library, the tag should be appended to the ciphertext
        ciphertext_with_tag = ciphertext + tag

        # Decrypt the data
        try:
            plaintext = chacha.decrypt(nonce, ciphertext_with_tag, associated_data)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def _encrypt_kyber(self, data: bytes, key: bytes, algorithm: str = 'KYBER768', **kwargs) -> Dict[str, Any]:
        """
        Encrypt data using Kyber KEM with AES-GCM for the symmetric part.

        Args:
            data: The data to encrypt
            key: The public key for encryption
            algorithm: The specific Kyber variant to use
            **kwargs: Additional parameters (ignored)

        Returns:
            A dictionary containing the encrypted data and metadata

        Raises:
            ValueError: If encryption fails
        """
        if not POSTQUANTUM_AVAILABLE or not self.pq_crypto:
            raise ValueError("Post-quantum cryptography is not available")

        # Encrypt the data using Kyber KEM with AES-GCM
        result = self.pq_crypto.encrypt_with_kem(data, key, algorithm)

        # Return the result with metadata
        return {
            'ciphertext': result['encrypted_data'],  # The AES-GCM encrypted data
            'algorithm': algorithm,
            'kem_ciphertext': result['ciphertext'],  # The KEM ciphertext
            'nonce': result['nonce'],  # The nonce used for AES-GCM
            'post_quantum': True
        }

    def _decrypt_kyber(self, ciphertext: bytes, key: bytes, kem_ciphertext: bytes, nonce: bytes, algorithm: str = 'KYBER768', **kwargs) -> bytes:
        """
        Decrypt data using Kyber KEM with AES-GCM for the symmetric part.

        Args:
            ciphertext: The encrypted data (AES-GCM ciphertext)
            key: The private key for decryption
            kem_ciphertext: The KEM ciphertext containing the encapsulated shared secret
            nonce: The nonce used for AES-GCM encryption
            algorithm: The specific Kyber variant used
            **kwargs: Additional parameters (ignored)

        Returns:
            The decrypted data

        Raises:
            ValueError: If decryption fails or authentication fails
        """
        if not POSTQUANTUM_AVAILABLE or not self.pq_crypto:
            raise ValueError("Post-quantum cryptography is not available")

        # Decrypt the data using Kyber KEM with AES-GCM
        encrypted_data = {
            'ciphertext': kem_ciphertext,
            'encrypted_data': ciphertext,
            'nonce': nonce,
            'algorithm': algorithm
        }

        return self.pq_crypto.decrypt_with_kem(encrypted_data, key)
