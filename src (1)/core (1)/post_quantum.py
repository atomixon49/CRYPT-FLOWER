"""
Post-quantum cryptography module.

This module provides support for post-quantum cryptography algorithms.
"""

import os
import time
import json
from typing import Dict, Any, Optional, Tuple, List, Union

# Import cryptography libraries for AES-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    import pqcrypto
    from pqcrypto.sign import dilithium2, dilithium3, dilithium5
    from pqcrypto.kem import kyber512, kyber768, kyber1024

    # Import NTRU variants if available
    try:
        from pqcrypto.kem import ntruhps2048509, ntruhps2048677, ntruhps4096821, ntruhrss701
        NTRU_AVAILABLE = True
    except ImportError:
        NTRU_AVAILABLE = False

    PQCRYPTO_AVAILABLE = True
except ImportError:
    PQCRYPTO_AVAILABLE = False
    NTRU_AVAILABLE = False


class PostQuantumCrypto:
    """Post-quantum cryptography implementation."""

    def __init__(self):
        """Initialize the post-quantum cryptography module."""
        if not PQCRYPTO_AVAILABLE:
            raise ImportError(
                "pqcrypto library is not available. "
                "Please install it with 'pip install pqcrypto'."
            )

        # Available algorithms
        self.available_sign_algorithms = {
            "DILITHIUM2": dilithium2,
            "DILITHIUM3": dilithium3,
            "DILITHIUM5": dilithium5,
        }

        self.available_kem_algorithms = {
            "KYBER512": kyber512,
            "KYBER768": kyber768,
            "KYBER1024": kyber1024,
        }

        # Add NTRU algorithms if available
        if NTRU_AVAILABLE:
            self.available_kem_algorithms.update({
                "NTRU-HPS-2048-509": ntruhps2048509,
                "NTRU-HPS-2048-677": ntruhps2048677,
                "NTRU-HPS-4096-821": ntruhps4096821,
                "NTRU-HRSS-701": ntruhrss701,
            })

    def generate_sign_keypair(self, algorithm: str = "DILITHIUM2") -> Tuple[bytes, bytes]:
        """
        Generate a post-quantum signature key pair.

        Args:
            algorithm: The signature algorithm to use (DILITHIUM2, DILITHIUM3, DILITHIUM5)

        Returns:
            A tuple containing (public_key, private_key)

        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm not in self.available_sign_algorithms:
            raise ValueError(
                f"Unsupported signature algorithm: {algorithm}. "
                f"Supported algorithms: {', '.join(self.available_sign_algorithms.keys())}"
            )

        # Get the algorithm implementation
        alg = self.available_sign_algorithms[algorithm]

        # Generate key pair
        public_key, private_key = alg.keypair()

        return public_key, private_key

    def sign(self, message: bytes, private_key: bytes, algorithm: str = "DILITHIUM2") -> bytes:
        """
        Sign a message using a post-quantum signature algorithm.

        Args:
            message: The message to sign
            private_key: The private key to use for signing
            algorithm: The signature algorithm to use

        Returns:
            The signature

        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm not in self.available_sign_algorithms:
            raise ValueError(
                f"Unsupported signature algorithm: {algorithm}. "
                f"Supported algorithms: {', '.join(self.available_sign_algorithms.keys())}"
            )

        # Get the algorithm implementation
        alg = self.available_sign_algorithms[algorithm]

        # Sign the message
        signature = alg.sign(message, private_key)

        return signature

    def verify(self, message: bytes, signature: bytes, public_key: bytes, algorithm: str = "DILITHIUM2") -> bool:
        """
        Verify a signature using a post-quantum signature algorithm.

        Args:
            message: The message that was signed
            signature: The signature to verify
            public_key: The public key to use for verification
            algorithm: The signature algorithm to use

        Returns:
            True if the signature is valid, False otherwise

        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm not in self.available_sign_algorithms:
            raise ValueError(
                f"Unsupported signature algorithm: {algorithm}. "
                f"Supported algorithms: {', '.join(self.available_sign_algorithms.keys())}"
            )

        # Get the algorithm implementation
        alg = self.available_sign_algorithms[algorithm]

        try:
            # Verify the signature
            alg.verify(message, signature, public_key)
            return True
        except Exception:
            return False

    def generate_kem_keypair(self, algorithm: str = "KYBER768") -> Tuple[bytes, bytes]:
        """
        Generate a post-quantum KEM (Key Encapsulation Mechanism) key pair.

        Args:
            algorithm: The KEM algorithm to use (KYBER512, KYBER768, KYBER1024)

        Returns:
            A tuple containing (public_key, private_key)

        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm not in self.available_kem_algorithms:
            raise ValueError(
                f"Unsupported KEM algorithm: {algorithm}. "
                f"Supported algorithms: {', '.join(self.available_kem_algorithms.keys())}"
            )

        # Get the algorithm implementation
        alg = self.available_kem_algorithms[algorithm]

        # Generate key pair
        public_key, private_key = alg.keypair()

        return public_key, private_key

    def encapsulate(self, public_key: bytes, algorithm: str = "KYBER768") -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using a post-quantum KEM algorithm.

        Args:
            public_key: The public key to use for encapsulation
            algorithm: The KEM algorithm to use

        Returns:
            A tuple containing (ciphertext, shared_secret)

        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm not in self.available_kem_algorithms:
            raise ValueError(
                f"Unsupported KEM algorithm: {algorithm}. "
                f"Supported algorithms: {', '.join(self.available_kem_algorithms.keys())}"
            )

        # Get the algorithm implementation
        alg = self.available_kem_algorithms[algorithm]

        # Encapsulate a shared secret
        ciphertext, shared_secret = alg.encap(public_key)

        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes, private_key: bytes, algorithm: str = "KYBER768") -> bytes:
        """
        Decapsulate a shared secret using a post-quantum KEM algorithm.

        Args:
            ciphertext: The ciphertext containing the encapsulated shared secret
            private_key: The private key to use for decapsulation
            algorithm: The KEM algorithm to use

        Returns:
            The shared secret

        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm not in self.available_kem_algorithms:
            raise ValueError(
                f"Unsupported KEM algorithm: {algorithm}. "
                f"Supported algorithms: {', '.join(self.available_kem_algorithms.keys())}"
            )

        # Get the algorithm implementation
        alg = self.available_kem_algorithms[algorithm]

        # Decapsulate the shared secret
        shared_secret = alg.decap(ciphertext, private_key)

        return shared_secret

    def encrypt_with_kem(self, plaintext: bytes, public_key: bytes, algorithm: str = "KYBER768") -> Dict[str, bytes]:
        """
        Encrypt data using a post-quantum KEM algorithm.

        This function encapsulates a shared secret, then uses it to encrypt the plaintext.
        It uses AES-GCM for the symmetric encryption part, which provides authenticated encryption.

        Args:
            plaintext: The data to encrypt
            public_key: The public key to use for encapsulation
            algorithm: The KEM algorithm to use

        Returns:
            A dictionary containing the ciphertext, encrypted data, nonce, and algorithm

        Raises:
            ValueError: If the algorithm is not supported
        """
        # Encapsulate a shared secret
        ciphertext, shared_secret = self.encapsulate(public_key, algorithm)

        # Derive a key for AES-GCM from the shared secret using HKDF
        # This is more secure than using the shared secret directly
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256-GCM
            salt=None,
            info=b'kyber-aes-gcm'
        ).derive(shared_secret)

        # Generate a random nonce for AES-GCM
        nonce = os.urandom(12)  # 96 bits as recommended for AES-GCM

        # Create an AES-GCM cipher
        aesgcm = AESGCM(derived_key)

        # Encrypt the plaintext
        # AES-GCM provides both confidentiality and authenticity
        encrypted_data = aesgcm.encrypt(nonce, plaintext, None)

        return {
            "ciphertext": ciphertext,  # The KEM ciphertext containing the encapsulated shared secret
            "encrypted_data": encrypted_data,  # The AES-GCM encrypted data
            "nonce": nonce,  # The nonce used for AES-GCM
            "algorithm": algorithm  # The KEM algorithm used
        }

    def decrypt_with_kem(self, encrypted_data: Dict[str, bytes], private_key: bytes) -> bytes:
        """
        Decrypt data using a post-quantum KEM algorithm.

        This function decapsulates the shared secret, then uses it to decrypt the ciphertext
        using AES-GCM, which provides authenticated encryption.

        Args:
            encrypted_data: A dictionary containing the KEM ciphertext, encrypted data, and nonce
            private_key: The private key to use for decapsulation

        Returns:
            The decrypted plaintext

        Raises:
            ValueError: If the algorithm is not supported, the encrypted data is invalid,
                       or the authentication tag verification fails
        """
        # Extract the ciphertext, encrypted data, nonce, and algorithm
        ciphertext = encrypted_data.get("ciphertext")
        encrypted_data_bytes = encrypted_data.get("encrypted_data")
        nonce = encrypted_data.get("nonce")
        algorithm = encrypted_data.get("algorithm", "KYBER768")

        if not ciphertext or not encrypted_data_bytes or not nonce:
            raise ValueError("Invalid encrypted data format: missing required fields")

        # Decapsulate the shared secret
        shared_secret = self.decapsulate(ciphertext, private_key, algorithm)

        # Derive the same key for AES-GCM from the shared secret using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256-GCM
            salt=None,
            info=b'kyber-aes-gcm'
        ).derive(shared_secret)

        # Create an AES-GCM cipher
        aesgcm = AESGCM(derived_key)

        try:
            # Decrypt the data
            # AES-GCM will verify the authentication tag automatically
            # and raise an exception if verification fails
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data_bytes, None)
            return decrypted_data
        except Exception as e:
            raise ValueError(f"Decryption failed: authentication tag verification failed. {str(e)}")
