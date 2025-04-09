"""
Post-Quantum Cryptography Module

This module provides an interface for post-quantum cryptographic algorithms.
It supports key encapsulation mechanisms (KEMs) like Kyber and signature
algorithms like Dilithium.

Note: This implementation requires the liboqs-python library, which can be installed with:
pip install liboqs
"""

import os
import logging
from typing import Dict, Any, Optional, Tuple, List, Union, Callable

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("post_quantum")

# Try to import liboqs
try:
    import oqs
    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False
    logger.warning("liboqs not available. Post-quantum cryptography will not work.")


class PostQuantumCrypto:
    """
    Interface for post-quantum cryptographic algorithms.
    
    This class provides methods for generating key pairs, encapsulating and
    decapsulating keys (for KEMs), and signing and verifying messages (for
    signature algorithms).
    """
    
    def __init__(self):
        """
        Initialize the post-quantum cryptography interface.
        
        Raises:
            ValueError: If liboqs is not available
        """
        if not LIBOQS_AVAILABLE:
            raise ValueError("liboqs is not available. Please install with: pip install liboqs")
        
        # Get supported algorithms
        self.supported_kems = oqs.get_enabled_KEM_mechanisms()
        self.supported_sigs = oqs.get_enabled_sig_mechanisms()
        
        logger.info(f"Initialized post-quantum cryptography with {len(self.supported_kems)} KEMs and {len(self.supported_sigs)} signature algorithms")
    
    def get_supported_algorithms(self) -> Dict[str, List[str]]:
        """
        Get a list of supported post-quantum algorithms.
        
        Returns:
            Dictionary with lists of supported KEM and signature algorithms
        """
        return {
            'kem': self.supported_kems,
            'signature': self.supported_sigs
        }
    
    def generate_kem_keypair(self, algorithm: str) -> Tuple[bytes, bytes]:
        """
        Generate a key pair for a key encapsulation mechanism (KEM).
        
        Args:
            algorithm: Name of the KEM algorithm (e.g., 'Kyber512', 'Kyber768', 'Kyber1024')
        
        Returns:
            Tuple containing (public_key, private_key)
        
        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm not in self.supported_kems:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")
        
        try:
            with oqs.KeyEncapsulation(algorithm) as kem:
                public_key = kem.generate_keypair()
                private_key = kem.export_secret_key()
                
                return public_key, private_key
        
        except Exception as e:
            logger.error(f"Failed to generate KEM key pair: {str(e)}")
            raise ValueError(f"Failed to generate KEM key pair: {str(e)}")
    
    def encapsulate(self, algorithm: str, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using a public key.
        
        Args:
            algorithm: Name of the KEM algorithm
            public_key: Public key to use for encapsulation
        
        Returns:
            Tuple containing (ciphertext, shared_secret)
        
        Raises:
            ValueError: If the algorithm is not supported or encapsulation fails
        """
        if algorithm not in self.supported_kems:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")
        
        try:
            with oqs.KeyEncapsulation(algorithm) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)
                
                return ciphertext, shared_secret
        
        except Exception as e:
            logger.error(f"Failed to encapsulate shared secret: {str(e)}")
            raise ValueError(f"Failed to encapsulate shared secret: {str(e)}")
    
    def decapsulate(self, algorithm: str, ciphertext: bytes, private_key: bytes) -> bytes:
        """
        Decapsulate a shared secret using a private key.
        
        Args:
            algorithm: Name of the KEM algorithm
            ciphertext: Ciphertext from encapsulation
            private_key: Private key to use for decapsulation
        
        Returns:
            Shared secret
        
        Raises:
            ValueError: If the algorithm is not supported or decapsulation fails
        """
        if algorithm not in self.supported_kems:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")
        
        try:
            with oqs.KeyEncapsulation(algorithm, private_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
                
                return shared_secret
        
        except Exception as e:
            logger.error(f"Failed to decapsulate shared secret: {str(e)}")
            raise ValueError(f"Failed to decapsulate shared secret: {str(e)}")
    
    def generate_signature_keypair(self, algorithm: str) -> Tuple[bytes, bytes]:
        """
        Generate a key pair for a signature algorithm.
        
        Args:
            algorithm: Name of the signature algorithm (e.g., 'Dilithium2', 'Dilithium3', 'Dilithium5')
        
        Returns:
            Tuple containing (public_key, private_key)
        
        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm not in self.supported_sigs:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")
        
        try:
            with oqs.Signature(algorithm) as sig:
                public_key = sig.generate_keypair()
                private_key = sig.export_secret_key()
                
                return public_key, private_key
        
        except Exception as e:
            logger.error(f"Failed to generate signature key pair: {str(e)}")
            raise ValueError(f"Failed to generate signature key pair: {str(e)}")
    
    def sign(self, algorithm: str, message: bytes, private_key: bytes) -> bytes:
        """
        Sign a message using a private key.
        
        Args:
            algorithm: Name of the signature algorithm
            message: Message to sign
            private_key: Private key to use for signing
        
        Returns:
            Signature
        
        Raises:
            ValueError: If the algorithm is not supported or signing fails
        """
        if algorithm not in self.supported_sigs:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")
        
        try:
            with oqs.Signature(algorithm, private_key) as sig:
                signature = sig.sign(message)
                
                return signature
        
        except Exception as e:
            logger.error(f"Failed to sign message: {str(e)}")
            raise ValueError(f"Failed to sign message: {str(e)}")
    
    def verify(self, algorithm: str, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature using a public key.
        
        Args:
            algorithm: Name of the signature algorithm
            message: Original message
            signature: Signature to verify
            public_key: Public key to use for verification
        
        Returns:
            True if the signature is valid, False otherwise
        
        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm not in self.supported_sigs:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")
        
        try:
            with oqs.Signature(algorithm) as sig:
                return sig.verify(message, signature, public_key)
        
        except Exception as e:
            logger.error(f"Failed to verify signature: {str(e)}")
            return False
    
    def get_algorithm_details(self, algorithm: str) -> Dict[str, Any]:
        """
        Get details about a post-quantum algorithm.
        
        Args:
            algorithm: Name of the algorithm
        
        Returns:
            Dictionary with algorithm details
        
        Raises:
            ValueError: If the algorithm is not supported
        """
        # Check if it's a KEM algorithm
        if algorithm in self.supported_kems:
            with oqs.KeyEncapsulation(algorithm) as kem:
                return {
                    'type': 'kem',
                    'name': algorithm,
                    'version': kem.alg_version(),
                    'claimed_nist_level': kem.claimed_nist_level(),
                    'is_ind_cca': kem.is_ind_cca(),
                    'length_public_key': kem.length_public_key(),
                    'length_secret_key': kem.length_secret_key(),
                    'length_ciphertext': kem.length_ciphertext(),
                    'length_shared_secret': kem.length_shared_secret()
                }
        
        # Check if it's a signature algorithm
        elif algorithm in self.supported_sigs:
            with oqs.Signature(algorithm) as sig:
                return {
                    'type': 'signature',
                    'name': algorithm,
                    'version': sig.alg_version(),
                    'claimed_nist_level': sig.claimed_nist_level(),
                    'is_euf_cma': sig.is_euf_cma(),
                    'length_public_key': sig.length_public_key(),
                    'length_secret_key': sig.length_secret_key(),
                    'length_signature': sig.length_signature()
                }
        
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
