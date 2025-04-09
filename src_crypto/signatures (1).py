"""
Digital Signatures Module

This module provides functionality for creating and verifying digital signatures.
"""

import os
import time
from typing import Tuple, Dict, Optional, Any
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class SignatureEngine:
    """
    Core digital signature functionality.
    
    This class provides a high-level interface for creating and verifying
    digital signatures using various algorithms.
    """
    
    def __init__(self):
        """Initialize the signature engine."""
        self.supported_algorithms = {
            'RSA-PSS': self._sign_rsa_pss,
            'RSA-PKCS1v15': self._sign_rsa_pkcs1v15,
            # Future: Add post-quantum signature algorithms
        }
        
        self.supported_verification = {
            'RSA-PSS': self._verify_rsa_pss,
            'RSA-PKCS1v15': self._verify_rsa_pkcs1v15,
            # Future: Add post-quantum signature verification
        }
    
    def generate_key_pair(self, algorithm: str = 'RSA-PSS', key_size: int = 3072) -> Dict[str, Any]:
        """
        Generate a new key pair for digital signatures.
        
        Args:
            algorithm: The signature algorithm
            key_size: The size of the key in bits
            
        Returns:
            A dictionary containing the key pair and metadata
            
        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm.startswith('RSA'):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            public_key = private_key.public_key()
            
            # Serialize keys for storage
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return {
                'algorithm': algorithm,
                'key_size': key_size,
                'private_key': private_key,
                'public_key': public_key,
                'private_pem': private_pem,
                'public_pem': public_pem,
                'created': time.time()
            }
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def sign(self, 
             data: bytes, 
             private_key: Any, 
             algorithm: str = 'RSA-PSS') -> Dict[str, Any]:
        """
        Sign data using the specified algorithm.
        
        Args:
            data: The data to sign
            private_key: The private key to use for signing
            algorithm: The signature algorithm to use
            
        Returns:
            A dictionary containing the signature and metadata
            
        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported algorithms: {list(self.supported_algorithms.keys())}")
        
        # Call the appropriate signing function
        sign_func = self.supported_algorithms[algorithm]
        signature = sign_func(data, private_key)
        
        # Return a dictionary with all the necessary information for verification
        return {
            'algorithm': algorithm,
            'signature': signature,
            'timestamp': time.time()
        }
    
    def verify(self, 
               data: bytes, 
               signature_result: Dict[str, Any], 
               public_key: Any) -> bool:
        """
        Verify a signature.
        
        Args:
            data: The data that was signed
            signature_result: The result from the sign method
            public_key: The public key to use for verification
            
        Returns:
            True if the signature is valid, False otherwise
            
        Raises:
            ValueError: If the algorithm is not supported
        """
        algorithm = signature_result.get('algorithm')
        if algorithm not in self.supported_verification:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported algorithms: {list(self.supported_verification.keys())}")
        
        # Call the appropriate verification function
        verify_func = self.supported_verification[algorithm]
        try:
            verify_func(data, signature_result.get('signature'), public_key)
            return True
        except InvalidSignature:
            return False
    
    def _sign_rsa_pss(self, data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Sign data using RSA-PSS.
        
        Args:
            data: The data to sign
            private_key: The RSA private key
            
        Returns:
            The signature
        """
        signature = private_key.sign(
            data,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def _verify_rsa_pss(self, data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> None:
        """
        Verify an RSA-PSS signature.
        
        Args:
            data: The data that was signed
            signature: The signature to verify
            public_key: The RSA public key
            
        Raises:
            InvalidSignature: If the signature is invalid
        """
        public_key.verify(
            signature,
            data,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def _sign_rsa_pkcs1v15(self, data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Sign data using RSA PKCS#1 v1.5.
        
        Args:
            data: The data to sign
            private_key: The RSA private key
            
        Returns:
            The signature
        """
        signature = private_key.sign(
            data,
            asymmetric_padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature
    
    def _verify_rsa_pkcs1v15(self, data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> None:
        """
        Verify an RSA PKCS#1 v1.5 signature.
        
        Args:
            data: The data that was signed
            signature: The signature to verify
            public_key: The RSA public key
            
        Raises:
            InvalidSignature: If the signature is invalid
        """
        public_key.verify(
            signature,
            data,
            asymmetric_padding.PKCS1v15(),
            hashes.SHA256()
        )
