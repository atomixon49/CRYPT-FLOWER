"""
Co-Signing Module

This module provides functionality for multiple parties to sign a document,
creating a chain of signatures that can be verified independently.
"""

import os
import json
import base64
import time
import hashlib
import logging
from typing import Dict, List, Any, Optional, Union, Tuple

from .signatures import SignatureEngine
from .key_management import KeyManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cosign")

class CoSignatureManager:
    """
    Manages co-signatures for documents.
    
    This class provides methods for:
    - Creating a new co-signature chain
    - Adding signatures to an existing chain
    - Verifying a co-signature chain
    - Managing the workflow for co-signatures
    """
    
    def __init__(self, key_manager: KeyManager = None):
        """
        Initialize the co-signature manager.
        
        Args:
            key_manager: KeyManager instance to use for key operations
        """
        self.signature_engine = SignatureEngine()
        self.key_manager = key_manager or KeyManager()
    
    def create_signature_chain(self, 
                              data: bytes, 
                              signer_key_id: str,
                              algorithm: str = "RSA-PSS",
                              metadata: Optional[Dict[str, Any]] = None,
                              required_signers: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Create a new co-signature chain with the first signature.
        
        Args:
            data: Data to sign
            signer_key_id: Key ID of the first signer
            algorithm: Signature algorithm to use
            metadata: Optional metadata to include
            required_signers: List of key IDs that are required to sign
        
        Returns:
            Dictionary containing the signature chain
        
        Raises:
            ValueError: If the signer key is invalid or signing fails
        """
        try:
            # Get the signer's private key
            private_key = self.key_manager.get_key(signer_key_id)
            if not private_key:
                raise ValueError(f"Private key not found: {signer_key_id}")
            
            # Get signer information
            signer_info = self._get_signer_info(signer_key_id)
            
            # Calculate document hash
            document_hash = self._hash_data(data)
            
            # Sign the document
            signature_result = self.signature_engine.sign(
                data=data,
                private_key=private_key,
                algorithm=algorithm
            )
            
            # Create the signature entry
            signature_entry = {
                'signer_id': signer_key_id,
                'signer_info': signer_info,
                'algorithm': algorithm,
                'signature': base64.b64encode(signature_result['signature']).decode('ascii'),
                'timestamp': time.time(),
                'sequence': 1  # First signature in the chain
            }
            
            # Create the signature chain
            signature_chain = {
                'version': '1.0',
                'type': 'cosignature_chain',
                'document_hash': base64.b64encode(document_hash).decode('ascii'),
                'hash_algorithm': 'SHA-256',
                'signatures': [signature_entry],
                'status': 'in_progress' if required_signers else 'completed'
            }
            
            # Add required signers if provided
            if required_signers:
                # Remove the current signer from the required list if present
                if signer_key_id in required_signers:
                    required_signers.remove(signer_key_id)
                
                signature_chain['required_signers'] = required_signers
                
                # If all required signers have signed, mark as completed
                if not required_signers:
                    signature_chain['status'] = 'completed'
            
            # Add metadata if provided
            if metadata:
                signature_chain['metadata'] = metadata
            
            return signature_chain
        
        except Exception as e:
            logger.error(f"Error creating signature chain: {str(e)}")
            raise ValueError(f"Failed to create signature chain: {str(e)}")
    
    def add_signature(self, 
                     data: bytes, 
                     signature_chain: Dict[str, Any],
                     signer_key_id: str,
                     algorithm: str = "RSA-PSS") -> Dict[str, Any]:
        """
        Add a signature to an existing co-signature chain.
        
        Args:
            data: Data to sign
            signature_chain: Existing signature chain
            signer_key_id: Key ID of the signer
            algorithm: Signature algorithm to use
        
        Returns:
            Updated signature chain
        
        Raises:
            ValueError: If the signer key is invalid, signing fails, or the chain is invalid
        """
        if not signature_chain or not isinstance(signature_chain, dict):
            raise ValueError("Invalid signature chain format")
        
        if signature_chain.get('type') != 'cosignature_chain':
            raise ValueError("Not a co-signature chain")
        
        if signature_chain.get('status') == 'completed':
            raise ValueError("Signature chain is already completed")
        
        try:
            # Verify the document hash
            document_hash = self._hash_data(data)
            stored_hash = base64.b64decode(signature_chain.get('document_hash', ''))
            
            if document_hash != stored_hash:
                raise ValueError("Document hash mismatch. The document has been modified.")
            
            # Check if the signer has already signed
            existing_signatures = signature_chain.get('signatures', [])
            for sig in existing_signatures:
                if sig.get('signer_id') == signer_key_id:
                    raise ValueError(f"Signer {signer_key_id} has already signed this document")
            
            # Check if the signer is in the required signers list
            required_signers = signature_chain.get('required_signers', [])
            if required_signers and signer_key_id not in required_signers:
                raise ValueError(f"Signer {signer_key_id} is not in the list of required signers")
            
            # Get the signer's private key
            private_key = self.key_manager.get_key(signer_key_id)
            if not private_key:
                raise ValueError(f"Private key not found: {signer_key_id}")
            
            # Get signer information
            signer_info = self._get_signer_info(signer_key_id)
            
            # Sign the document
            signature_result = self.signature_engine.sign(
                data=data,
                private_key=private_key,
                algorithm=algorithm
            )
            
            # Create the signature entry
            signature_entry = {
                'signer_id': signer_key_id,
                'signer_info': signer_info,
                'algorithm': algorithm,
                'signature': base64.b64encode(signature_result['signature']).decode('ascii'),
                'timestamp': time.time(),
                'sequence': len(existing_signatures) + 1
            }
            
            # Add the signature to the chain
            signature_chain['signatures'].append(signature_entry)
            
            # Update required signers if present
            if required_signers and signer_key_id in required_signers:
                required_signers.remove(signer_key_id)
                signature_chain['required_signers'] = required_signers
                
                # If all required signers have signed, mark as completed
                if not required_signers:
                    signature_chain['status'] = 'completed'
            
            return signature_chain
        
        except Exception as e:
            logger.error(f"Error adding signature: {str(e)}")
            raise ValueError(f"Failed to add signature: {str(e)}")
    
    def verify_signature_chain(self, 
                              data: bytes, 
                              signature_chain: Dict[str, Any],
                              verify_all: bool = True) -> Dict[str, Any]:
        """
        Verify a co-signature chain.
        
        Args:
            data: The signed data
            signature_chain: The signature chain to verify
            verify_all: Whether to verify all signatures or just check the chain structure
        
        Returns:
            Dictionary with verification results
        
        Raises:
            ValueError: If the signature chain is invalid
        """
        if not signature_chain or not isinstance(signature_chain, dict):
            raise ValueError("Invalid signature chain format")
        
        if signature_chain.get('type') != 'cosignature_chain':
            raise ValueError("Not a co-signature chain")
        
        try:
            # Verify the document hash
            document_hash = self._hash_data(data)
            stored_hash = base64.b64decode(signature_chain.get('document_hash', ''))
            
            hash_valid = document_hash == stored_hash
            
            # Get the signatures
            signatures = signature_chain.get('signatures', [])
            
            # Verify each signature
            verification_results = []
            all_valid = True
            
            for sig in signatures:
                signer_id = sig.get('signer_id')
                algorithm = sig.get('algorithm')
                signature_b64 = sig.get('signature')
                
                result = {
                    'signer_id': signer_id,
                    'signer_info': sig.get('signer_info', {}),
                    'sequence': sig.get('sequence'),
                    'timestamp': sig.get('timestamp'),
                    'valid': False
                }
                
                if verify_all:
                    try:
                        # Get the signer's public key
                        public_key_id = self._get_public_key_id(signer_id)
                        public_key = self.key_manager.get_key(public_key_id)
                        
                        if not public_key:
                            result['error'] = f"Public key not found: {public_key_id}"
                            all_valid = False
                        else:
                            # Verify the signature
                            signature = base64.b64decode(signature_b64)
                            
                            is_valid = self.signature_engine.verify(
                                data=data,
                                signature_result={
                                    'algorithm': algorithm,
                                    'signature': signature
                                },
                                public_key=public_key
                            )
                            
                            result['valid'] = is_valid
                            if not is_valid:
                                all_valid = False
                    
                    except Exception as e:
                        result['error'] = str(e)
                        all_valid = False
                
                verification_results.append(result)
            
            # Check if all required signers have signed
            required_signers = signature_chain.get('required_signers', [])
            missing_signers = []
            
            if required_signers:
                # Get the list of signers who have signed
                actual_signers = [sig.get('signer_id') for sig in signatures]
                
                # Find missing signers
                for signer_id in required_signers:
                    if signer_id not in actual_signers:
                        missing_signers.append(signer_id)
            
            # Prepare the result
            return {
                'hash_valid': hash_valid,
                'signatures_valid': all_valid if verify_all else None,
                'verification_results': verification_results,
                'status': signature_chain.get('status', 'unknown'),
                'missing_signers': missing_signers,
                'complete': len(missing_signers) == 0
            }
        
        except Exception as e:
            logger.error(f"Error verifying signature chain: {str(e)}")
            raise ValueError(f"Failed to verify signature chain: {str(e)}")
    
    def get_signature_status(self, signature_chain: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get the status of a signature chain.
        
        Args:
            signature_chain: The signature chain to check
        
        Returns:
            Dictionary with status information
        
        Raises:
            ValueError: If the signature chain is invalid
        """
        if not signature_chain or not isinstance(signature_chain, dict):
            raise ValueError("Invalid signature chain format")
        
        if signature_chain.get('type') != 'cosignature_chain':
            raise ValueError("Not a co-signature chain")
        
        try:
            # Get the signatures
            signatures = signature_chain.get('signatures', [])
            
            # Get the required signers
            required_signers = signature_chain.get('required_signers', [])
            
            # Get the list of signers who have signed
            actual_signers = [sig.get('signer_id') for sig in signatures]
            
            # Find missing signers
            missing_signers = []
            for signer_id in required_signers:
                if signer_id not in actual_signers:
                    missing_signers.append(signer_id)
            
            # Prepare the result
            return {
                'status': signature_chain.get('status', 'unknown'),
                'total_signatures': len(signatures),
                'required_signers': required_signers,
                'missing_signers': missing_signers,
                'complete': len(missing_signers) == 0,
                'signatures': signatures
            }
        
        except Exception as e:
            logger.error(f"Error getting signature status: {str(e)}")
            raise ValueError(f"Failed to get signature status: {str(e)}")
    
    def _hash_data(self, data: bytes) -> bytes:
        """
        Calculate the hash of data.
        
        Args:
            data: Data to hash
        
        Returns:
            Hash of the data
        """
        return hashlib.sha256(data).digest()
    
    def _get_signer_info(self, key_id: str) -> Dict[str, Any]:
        """
        Get information about a signer.
        
        Args:
            key_id: Key ID of the signer
        
        Returns:
            Dictionary with signer information
        """
        try:
            # Get key information
            key_info = self.key_manager.get_key_info(key_id)
            
            # Extract relevant information
            signer_info = {
                'name': key_info.get('label', key_id),
                'algorithm': key_info.get('algorithm'),
                'key_type': key_info.get('key_type')
            }
            
            # Add certificate information if available
            if key_info.get('key_type') == 'certificate':
                signer_info['subject'] = key_info.get('subject', {})
                signer_info['issuer'] = key_info.get('issuer', {})
            
            return signer_info
        
        except Exception:
            # Return minimal information if key info is not available
            return {
                'name': key_id
            }
    
    def _get_public_key_id(self, key_id: str) -> str:
        """
        Get the public key ID corresponding to a key ID.
        
        Args:
            key_id: The key ID
        
        Returns:
            The corresponding public key ID
        """
        # If the key ID already ends with .public, return it as is
        if key_id.endswith('.public'):
            return key_id
        
        # If the key ID ends with .private, replace it with .public
        if key_id.endswith('.private'):
            return key_id.replace('.private', '.public')
        
        # Otherwise, assume it's a key ID base and append .public
        key_id_base = key_id.split('.')[0]
        return f"{key_id_base}.public"
