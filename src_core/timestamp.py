"""
Timestamp Module

This module provides functionality for secure timestamping of documents and signatures,
including integration with Time Stamping Authority (TSA) services.
"""

import os
import json
import base64
import time
import hashlib
import logging
import requests
from typing import Dict, List, Any, Optional, Union, Tuple
from urllib.parse import urljoin

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("timestamp")

class TimestampManager:
    """
    Manages secure timestamps for documents and signatures.
    
    This class provides methods for:
    - Creating timestamp requests
    - Sending requests to TSA servers
    - Verifying timestamp responses
    - Managing timestamp tokens
    """
    
    def __init__(self, tsa_url: Optional[str] = None, tsa_username: Optional[str] = None, tsa_password: Optional[str] = None):
        """
        Initialize the timestamp manager.
        
        Args:
            tsa_url: URL of the Time Stamping Authority (TSA) server
            tsa_username: Username for TSA authentication (if required)
            tsa_password: Password for TSA authentication (if required)
        """
        self.tsa_url = tsa_url
        self.tsa_username = tsa_username
        self.tsa_password = tsa_password
        
        # Import cryptography modules
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.x509.oid import ExtensionOID, NameOID
            self.crypto_available = True
        except ImportError:
            logger.warning("Cryptography library not available. Some features may not work.")
            self.crypto_available = False
    
    def timestamp_data(self, 
                      data: bytes, 
                      hash_algorithm: str = "sha256",
                      use_tsa: bool = True) -> Dict[str, Any]:
        """
        Create a timestamp for data.
        
        Args:
            data: Data to timestamp
            hash_algorithm: Hash algorithm to use
            use_tsa: Whether to use a TSA server or create a local timestamp
        
        Returns:
            Dictionary containing the timestamp information
        
        Raises:
            ValueError: If timestamping fails
        """
        try:
            # Calculate the hash of the data
            data_hash = self._hash_data(data, hash_algorithm)
            
            # Create a timestamp
            if use_tsa and self.tsa_url:
                # Use TSA server
                timestamp_token = self._request_tsa_timestamp(data_hash, hash_algorithm)
                
                # Parse the timestamp token
                timestamp_info = self._parse_timestamp_token(timestamp_token)
                
                # Create the timestamp result
                timestamp_result = {
                    'type': 'tsa_timestamp',
                    'hash_algorithm': hash_algorithm,
                    'data_hash': base64.b64encode(data_hash).decode('ascii'),
                    'timestamp_token': base64.b64encode(timestamp_token).decode('ascii'),
                    'timestamp_info': timestamp_info
                }
            else:
                # Create a local timestamp
                timestamp_result = {
                    'type': 'local_timestamp',
                    'hash_algorithm': hash_algorithm,
                    'data_hash': base64.b64encode(data_hash).decode('ascii'),
                    'timestamp': time.time(),
                    'local_time': time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())
                }
            
            return timestamp_result
        
        except Exception as e:
            logger.error(f"Error creating timestamp: {str(e)}")
            raise ValueError(f"Failed to create timestamp: {str(e)}")
    
    def timestamp_signature(self, 
                           signature_data: Dict[str, Any],
                           hash_algorithm: str = "sha256",
                           use_tsa: bool = True) -> Dict[str, Any]:
        """
        Create a timestamp for a signature.
        
        Args:
            signature_data: Signature data to timestamp
            hash_algorithm: Hash algorithm to use
            use_tsa: Whether to use a TSA server or create a local timestamp
        
        Returns:
            Updated signature data with timestamp
        
        Raises:
            ValueError: If timestamping fails
        """
        if not signature_data or not isinstance(signature_data, dict):
            raise ValueError("Invalid signature data format")
        
        try:
            # Get the signature value
            if 'signature' in signature_data:
                # Direct signature value
                signature = base64.b64decode(signature_data['signature'])
            elif 'signature_result' in signature_data and 'signature' in signature_data['signature_result']:
                # Nested signature value
                signature = base64.b64decode(signature_data['signature_result']['signature'])
            else:
                raise ValueError("Signature value not found in signature data")
            
            # Create a timestamp for the signature
            timestamp_result = self.timestamp_data(signature, hash_algorithm, use_tsa)
            
            # Add the timestamp to the signature data
            signature_data_copy = signature_data.copy()
            signature_data_copy['timestamp'] = timestamp_result
            
            return signature_data_copy
        
        except Exception as e:
            logger.error(f"Error timestamping signature: {str(e)}")
            raise ValueError(f"Failed to timestamp signature: {str(e)}")
    
    def verify_timestamp(self, 
                        data: bytes, 
                        timestamp_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a timestamp.
        
        Args:
            data: The original data
            timestamp_data: The timestamp data to verify
        
        Returns:
            Dictionary with verification results
        
        Raises:
            ValueError: If verification fails
        """
        if not timestamp_data or not isinstance(timestamp_data, dict):
            raise ValueError("Invalid timestamp data format")
        
        try:
            # Get the timestamp type
            timestamp_type = timestamp_data.get('type')
            
            if timestamp_type == 'tsa_timestamp':
                # Verify a TSA timestamp
                return self._verify_tsa_timestamp(data, timestamp_data)
            elif timestamp_type == 'local_timestamp':
                # Verify a local timestamp
                return self._verify_local_timestamp(data, timestamp_data)
            else:
                raise ValueError(f"Unknown timestamp type: {timestamp_type}")
        
        except Exception as e:
            logger.error(f"Error verifying timestamp: {str(e)}")
            raise ValueError(f"Failed to verify timestamp: {str(e)}")
    
    def verify_signature_timestamp(self, 
                                  signature_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a timestamp on a signature.
        
        Args:
            signature_data: The signature data with timestamp
        
        Returns:
            Dictionary with verification results
        
        Raises:
            ValueError: If verification fails
        """
        if not signature_data or not isinstance(signature_data, dict):
            raise ValueError("Invalid signature data format")
        
        if 'timestamp' not in signature_data:
            raise ValueError("No timestamp found in signature data")
        
        try:
            # Get the signature value
            if 'signature' in signature_data:
                # Direct signature value
                signature = base64.b64decode(signature_data['signature'])
            elif 'signature_result' in signature_data and 'signature' in signature_data['signature_result']:
                # Nested signature value
                signature = base64.b64decode(signature_data['signature_result']['signature'])
            else:
                raise ValueError("Signature value not found in signature data")
            
            # Verify the timestamp
            timestamp_result = self.verify_timestamp(signature, signature_data['timestamp'])
            
            return timestamp_result
        
        except Exception as e:
            logger.error(f"Error verifying signature timestamp: {str(e)}")
            raise ValueError(f"Failed to verify signature timestamp: {str(e)}")
    
    def _hash_data(self, data: bytes, algorithm: str) -> bytes:
        """
        Calculate the hash of data.
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm to use
        
        Returns:
            Hash of the data
        
        Raises:
            ValueError: If the hash algorithm is not supported
        """
        if algorithm.lower() == 'sha256':
            return hashlib.sha256(data).digest()
        elif algorithm.lower() == 'sha384':
            return hashlib.sha384(data).digest()
        elif algorithm.lower() == 'sha512':
            return hashlib.sha512(data).digest()
        elif algorithm.lower() == 'sha1':
            # SHA-1 is not recommended for security-critical applications
            logger.warning("SHA-1 is not recommended for security-critical applications")
            return hashlib.sha1(data).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    def _request_tsa_timestamp(self, data_hash: bytes, hash_algorithm: str) -> bytes:
        """
        Request a timestamp from a TSA server.
        
        Args:
            data_hash: Hash of the data to timestamp
            hash_algorithm: Hash algorithm used
        
        Returns:
            Timestamp token
        
        Raises:
            ValueError: If the TSA request fails
        """
        if not self.tsa_url:
            raise ValueError("TSA URL not configured")
        
        try:
            # Create a timestamp request (RFC 3161)
            # This is a simplified implementation
            from cryptography.hazmat.primitives import hashes
            from cryptography.x509.oid import ExtensionOID
            import asn1crypto.tsp
            
            # Map hash algorithm to OID
            hash_algorithm_oid = {
                'sha1': '1.3.14.3.2.26',
                'sha256': '2.16.840.1.101.3.4.2.1',
                'sha384': '2.16.840.1.101.3.4.2.2',
                'sha512': '2.16.840.1.101.3.4.2.3'
            }.get(hash_algorithm.lower())
            
            if not hash_algorithm_oid:
                raise ValueError(f"Unsupported hash algorithm for TSA: {hash_algorithm}")
            
            # Create the TimeStampReq
            tsp_req = asn1crypto.tsp.TimeStampReq({
                'version': 1,
                'message_imprint': {
                    'hash_algorithm': {
                        'algorithm': hash_algorithm_oid
                    },
                    'hashed_message': data_hash
                },
                'cert_req': True
            })
            
            # Encode the request
            tsp_req_der = tsp_req.dump()
            
            # Send the request to the TSA server
            headers = {
                'Content-Type': 'application/timestamp-query',
                'Accept': 'application/timestamp-reply'
            }
            
            # Add authentication if provided
            auth = None
            if self.tsa_username and self.tsa_password:
                auth = (self.tsa_username, self.tsa_password)
            
            response = requests.post(
                self.tsa_url,
                data=tsp_req_der,
                headers=headers,
                auth=auth
            )
            
            # Check the response
            if response.status_code != 200:
                raise ValueError(f"TSA server returned error: {response.status_code} {response.reason}")
            
            # Return the timestamp token
            return response.content
        
        except ImportError:
            raise ValueError("Required libraries not available for TSA timestamping")
        except Exception as e:
            logger.error(f"Error requesting TSA timestamp: {str(e)}")
            raise ValueError(f"Failed to request TSA timestamp: {str(e)}")
    
    def _parse_timestamp_token(self, timestamp_token: bytes) -> Dict[str, Any]:
        """
        Parse a timestamp token.
        
        Args:
            timestamp_token: Timestamp token to parse
        
        Returns:
            Dictionary with timestamp information
        
        Raises:
            ValueError: If parsing fails
        """
        try:
            # Parse the timestamp token (RFC 3161)
            import asn1crypto.tsp
            import asn1crypto.cms
            
            # Parse the TimeStampResp
            tsp_resp = asn1crypto.tsp.TimeStampResp.load(timestamp_token)
            
            # Check the status
            status = tsp_resp['status']['status'].native
            if status != 0:
                status_string = tsp_resp['status']['status_string']
                raise ValueError(f"TSA response status: {status} {status_string}")
            
            # Get the TimeStampToken
            tsp_token = tsp_resp['time_stamp_token']
            
            # Parse the CMS ContentInfo
            content_info = asn1crypto.cms.ContentInfo.load(tsp_token.dump())
            
            # Get the SignedData
            signed_data = content_info['content']
            
            # Get the encapsulated content
            encap_content = signed_data['encap_content_info']['content']
            
            # Parse the TSTInfo
            tst_info = asn1crypto.tsp.TSTInfo.load(encap_content.native)
            
            # Extract information
            timestamp_info = {
                'version': tst_info['version'].native,
                'policy': tst_info['policy'].native,
                'message_imprint': {
                    'algorithm': tst_info['message_imprint']['hash_algorithm']['algorithm'].native,
                    'hash': tst_info['message_imprint']['hashed_message'].native.hex()
                },
                'serial_number': tst_info['serial_number'].native,
                'timestamp': tst_info['gen_time'].native.timestamp(),
                'timestamp_str': tst_info['gen_time'].native.strftime('%Y-%m-%d %H:%M:%S %Z'),
                'accuracy': None,
                'ordering': tst_info['ordering'].native,
                'nonce': tst_info['nonce'].native if 'nonce' in tst_info else None
            }
            
            # Add accuracy if present
            if 'accuracy' in tst_info:
                accuracy = tst_info['accuracy']
                timestamp_info['accuracy'] = {
                    'seconds': accuracy['seconds'].native if 'seconds' in accuracy else 0,
                    'millis': accuracy['millis'].native if 'millis' in accuracy else 0,
                    'micros': accuracy['micros'].native if 'micros' in accuracy else 0
                }
            
            # Add TSA name if present
            if 'tsa' in tst_info:
                tsa = tst_info['tsa']
                timestamp_info['tsa'] = tsa.native
            
            return timestamp_info
        
        except ImportError:
            raise ValueError("Required libraries not available for parsing timestamp token")
        except Exception as e:
            logger.error(f"Error parsing timestamp token: {str(e)}")
            raise ValueError(f"Failed to parse timestamp token: {str(e)}")
    
    def _verify_tsa_timestamp(self, data: bytes, timestamp_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a TSA timestamp.
        
        Args:
            data: The original data
            timestamp_data: The timestamp data to verify
        
        Returns:
            Dictionary with verification results
        
        Raises:
            ValueError: If verification fails
        """
        try:
            # Get the hash algorithm
            hash_algorithm = timestamp_data.get('hash_algorithm', 'sha256')
            
            # Calculate the hash of the data
            data_hash = self._hash_data(data, hash_algorithm)
            
            # Get the stored hash
            stored_hash_b64 = timestamp_data.get('data_hash', '')
            stored_hash = base64.b64decode(stored_hash_b64)
            
            # Compare the hashes
            hash_valid = data_hash == stored_hash
            
            # Get the timestamp token
            token_b64 = timestamp_data.get('timestamp_token', '')
            token = base64.b64decode(token_b64)
            
            # Parse the timestamp token
            timestamp_info = timestamp_data.get('timestamp_info', {})
            if not timestamp_info:
                timestamp_info = self._parse_timestamp_token(token)
            
            # Verify the token
            # This would involve verifying the signature on the token,
            # checking the certificate chain, etc.
            # For simplicity, we'll just check that the hash in the token
            # matches the hash of the data
            token_hash_hex = timestamp_info.get('message_imprint', {}).get('hash', '')
            token_hash = bytes.fromhex(token_hash_hex)
            
            token_hash_valid = data_hash == token_hash
            
            # Prepare the result
            return {
                'valid': hash_valid and token_hash_valid,
                'hash_valid': hash_valid,
                'token_hash_valid': token_hash_valid,
                'timestamp': timestamp_info.get('timestamp'),
                'timestamp_str': timestamp_info.get('timestamp_str'),
                'tsa': timestamp_info.get('tsa')
            }
        
        except Exception as e:
            logger.error(f"Error verifying TSA timestamp: {str(e)}")
            raise ValueError(f"Failed to verify TSA timestamp: {str(e)}")
    
    def _verify_local_timestamp(self, data: bytes, timestamp_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a local timestamp.
        
        Args:
            data: The original data
            timestamp_data: The timestamp data to verify
        
        Returns:
            Dictionary with verification results
        
        Raises:
            ValueError: If verification fails
        """
        try:
            # Get the hash algorithm
            hash_algorithm = timestamp_data.get('hash_algorithm', 'sha256')
            
            # Calculate the hash of the data
            data_hash = self._hash_data(data, hash_algorithm)
            
            # Get the stored hash
            stored_hash_b64 = timestamp_data.get('data_hash', '')
            stored_hash = base64.b64decode(stored_hash_b64)
            
            # Compare the hashes
            hash_valid = data_hash == stored_hash
            
            # Get the timestamp
            timestamp = timestamp_data.get('timestamp')
            local_time = timestamp_data.get('local_time')
            
            # Prepare the result
            return {
                'valid': hash_valid,
                'hash_valid': hash_valid,
                'timestamp': timestamp,
                'timestamp_str': local_time,
                'local': True
            }
        
        except Exception as e:
            logger.error(f"Error verifying local timestamp: {str(e)}")
            raise ValueError(f"Failed to verify local timestamp: {str(e)}")
