"""
JSON Web Token (JWT) Interface Module.

This module provides functionality for working with JSON Web Tokens (JWT),
including JSON Web Encryption (JWE) and JSON Web Signature (JWS).
It supports standard JWT operations for interoperability with other systems.
"""

import os
import json
import time
import base64
import logging
from typing import Dict, Any, Optional, List, Union, Tuple

# Import JWT libraries
try:
    import jwt
    import jwcrypto.jwk as jwk
    import jwcrypto.jwe as jwe
    import jwcrypto.jws as jws
    from jwcrypto.common import json_encode, json_decode
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives import serialization
    JWT_SUPPORT = True
except ImportError:
    JWT_SUPPORT = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("jwt_interface")


class JWTError(Exception):
    """Exception raised for JWT related errors."""
    pass


class JWTInterface:
    """
    Interface for working with JSON Web Tokens (JWT).

    This class provides methods for creating and verifying JWTs,
    as well as encrypting and decrypting data using JWE and JWS.
    It supports interoperability with external systems through standard
    JWT formats and algorithms.
    """

    # Supported algorithms
    SUPPORTED_SIGNING_ALGORITHMS = [
        # RSA algorithms
        'RS256', 'RS384', 'RS512',  # RSASSA-PKCS1-v1_5 with SHA-256/384/512
        'PS256', 'PS384', 'PS512',  # RSASSA-PSS with SHA-256/384/512

        # ECDSA algorithms
        'ES256', 'ES384', 'ES512',  # ECDSA with SHA-256/384/512

        # HMAC algorithms
        'HS256', 'HS384', 'HS512',  # HMAC with SHA-256/384/512

        # EdDSA algorithms
        'EdDSA',  # Edwards-curve Digital Signature Algorithm
    ]

    SUPPORTED_KEY_ENCRYPTION_ALGORITHMS = [
        # RSA algorithms
        'RSA-OAEP', 'RSA-OAEP-256',  # RSAES OAEP using SHA-1/256 and MGF1
        'RSA1_5',  # RSAES-PKCS1-v1_5

        # ECDH algorithms
        'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',  # ECDH-ES with key wrapping

        # AES key wrapping
        'A128KW', 'A192KW', 'A256KW',  # AES key wrap with 128/192/256-bit key

        # Direct encryption
        'dir',  # Direct use of a shared symmetric key
    ]

    SUPPORTED_CONTENT_ENCRYPTION_ALGORITHMS = [
        # AES GCM
        'A128GCM', 'A192GCM', 'A256GCM',  # AES GCM with 128/192/256-bit key

        # AES CBC with HMAC
        'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',  # AES CBC with HMAC SHA-256/384/512
    ]

    def __init__(self, key_manager=None):
        """
        Initialize the JWT interface.

        Args:
            key_manager: Optional key manager to use for key operations

        Raises:
            JWTError: If JWT support is not available
        """
        if not JWT_SUPPORT:
            raise JWTError("JWT support is not available. Please install pyjwt and jwcrypto.")

        self.key_manager = key_manager

        # Check if post-quantum support is available
        self.pq_support = False
        try:
            from ..core.post_quantum import PostQuantumCrypto, PQ_KEM_ALGORITHMS, PQ_SIGN_ALGORITHMS
            self.pq_crypto = PostQuantumCrypto()
            self.pq_support = True

            # Add post-quantum algorithms to supported algorithms
            self.SUPPORTED_SIGNING_ALGORITHMS.extend(PQ_SIGN_ALGORITHMS)
            self.SUPPORTED_KEY_ENCRYPTION_ALGORITHMS.extend(PQ_KEM_ALGORITHMS)

            logger.info("Post-quantum cryptography support enabled for JWT operations")
        except ImportError:
            logger.info("Post-quantum cryptography support not available for JWT operations")

    def create_jwk(self, key: Any, kid: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a JSON Web Key (JWK) from a cryptographic key.

        Args:
            key: Cryptographic key (RSA, EC, or symmetric key)
            kid: Optional key ID

        Returns:
            JWK as a dictionary

        Raises:
            JWTError: If JWK creation fails
        """
        try:
            # Convert key to JWK
            if hasattr(key, 'private_bytes'):  # RSA or EC private key
                key_data = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                jwk_key = jwk.JWK.from_pem(key_data)
            elif hasattr(key, 'public_bytes'):  # RSA or EC public key
                key_data = key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                jwk_key = jwk.JWK.from_pem(key_data)
            elif isinstance(key, bytes):  # Symmetric key
                jwk_key = jwk.JWK(kty='oct', k=base64.urlsafe_b64encode(key).decode('utf-8').rstrip('='))
            else:
                raise JWTError(f"Unsupported key type: {type(key)}")

            # Set key ID if provided
            if kid:
                jwk_key.update({'kid': kid})

            # Return JWK as dictionary
            return json_decode(jwk_key.export())

        except Exception as e:
            raise JWTError(f"Failed to create JWK: {str(e)}")

    def create_jws(self,
                  payload: Union[Dict[str, Any], str, bytes],
                  key: Any,
                  algorithm: str = 'RS256',
                  headers: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a JSON Web Signature (JWS).

        Args:
            payload: Data to sign
            key: Key to use for signing
            algorithm: Signature algorithm to use
            headers: Optional additional headers

        Returns:
            JWS token as a string

        Raises:
            JWTError: If JWS creation fails
        """
        try:
            # Convert payload to JSON if it's a dictionary
            if isinstance(payload, dict):
                payload = json.dumps(payload)

            # Convert payload to bytes if it's a string
            if isinstance(payload, str):
                payload = payload.encode('utf-8')

            # Create JWK from key
            jwk_key = self._key_to_jwk(key)

            # Create JWS
            token = jws.JWS(payload)

            # Prepare headers
            all_headers = {'alg': algorithm}
            if headers:
                all_headers.update(headers)

            # Sign the token
            token.add_signature(jwk_key, None, all_headers)

            # Return the signed token
            return token.serialize()

        except Exception as e:
            raise JWTError(f"Failed to create JWS: {str(e)}")

    def verify_jws(self,
                  token: str,
                  key: Any,
                  algorithms: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Verify a JSON Web Signature (JWS).

        Args:
            token: JWS token to verify
            key: Key to use for verification
            algorithms: List of allowed algorithms

        Returns:
            Dictionary with verification results:
            {
                'payload': bytes,  # The payload
                'headers': Dict[str, Any],  # The headers
                'valid': bool  # Whether the signature is valid
            }

        Raises:
            JWTError: If JWS verification fails
        """
        try:
            # Create JWK from key
            jwk_key = self._key_to_jwk(key)

            # Create JWS
            token_obj = jws.JWS()

            # Verify the token
            try:
                token_obj.deserialize(token)
                token_obj.verify(jwk_key, algorithms)
                valid = True
            except Exception as e:
                logger.warning(f"JWS verification failed: {str(e)}")
                valid = False

            # Get payload and headers
            payload = token_obj.payload
            headers = token_obj.jose_header

            return {
                'payload': payload,
                'headers': headers,
                'valid': valid
            }

        except Exception as e:
            raise JWTError(f"Failed to verify JWS: {str(e)}")

    def create_jwe(self,
                  payload: Union[Dict[str, Any], str, bytes],
                  key: Any,
                  algorithm: str = 'RSA-OAEP',
                  encryption: str = 'A256GCM',
                  headers: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a JSON Web Encryption (JWE).

        Args:
            payload: Data to encrypt
            key: Key to use for encryption
            algorithm: Key encryption algorithm to use
            encryption: Content encryption algorithm to use
            headers: Optional additional headers

        Returns:
            JWE token as a string

        Raises:
            JWTError: If JWE creation fails
        """
        try:
            # Convert payload to JSON if it's a dictionary
            if isinstance(payload, dict):
                payload = json.dumps(payload)

            # Convert payload to bytes if it's a string
            if isinstance(payload, str):
                payload = payload.encode('utf-8')

            # Create JWK from key
            jwk_key = self._key_to_jwk(key)

            # Create JWE
            token = jwe.JWE(payload)

            # Prepare headers
            all_headers = {
                'alg': algorithm,
                'enc': encryption
            }
            if headers:
                all_headers.update(headers)

            # Encrypt the token
            token.add_recipient(jwk_key, all_headers)

            # Return the encrypted token
            return token.serialize()

        except Exception as e:
            raise JWTError(f"Failed to create JWE: {str(e)}")

    def decrypt_jwe(self,
                   token: str,
                   key: Any) -> Dict[str, Any]:
        """
        Decrypt a JSON Web Encryption (JWE).

        Args:
            token: JWE token to decrypt
            key: Key to use for decryption

        Returns:
            Dictionary with decryption results:
            {
                'payload': bytes,  # The decrypted payload
                'headers': Dict[str, Any]  # The headers
            }

        Raises:
            JWTError: If JWE decryption fails
        """
        try:
            # Create JWK from key
            jwk_key = self._key_to_jwk(key)

            # Create JWE
            token_obj = jwe.JWE()

            # Decrypt the token
            token_obj.deserialize(token)
            token_obj.decrypt(jwk_key)

            # Get payload and headers
            payload = token_obj.payload
            headers = token_obj.jose_header

            return {
                'payload': payload,
                'headers': headers
            }

        except Exception as e:
            raise JWTError(f"Failed to decrypt JWE: {str(e)}")

    def create_jwt(self,
                  payload: Dict[str, Any],
                  key: Any,
                  algorithm: str = 'RS256',
                  expiration: Optional[int] = None,
                  not_before: Optional[int] = None,
                  headers: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a JSON Web Token (JWT).

        Args:
            payload: Claims to include in the token
            key: Key to use for signing
            algorithm: Signature algorithm to use
            expiration: Optional expiration time (in seconds from now)
            not_before: Optional not-before time (in seconds from now)
            headers: Optional additional headers

        Returns:
            JWT token as a string

        Raises:
            JWTError: If JWT creation fails
        """
        try:
            # Add standard claims if not present
            if 'iat' not in payload:
                payload['iat'] = int(time.time())

            if expiration is not None and 'exp' not in payload:
                payload['exp'] = int(time.time()) + expiration

            if not_before is not None and 'nbf' not in payload:
                payload['nbf'] = int(time.time()) + not_before

            # Create JWT
            token = jwt.encode(
                payload=payload,
                key=key,
                algorithm=algorithm,
                headers=headers
            )

            return token

        except Exception as e:
            raise JWTError(f"Failed to create JWT: {str(e)}")

    def verify_jwt(self,
                  token: str,
                  key: Any,
                  algorithms: Optional[List[str]] = None,
                  audience: Optional[str] = None,
                  issuer: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify a JSON Web Token (JWT).

        Args:
            token: JWT token to verify
            key: Key to use for verification
            algorithms: List of allowed algorithms
            audience: Expected audience
            issuer: Expected issuer

        Returns:
            Dictionary with the decoded payload

        Raises:
            JWTError: If JWT verification fails
        """
        try:
            # Set default algorithms if not provided
            if algorithms is None:
                algorithms = ['RS256', 'HS256']

            # Verify and decode the token
            payload = jwt.decode(
                jwt=token,
                key=key,
                algorithms=algorithms,
                audience=audience,
                issuer=issuer
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise JWTError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise JWTError(f"Invalid token: {str(e)}")
        except Exception as e:
            raise JWTError(f"Failed to verify JWT: {str(e)}")

    def _key_to_jwk(self, key: Any) -> jwk.JWK:
        """
        Convert a cryptographic key to a JWK.

        Args:
            key: Cryptographic key (RSA, EC, or symmetric key)

        Returns:
            JWK object

        Raises:
            JWTError: If key conversion fails
        """
        try:
            # Check if the key is already a JWK
            if isinstance(key, jwk.JWK):
                return key

            # Check if the key is a JWK dictionary
            if isinstance(key, dict) and 'kty' in key:
                return jwk.JWK(**key)

            # Convert key to JWK
            if hasattr(key, 'private_bytes'):  # RSA or EC private key
                key_data = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                return jwk.JWK.from_pem(key_data)
            elif hasattr(key, 'public_bytes'):  # RSA or EC public key
                key_data = key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                return jwk.JWK.from_pem(key_data)
            elif isinstance(key, bytes):  # Symmetric key
                return jwk.JWK(kty='oct', k=base64.urlsafe_b64encode(key).decode('utf-8').rstrip('='))
            elif isinstance(key, str):  # PEM string
                return jwk.JWK.from_pem(key.encode('utf-8'))
            else:
                raise JWTError(f"Unsupported key type: {type(key)}")

        except Exception as e:
            raise JWTError(f"Failed to convert key to JWK: {str(e)}")

    def jwk_to_pem(self, jwk_data: Union[Dict[str, Any], str]) -> bytes:
        """
        Convert a JWK to PEM format.

        Args:
            jwk_data: JWK as a dictionary or JSON string

        Returns:
            PEM-encoded key as bytes

        Raises:
            JWTError: If JWK conversion fails
        """
        try:
            # Convert JSON string to dictionary if needed
            if isinstance(jwk_data, str):
                jwk_data = json.loads(jwk_data)

            # Create JWK object
            jwk_key = jwk.JWK(**jwk_data)

            # Export to PEM
            if jwk_data.get('kty') == 'RSA':
                if 'd' in jwk_data:  # Private key
                    return jwk_key.export_to_pem(private_key=True, password=None)
                else:  # Public key
                    return jwk_key.export_to_pem()
            elif jwk_data.get('kty') == 'EC':
                if 'd' in jwk_data:  # Private key
                    return jwk_key.export_to_pem(private_key=True, password=None)
                else:  # Public key
                    return jwk_key.export_to_pem()
            elif jwk_data.get('kty') == 'oct':
                # Symmetric keys don't have a standard PEM format
                # Return the raw key bytes
                k = jwk_data.get('k', '')
                # Add padding if needed
                padding = '=' * (4 - len(k) % 4) if len(k) % 4 else ''
                return base64.urlsafe_b64decode(k + padding)
            else:
                raise JWTError(f"Unsupported key type: {jwk_data.get('kty')}")

        except Exception as e:
            raise JWTError(f"Failed to convert JWK to PEM: {str(e)}")

    def create_jwks(self, keys: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create a JWK Set (JWKS) from a list of JWKs.

        Args:
            keys: List of JWKs as dictionaries

        Returns:
            JWKS as a dictionary

        Raises:
            JWTError: If JWKS creation fails
        """
        try:
            return {
                'keys': keys
            }

        except Exception as e:
            raise JWTError(f"Failed to create JWKS: {str(e)}")

    def find_key_in_jwks(self,
                        jwks: Dict[str, Any],
                        kid: Optional[str] = None,
                        kty: Optional[str] = None,
                        use: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Find a key in a JWK Set (JWKS).

        Args:
            jwks: JWKS as a dictionary
            kid: Optional key ID to match
            kty: Optional key type to match
            use: Optional key use to match

        Returns:
            Matching JWK as a dictionary, or None if not found

        Raises:
            JWTError: If JWKS search fails
        """
        try:
            # Get the keys from the JWKS
            keys = jwks.get('keys', [])

            # Find a matching key
            for key in keys:
                if kid and key.get('kid') != kid:
                    continue

                if kty and key.get('kty') != kty:
                    continue

                if use and key.get('use') != use:
                    continue

                return key

            return None

        except Exception as e:
            raise JWTError(f"Failed to find key in JWKS: {str(e)}")

    def get_token_header(self, token: str) -> Dict[str, Any]:
        """
        Get the header of a JWT, JWS, or JWE token.

        Args:
            token: Token to parse

        Returns:
            Token header as a dictionary

        Raises:
            JWTError: If token parsing fails
        """
        try:
            # Split the token
            parts = token.split('.')

            # JWT and JWS have 3 parts, JWE has 5 parts
            if len(parts) not in [3, 5]:
                raise JWTError("Invalid token format")

            # Decode the header
            header_b64 = parts[0]

            # Add padding if needed
            padding = '=' * (4 - len(header_b64) % 4) if len(header_b64) % 4 else ''

            # Decode and parse the header
            header_json = base64.urlsafe_b64decode(header_b64 + padding).decode('utf-8')
            header = json.loads(header_json)

            return header

        except Exception as e:
            raise JWTError(f"Failed to get token header: {str(e)}")

    def is_token_encrypted(self, token: str) -> bool:
        """
        Check if a token is encrypted (JWE).

        Args:
            token: Token to check

        Returns:
            True if the token is encrypted, False otherwise

        Raises:
            JWTError: If token parsing fails
        """
        try:
            # Get the token header
            header = self.get_token_header(token)

            # Check if the token has an encryption algorithm
            return 'enc' in header

        except Exception as e:
            raise JWTError(f"Failed to check if token is encrypted: {str(e)}")

    def get_token_claims(self, token: str) -> Dict[str, Any]:
        """
        Get the claims of a JWT or JWS token (without verification).

        Args:
            token: Token to parse

        Returns:
            Token claims as a dictionary

        Raises:
            JWTError: If token parsing fails or the token is encrypted
        """
        try:
            # Check if the token is encrypted
            if self.is_token_encrypted(token):
                raise JWTError("Cannot get claims from encrypted token without decryption")

            # Split the token
            parts = token.split('.')

            # JWT and JWS have 3 parts
            if len(parts) != 3:
                raise JWTError("Invalid token format")

            # Decode the payload
            payload_b64 = parts[1]

            # Add padding if needed
            padding = '=' * (4 - len(payload_b64) % 4) if len(payload_b64) % 4 else ''

            # Decode and parse the payload
            payload_json = base64.urlsafe_b64decode(payload_b64 + padding).decode('utf-8')
            payload = json.loads(payload_json)

            return payload

        except Exception as e:
            raise JWTError(f"Failed to get token claims: {str(e)}")

    def validate_token_structure(self, token: str) -> Dict[str, Any]:
        """
        Validate the structure of a JWT, JWS, or JWE token (without verification).

        Args:
            token: Token to validate

        Returns:
            Dictionary with validation results:
            {
                'valid': bool,  # Whether the token structure is valid
                'type': str,  # 'JWT', 'JWS', or 'JWE'
                'header': Dict[str, Any],  # The token header
                'errors': List[str]  # List of error messages if any
            }

        Raises:
            JWTError: If token validation fails
        """
        try:
            # Initialize result
            result = {
                'valid': True,
                'type': None,
                'header': None,
                'errors': []
            }

            # Split the token
            parts = token.split('.')

            # Check the number of parts
            if len(parts) == 3:
                # JWT or JWS
                result['type'] = 'JWT/JWS'
            elif len(parts) == 5:
                # JWE
                result['type'] = 'JWE'
            else:
                result['valid'] = False
                result['errors'].append(f"Invalid token format: expected 3 or 5 parts, got {len(parts)}")
                return result

            # Try to decode the header
            try:
                header_b64 = parts[0]

                # Add padding if needed
                padding = '=' * (4 - len(header_b64) % 4) if len(header_b64) % 4 else ''

                # Decode and parse the header
                header_json = base64.urlsafe_b64decode(header_b64 + padding).decode('utf-8')
                header = json.loads(header_json)

                result['header'] = header

                # Check required header fields
                if 'alg' not in header:
                    result['valid'] = False
                    result['errors'].append("Missing 'alg' in header")

                if result['type'] == 'JWE' and 'enc' not in header:
                    result['valid'] = False
                    result['errors'].append("Missing 'enc' in JWE header")

            except Exception as e:
                result['valid'] = False
                result['errors'].append(f"Failed to decode header: {str(e)}")

            # If it's a JWT/JWS, try to decode the payload
            if result['type'] == 'JWT/JWS' and result['valid']:
                try:
                    payload_b64 = parts[1]

                    # Add padding if needed
                    padding = '=' * (4 - len(payload_b64) % 4) if len(payload_b64) % 4 else ''

                    # Decode the payload
                    base64.urlsafe_b64decode(payload_b64 + padding)

                except Exception as e:
                    result['valid'] = False
                    result['errors'].append(f"Failed to decode payload: {str(e)}")

            return result

        except Exception as e:
            raise JWTError(f"Failed to validate token structure: {str(e)}")

    def get_key_thumbprint(self, jwk_data: Dict[str, Any], hash_algorithm: str = 'SHA-256') -> str:
        """
        Calculate the thumbprint of a JWK.

        Args:
            jwk_data: JWK as a dictionary
            hash_algorithm: Hash algorithm to use

        Returns:
            Base64url-encoded thumbprint

        Raises:
            JWTError: If thumbprint calculation fails
        """
        try:
            # Create JWK object
            jwk_key = jwk.JWK(**jwk_data)

            # Calculate thumbprint
            if hash_algorithm == 'SHA-256':
                thumbprint = jwk_key.thumbprint()
            elif hash_algorithm == 'SHA-1':
                thumbprint = jwk_key.thumbprint(hash_function='SHA-1')
            elif hash_algorithm == 'SHA-384':
                thumbprint = jwk_key.thumbprint(hash_function='SHA-384')
            elif hash_algorithm == 'SHA-512':
                thumbprint = jwk_key.thumbprint(hash_function='SHA-512')
            else:
                raise JWTError(f"Unsupported hash algorithm: {hash_algorithm}")

            return thumbprint

        except Exception as e:
            raise JWTError(f"Failed to calculate key thumbprint: {str(e)}")

    # Key Management Integration Methods

    def get_key_from_manager(self, key_id: str) -> Any:
        """
        Get a key from the key manager.

        Args:
            key_id: ID of the key to retrieve

        Returns:
            The key if found, None otherwise

        Raises:
            JWTError: If the key manager is not available
        """
        if not self.key_manager:
            raise JWTError("Key manager not available")

        try:
            return self.key_manager.get_key(key_id)
        except Exception as e:
            raise JWTError(f"Failed to get key from key manager: {str(e)}")

    def create_jws_with_key_id(self,
                              payload: Union[Dict[str, Any], str, bytes],
                              key_id: str,
                              algorithm: str = 'RS256',
                              headers: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a JWS using a key from the key manager.

        Args:
            payload: Data to sign
            key_id: ID of the key to use for signing
            algorithm: Signature algorithm to use
            headers: Optional additional headers

        Returns:
            JWS token as a string

        Raises:
            JWTError: If JWS creation fails
        """
        # Get the key from the key manager
        key = self.get_key_from_manager(key_id)
        if not key:
            raise JWTError(f"Key not found: {key_id}")

        # Add key ID to headers
        all_headers = headers or {}
        all_headers['kid'] = key_id

        # Create JWS
        return self.create_jws(payload, key, algorithm, all_headers)

    def verify_jws_with_key_id(self,
                              token: str,
                              key_id: str,
                              algorithms: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Verify a JWS using a key from the key manager.

        Args:
            token: JWS token to verify
            key_id: ID of the key to use for verification
            algorithms: List of allowed algorithms

        Returns:
            Dictionary with verification results

        Raises:
            JWTError: If JWS verification fails
        """
        # Get the key from the key manager
        key = self.get_key_from_manager(key_id)
        if not key:
            raise JWTError(f"Key not found: {key_id}")

        # Verify JWS
        return self.verify_jws(token, key, algorithms)

    def create_jwe_with_key_id(self,
                              payload: Union[Dict[str, Any], str, bytes],
                              key_id: str,
                              algorithm: str = 'RSA-OAEP',
                              encryption: str = 'A256GCM',
                              headers: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a JWE using a key from the key manager.

        Args:
            payload: Data to encrypt
            key_id: ID of the key to use for encryption
            algorithm: Key encryption algorithm to use
            encryption: Content encryption algorithm to use
            headers: Optional additional headers

        Returns:
            JWE token as a string

        Raises:
            JWTError: If JWE creation fails
        """
        # Get the key from the key manager
        key = self.get_key_from_manager(key_id)
        if not key:
            raise JWTError(f"Key not found: {key_id}")

        # Add key ID to headers
        all_headers = headers or {}
        all_headers['kid'] = key_id

        # Create JWE
        return self.create_jwe(payload, key, algorithm, encryption, all_headers)

    def decrypt_jwe_with_key_id(self,
                               token: str,
                               key_id: str) -> Dict[str, Any]:
        """
        Decrypt a JWE using a key from the key manager.

        Args:
            token: JWE token to decrypt
            key_id: ID of the key to use for decryption

        Returns:
            Dictionary with decryption results

        Raises:
            JWTError: If JWE decryption fails
        """
        # Get the key from the key manager
        key = self.get_key_from_manager(key_id)
        if not key:
            raise JWTError(f"Key not found: {key_id}")

        # Decrypt JWE
        return self.decrypt_jwe(token, key)

    # Post-Quantum Support Methods

    def is_post_quantum_algorithm(self, algorithm: str) -> bool:
        """
        Check if an algorithm is a post-quantum algorithm.

        Args:
            algorithm: Algorithm to check

        Returns:
            True if the algorithm is a post-quantum algorithm, False otherwise
        """
        if not self.pq_support:
            return False

        try:
            from ..core.post_quantum import PQ_KEM_ALGORITHMS, PQ_SIGN_ALGORITHMS
            return algorithm in PQ_KEM_ALGORITHMS or algorithm in PQ_SIGN_ALGORITHMS
        except ImportError:
            return False

    def create_pq_jws(self,
                     payload: Union[Dict[str, Any], str, bytes],
                     key: Any,
                     algorithm: str,
                     headers: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a JWS using a post-quantum signature algorithm.

        Args:
            payload: Data to sign
            key: Key to use for signing
            algorithm: Post-quantum signature algorithm to use
            headers: Optional additional headers

        Returns:
            JWS token as a string

        Raises:
            JWTError: If JWS creation fails or post-quantum support is not available
        """
        if not self.pq_support:
            raise JWTError("Post-quantum support not available")

        try:
            # Convert payload to bytes if needed
            if isinstance(payload, dict):
                payload_bytes = json.dumps(payload).encode('utf-8')
            elif isinstance(payload, str):
                payload_bytes = payload.encode('utf-8')
            else:
                payload_bytes = payload

            # Sign the payload using post-quantum algorithm
            signature = self.pq_crypto.sign(payload_bytes, key, algorithm)

            # Create a JWS-like structure manually
            # Header
            header = {'alg': algorithm, 'pq': True}
            if headers:
                header.update(headers)

            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode('utf-8')).decode('utf-8').rstrip('=')

            # Payload
            if isinstance(payload, dict):
                payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').rstrip('=')
            elif isinstance(payload, str):
                payload_b64 = base64.urlsafe_b64encode(payload.encode('utf-8')).decode('utf-8').rstrip('=')
            else:
                payload_b64 = base64.urlsafe_b64encode(payload).decode('utf-8').rstrip('=')

            # Signature
            signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

            # Combine to form JWS
            return f"{header_b64}.{payload_b64}.{signature_b64}"

        except Exception as e:
            raise JWTError(f"Failed to create post-quantum JWS: {str(e)}")

    def verify_pq_jws(self,
                     token: str,
                     key: Any,
                     algorithms: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Verify a JWS created with a post-quantum signature algorithm.

        Args:
            token: JWS token to verify
            key: Key to use for verification
            algorithms: List of allowed algorithms

        Returns:
            Dictionary with verification results

        Raises:
            JWTError: If JWS verification fails or post-quantum support is not available
        """
        if not self.pq_support:
            raise JWTError("Post-quantum support not available")

        try:
            # Split the token
            parts = token.split('.')
            if len(parts) != 3:
                raise JWTError("Invalid token format")

            # Decode the header
            header_b64 = parts[0]
            padding = '=' * (4 - len(header_b64) % 4) if len(header_b64) % 4 else ''
            header_json = base64.urlsafe_b64decode(header_b64 + padding).decode('utf-8')
            header = json.loads(header_json)

            # Check if it's a post-quantum token
            if not header.get('pq', False):
                raise JWTError("Not a post-quantum token")

            # Get the algorithm
            algorithm = header.get('alg')
            if not algorithm:
                raise JWTError("Missing algorithm in header")

            # Check if the algorithm is allowed
            if algorithms and algorithm not in algorithms:
                raise JWTError(f"Algorithm not allowed: {algorithm}")

            # Decode the payload
            payload_b64 = parts[1]
            padding = '=' * (4 - len(payload_b64) % 4) if len(payload_b64) % 4 else ''
            payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)

            # Decode the signature
            signature_b64 = parts[2]
            padding = '=' * (4 - len(signature_b64) % 4) if len(signature_b64) % 4 else ''
            signature = base64.urlsafe_b64decode(signature_b64 + padding)

            # Verify the signature
            valid = self.pq_crypto.verify(payload_bytes, signature, key, algorithm)

            # Try to parse the payload as JSON
            try:
                payload = json.loads(payload_bytes.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = payload_bytes

            return {
                'payload': payload,
                'headers': header,
                'valid': valid
            }

        except Exception as e:
            raise JWTError(f"Failed to verify post-quantum JWS: {str(e)}")
