"""
Tests for the JWT interface module.
"""

import unittest
import os
import tempfile
import json
import base64
from datetime import datetime, timedelta

from src.core.key_management import KeyManager
from src.core.jwt_interface import JWTInterface, JWTError


class TestJWTInterface(unittest.TestCase):
    """Test cases for the JWT interface."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key_manager = KeyManager()
        
        # Check if JWT support is available
        try:
            self.jwt_interface = JWTInterface(key_manager=self.key_manager)
        except JWTError:
            self.skipTest("JWT support is not available")
        
        # Generate RSA key pair for testing
        self.public_key, self.private_key = self.key_manager.generate_asymmetric_keypair(
            algorithm='RSA',
            key_size=2048
        )
        
        # Generate symmetric key for testing
        self.symmetric_key = self.key_manager.generate_symmetric_key(
            algorithm='AES',
            key_size=256
        )
        
        # Test data
        self.test_payload = {
            'sub': 'test_user',
            'name': 'Test User',
            'admin': True,
            'iat': int(datetime.now().timestamp()),
            'exp': int((datetime.now() + timedelta(hours=1)).timestamp())
        }
    
    def test_create_jwk(self):
        """Test creating a JWK from a key."""
        # Create JWK from RSA private key
        jwk_private = self.jwt_interface.create_jwk(self.private_key, kid='test-key-1')
        
        # Check that the JWK has the expected properties
        self.assertEqual(jwk_private['kty'], 'RSA')
        self.assertEqual(jwk_private['kid'], 'test-key-1')
        self.assertIn('n', jwk_private)  # Modulus
        self.assertIn('e', jwk_private)  # Exponent
        self.assertIn('d', jwk_private)  # Private exponent
        
        # Create JWK from RSA public key
        jwk_public = self.jwt_interface.create_jwk(self.public_key, kid='test-key-2')
        
        # Check that the JWK has the expected properties
        self.assertEqual(jwk_public['kty'], 'RSA')
        self.assertEqual(jwk_public['kid'], 'test-key-2')
        self.assertIn('n', jwk_public)  # Modulus
        self.assertIn('e', jwk_public)  # Exponent
        self.assertNotIn('d', jwk_public)  # No private exponent
        
        # Create JWK from symmetric key
        jwk_symmetric = self.jwt_interface.create_jwk(self.symmetric_key, kid='test-key-3')
        
        # Check that the JWK has the expected properties
        self.assertEqual(jwk_symmetric['kty'], 'oct')
        self.assertEqual(jwk_symmetric['kid'], 'test-key-3')
        self.assertIn('k', jwk_symmetric)  # Key value
    
    def test_create_and_verify_jws(self):
        """Test creating and verifying a JWS."""
        # Create JWS
        jws_token = self.jwt_interface.create_jws(
            payload=self.test_payload,
            key=self.private_key,
            algorithm='RS256',
            headers={'kid': 'test-key-1'}
        )
        
        # Check that the token is a string
        self.assertIsInstance(jws_token, str)
        
        # Check that the token has three parts
        parts = jws_token.split('.')
        self.assertEqual(len(parts), 3)
        
        # Verify JWS
        result = self.jwt_interface.verify_jws(
            token=jws_token,
            key=self.public_key,
            algorithms=['RS256']
        )
        
        # Check that verification succeeded
        self.assertTrue(result['valid'])
        
        # Check that the payload matches
        payload = json.loads(result['payload'].decode('utf-8'))
        self.assertEqual(payload['sub'], self.test_payload['sub'])
        self.assertEqual(payload['name'], self.test_payload['name'])
        self.assertEqual(payload['admin'], self.test_payload['admin'])
    
    def test_create_and_decrypt_jwe(self):
        """Test creating and decrypting a JWE."""
        # Create JWE
        jwe_token = self.jwt_interface.create_jwe(
            payload=self.test_payload,
            key=self.public_key,
            algorithm='RSA-OAEP',
            encryption='A256GCM',
            headers={'kid': 'test-key-1'}
        )
        
        # Check that the token is a string
        self.assertIsInstance(jwe_token, str)
        
        # Check that the token has five parts
        parts = jwe_token.split('.')
        self.assertEqual(len(parts), 5)
        
        # Decrypt JWE
        result = self.jwt_interface.decrypt_jwe(
            token=jwe_token,
            key=self.private_key
        )
        
        # Check that decryption succeeded
        self.assertIn('payload', result)
        
        # Check that the payload matches
        payload = json.loads(result['payload'].decode('utf-8'))
        self.assertEqual(payload['sub'], self.test_payload['sub'])
        self.assertEqual(payload['name'], self.test_payload['name'])
        self.assertEqual(payload['admin'], self.test_payload['admin'])
    
    def test_create_and_verify_jwt(self):
        """Test creating and verifying a JWT."""
        # Create JWT
        jwt_token = self.jwt_interface.create_jwt(
            payload=self.test_payload,
            key=self.private_key,
            algorithm='RS256',
            headers={'kid': 'test-key-1'}
        )
        
        # Check that the token is a string
        self.assertIsInstance(jwt_token, str)
        
        # Check that the token has three parts
        parts = jwt_token.split('.')
        self.assertEqual(len(parts), 3)
        
        # Verify JWT
        payload = self.jwt_interface.verify_jwt(
            token=jwt_token,
            key=self.public_key,
            algorithms=['RS256']
        )
        
        # Check that the payload matches
        self.assertEqual(payload['sub'], self.test_payload['sub'])
        self.assertEqual(payload['name'], self.test_payload['name'])
        self.assertEqual(payload['admin'], self.test_payload['admin'])
    
    def test_key_management_integration(self):
        """Test integration with the key manager."""
        # Get the key IDs
        private_key_id = None
        public_key_id = None
        
        # Find the key IDs
        for key_id, key_info in self.key_manager.active_keys.items():
            if key_info.get('algorithm') == 'RSA':
                if key_id.endswith('.private'):
                    private_key_id = key_id
                elif key_id.endswith('.public'):
                    public_key_id = key_id
        
        # Skip if keys not found
        if not private_key_id or not public_key_id:
            self.skipTest("RSA keys not found in key manager")
        
        # Create JWS with key ID
        jws_token = self.jwt_interface.create_jws_with_key_id(
            payload=self.test_payload,
            key_id=private_key_id,
            algorithm='RS256'
        )
        
        # Verify JWS with key ID
        result = self.jwt_interface.verify_jws_with_key_id(
            token=jws_token,
            key_id=public_key_id,
            algorithms=['RS256']
        )
        
        # Check that verification succeeded
        self.assertTrue(result['valid'])
        
        # Create JWE with key ID
        jwe_token = self.jwt_interface.create_jwe_with_key_id(
            payload=self.test_payload,
            key_id=public_key_id,
            algorithm='RSA-OAEP',
            encryption='A256GCM'
        )
        
        # Decrypt JWE with key ID
        result = self.jwt_interface.decrypt_jwe_with_key_id(
            token=jwe_token,
            key_id=private_key_id
        )
        
        # Check that decryption succeeded
        self.assertIn('payload', result)
    
    def test_jwk_to_pem(self):
        """Test converting a JWK to PEM format."""
        # Create JWK from RSA private key
        jwk_private = self.jwt_interface.create_jwk(self.private_key)
        
        # Convert JWK to PEM
        pem_private = self.jwt_interface.jwk_to_pem(jwk_private)
        
        # Check that the PEM is bytes
        self.assertIsInstance(pem_private, bytes)
        
        # Check that the PEM starts with the expected header
        self.assertTrue(pem_private.startswith(b'-----BEGIN PRIVATE KEY-----'))
        
        # Create JWK from RSA public key
        jwk_public = self.jwt_interface.create_jwk(self.public_key)
        
        # Convert JWK to PEM
        pem_public = self.jwt_interface.jwk_to_pem(jwk_public)
        
        # Check that the PEM is bytes
        self.assertIsInstance(pem_public, bytes)
        
        # Check that the PEM starts with the expected header
        self.assertTrue(pem_public.startswith(b'-----BEGIN PUBLIC KEY-----'))
    
    def test_token_validation(self):
        """Test token validation."""
        # Create JWT
        jwt_token = self.jwt_interface.create_jwt(
            payload=self.test_payload,
            key=self.private_key,
            algorithm='RS256'
        )
        
        # Validate token structure
        result = self.jwt_interface.validate_token_structure(jwt_token)
        
        # Check that validation succeeded
        self.assertTrue(result['valid'])
        self.assertEqual(result['type'], 'JWT/JWS')
        self.assertEqual(result['header']['alg'], 'RS256')
        
        # Create JWE
        jwe_token = self.jwt_interface.create_jwe(
            payload=self.test_payload,
            key=self.public_key,
            algorithm='RSA-OAEP',
            encryption='A256GCM'
        )
        
        # Validate token structure
        result = self.jwt_interface.validate_token_structure(jwe_token)
        
        # Check that validation succeeded
        self.assertTrue(result['valid'])
        self.assertEqual(result['type'], 'JWE')
        self.assertEqual(result['header']['alg'], 'RSA-OAEP')
        self.assertEqual(result['header']['enc'], 'A256GCM')
    
    def test_get_token_header(self):
        """Test getting token header."""
        # Create JWT
        jwt_token = self.jwt_interface.create_jwt(
            payload=self.test_payload,
            key=self.private_key,
            algorithm='RS256',
            headers={'kid': 'test-key-1'}
        )
        
        # Get token header
        header = self.jwt_interface.get_token_header(jwt_token)
        
        # Check that the header has the expected properties
        self.assertEqual(header['alg'], 'RS256')
        self.assertEqual(header['kid'], 'test-key-1')
    
    def test_get_token_claims(self):
        """Test getting token claims."""
        # Create JWT
        jwt_token = self.jwt_interface.create_jwt(
            payload=self.test_payload,
            key=self.private_key,
            algorithm='RS256'
        )
        
        # Get token claims
        claims = self.jwt_interface.get_token_claims(jwt_token)
        
        # Check that the claims match
        self.assertEqual(claims['sub'], self.test_payload['sub'])
        self.assertEqual(claims['name'], self.test_payload['name'])
        self.assertEqual(claims['admin'], self.test_payload['admin'])
    
    def test_is_token_encrypted(self):
        """Test checking if a token is encrypted."""
        # Create JWT
        jwt_token = self.jwt_interface.create_jwt(
            payload=self.test_payload,
            key=self.private_key,
            algorithm='RS256'
        )
        
        # Check if token is encrypted
        is_encrypted = self.jwt_interface.is_token_encrypted(jwt_token)
        
        # Check that the token is not encrypted
        self.assertFalse(is_encrypted)
        
        # Create JWE
        jwe_token = self.jwt_interface.create_jwe(
            payload=self.test_payload,
            key=self.public_key,
            algorithm='RSA-OAEP',
            encryption='A256GCM'
        )
        
        # Check if token is encrypted
        is_encrypted = self.jwt_interface.is_token_encrypted(jwe_token)
        
        # Check that the token is encrypted
        self.assertTrue(is_encrypted)
    
    def test_get_key_thumbprint(self):
        """Test getting key thumbprint."""
        # Create JWK from RSA public key
        jwk_public = self.jwt_interface.create_jwk(self.public_key, kid='test-key-2')
        
        # Get key thumbprint
        thumbprint = self.jwt_interface.get_key_thumbprint(jwk_public)
        
        # Check that the thumbprint is a string
        self.assertIsInstance(thumbprint, str)
        
        # Check that the thumbprint is not empty
        self.assertTrue(thumbprint)


if __name__ == '__main__':
    unittest.main()
