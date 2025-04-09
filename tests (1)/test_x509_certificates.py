"""
Tests for X.509 certificate functionality.
"""

import unittest
import os
import tempfile
from datetime import datetime, timedelta

from src.core.key_management import KeyManager
from src.core.x509_certificates import X509CertificateManager

class TestX509Certificates(unittest.TestCase):
    """Test X.509 certificate functionality."""
    
    def setUp(self):
        """Set up the test environment."""
        self.key_manager = KeyManager()
        
        # Check if X.509 support is available
        if not hasattr(self.key_manager, 'x509_manager') or not self.key_manager.x509_manager:
            self.skipTest("X.509 certificate support is not available")
            
        # Generate RSA key pair for testing
        self.public_key, self.private_key = self.key_manager.generate_asymmetric_keypair(
            algorithm='RSA',
            key_size=2048
        )
        
        # Get the key ID
        self.key_ids = list(self.key_manager.active_keys.keys())
        self.private_key_id = [k for k in self.key_ids if k.endswith('.private')][0]
        
        # Test certificate parameters
        self.common_name = "test.example.com"
        self.organization = "Test Organization"
        self.country = "US"
        self.state = "California"
        self.locality = "San Francisco"
        self.dns_names = ["test1.example.com", "test2.example.com"]
        self.ip_addresses = ["192.168.1.1", "10.0.0.1"]
    
    def test_generate_self_signed_certificate(self):
        """Test generating a self-signed certificate."""
        # Generate a certificate
        cert_id = self.key_manager.generate_x509_certificate(
            private_key_id=self.private_key_id,
            common_name=self.common_name,
            organization=self.organization,
            country=self.country,
            state=self.state,
            locality=self.locality,
            valid_days=365,
            dns_names=self.dns_names,
            ip_addresses=self.ip_addresses
        )
        
        # Verify the certificate was created
        self.assertIsNotNone(cert_id)
        self.assertTrue(cert_id in self.key_manager.active_keys)
        
        # Verify certificate data
        cert_data = self.key_manager.active_keys[cert_id]
        self.assertEqual(cert_data['purpose'], 'x509_certificate')
        self.assertEqual(cert_data['key_type'], 'certificate')
        self.assertEqual(cert_data['subject']['common_name'], self.common_name)
        self.assertEqual(cert_data['subject']['organization'], self.organization)
        self.assertEqual(cert_data['subject']['country'], self.country)
        self.assertEqual(cert_data['subject']['state'], self.state)
        self.assertEqual(cert_data['subject']['locality'], self.locality)
        
        # Verify the certificate can be loaded
        certificate = self.key_manager.x509_manager.load_certificate_from_pem(cert_data['key'])
        self.assertIsNotNone(certificate)
        
        # Verify certificate info
        cert_info = self.key_manager.x509_manager.get_certificate_info(certificate)
        self.assertEqual(cert_info['subject'].get('commonName'), self.common_name)
        self.assertEqual(cert_info['subject'].get('organizationName'), self.organization)
        self.assertEqual(cert_info['subject'].get('countryName'), self.country)
        self.assertEqual(cert_info['subject'].get('stateOrProvinceName'), self.state)
        self.assertEqual(cert_info['subject'].get('localityName'), self.locality)
    
    def test_create_certificate_signing_request(self):
        """Test creating a certificate signing request (CSR)."""
        # Create a CSR
        csr_pem = self.key_manager.create_certificate_signing_request(
            private_key_id=self.private_key_id,
            common_name=self.common_name,
            organization=self.organization,
            country=self.country,
            state=self.state,
            locality=self.locality,
            dns_names=self.dns_names,
            ip_addresses=self.ip_addresses
        )
        
        # Verify the CSR was created
        self.assertIsNotNone(csr_pem)
        
        # Verify the CSR can be loaded
        csr = self.key_manager.x509_manager.load_csr_from_pem(csr_pem)
        self.assertIsNotNone(csr)
        
        # Verify CSR signature
        self.assertTrue(self.key_manager.x509_manager.verify_csr_signature(csr))
        
        # Get the CSR ID
        csr_id = f"{self.private_key_id.split('.')[0]}.csr"
        self.assertTrue(csr_id in self.key_manager.active_keys)
        
        # Verify CSR data
        csr_data = self.key_manager.active_keys[csr_id]
        self.assertEqual(csr_data['purpose'], 'certificate_signing_request')
        self.assertEqual(csr_data['key_type'], 'csr')
        self.assertEqual(csr_data['subject']['common_name'], self.common_name)
        self.assertEqual(csr_data['subject']['organization'], self.organization)
        self.assertEqual(csr_data['subject']['country'], self.country)
        self.assertEqual(csr_data['subject']['state'], self.state)
        self.assertEqual(csr_data['subject']['locality'], self.locality)
    
    def test_import_certificate(self):
        """Test importing a certificate."""
        # Generate a certificate
        cert_id = self.key_manager.generate_x509_certificate(
            private_key_id=self.private_key_id,
            common_name=self.common_name,
            organization=self.organization,
            country=self.country,
            state=self.state,
            locality=self.locality
        )
        
        # Get the certificate data
        cert_data = self.key_manager.active_keys[cert_id]['key']
        
        # Remove the certificate
        del self.key_manager.active_keys[cert_id]
        
        # Import the certificate
        imported_cert_id = self.key_manager.import_certificate(
            certificate_data=cert_data,
            key_id_base=self.private_key_id.split('.')[0]
        )
        
        # Verify the certificate was imported
        self.assertIsNotNone(imported_cert_id)
        self.assertTrue(imported_cert_id in self.key_manager.active_keys)
        
        # Verify certificate data
        imported_cert_data = self.key_manager.active_keys[imported_cert_id]
        self.assertEqual(imported_cert_data['purpose'], 'x509_certificate')
        self.assertEqual(imported_cert_data['key_type'], 'certificate')
        
        # Verify the certificate can be loaded
        certificate = self.key_manager.x509_manager.load_certificate_from_pem(imported_cert_data['key'])
        self.assertIsNotNone(certificate)
        
        # Verify certificate info
        cert_info = self.key_manager.x509_manager.get_certificate_info(certificate)
        self.assertEqual(cert_info['subject'].get('commonName'), self.common_name)
    
    def test_verify_certificate(self):
        """Test verifying a certificate."""
        # Generate a self-signed certificate
        cert_id = self.key_manager.generate_x509_certificate(
            private_key_id=self.private_key_id,
            common_name=self.common_name,
            organization=self.organization,
            country=self.country,
            state=self.state,
            locality=self.locality
        )
        
        # Verify the certificate against itself (self-signed)
        result = self.key_manager.verify_certificate(
            cert_id=cert_id,
            trusted_cert_ids=[cert_id]
        )
        
        # Verify the result
        self.assertTrue(result['valid'])
        self.assertTrue(result['chain_valid'])
        self.assertFalse(result['expired'])
        self.assertFalse(result['not_yet_valid'])
        
        # Verify subject information
        self.assertEqual(result['subject'].get('common_name'), self.common_name)
        self.assertEqual(result['subject'].get('organization'), self.organization)
        self.assertEqual(result['subject'].get('country'), self.country)
        self.assertEqual(result['subject'].get('state'), self.state)
        self.assertEqual(result['subject'].get('locality'), self.locality)

if __name__ == '__main__':
    unittest.main()
