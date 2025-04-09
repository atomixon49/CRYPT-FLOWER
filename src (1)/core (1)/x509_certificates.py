"""
X.509 Certificate Module

This module provides functionality for working with X.509 certificates, including:
- Certificate generation
- Certificate signing requests (CSRs)
- Certificate validation
- Certificate chain verification
- Certificate revocation checking

It uses the cryptography library for X.509 operations.
"""

import os
import datetime
import ipaddress
from typing import List, Dict, Any, Optional, Tuple, Union
from pathlib import Path
import logging

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Configure logging
logger = logging.getLogger(__name__)

class X509CertificateManager:
    """
    Manages X.509 certificates and related operations.
    
    This class provides methods for:
    - Generating self-signed certificates
    - Creating certificate signing requests (CSRs)
    - Signing CSRs to create certificates
    - Validating certificates
    - Checking certificate revocation status
    """
    
    def __init__(self):
        """Initialize the X.509 certificate manager."""
        self.default_hash_algorithm = hashes.SHA256()
    
    def generate_self_signed_certificate(
        self,
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        common_name: str,
        organization: Optional[str] = None,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        valid_days: int = 365,
        dns_names: Optional[List[str]] = None,
        ip_addresses: Optional[List[str]] = None
    ) -> x509.Certificate:
        """
        Generate a self-signed X.509 certificate.
        
        Args:
            private_key: The private key to use for signing
            common_name: The common name (CN) for the certificate
            organization: The organization (O) for the certificate
            country: The country (C) for the certificate
            state: The state/province (ST) for the certificate
            locality: The locality (L) for the certificate
            valid_days: Number of days the certificate will be valid
            dns_names: List of DNS names to include as subject alternative names
            ip_addresses: List of IP addresses to include as subject alternative names
            
        Returns:
            A self-signed X.509 certificate
            
        Raises:
            ValueError: If the parameters are invalid
        """
        # Create a name for the certificate subject
        name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        
        if organization:
            name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if country:
            name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        if state:
            name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
            
        subject = x509.Name(name_attributes)
        
        # Create certificate builder
        now = datetime.datetime.utcnow()
        cert_builder = x509.CertificateBuilder(
            issuer_name=subject,  # Self-signed, so issuer = subject
            subject_name=subject,
            public_key=private_key.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=now,
            not_valid_after=now + datetime.timedelta(days=valid_days)
        )
        
        # Add basic constraints extension (CA=True for self-signed)
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        
        # Add key usage extension
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Add subject alternative names if provided
        san_list = []
        if dns_names:
            for dns_name in dns_names:
                san_list.append(x509.DNSName(dns_name))
        
        if ip_addresses:
            for ip_addr in ip_addresses:
                san_list.append(x509.IPAddress(ipaddress.ip_address(ip_addr)))
        
        if san_list:
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )
        
        # Sign the certificate with the private key
        certificate = cert_builder.sign(
            private_key=private_key,
            algorithm=self.default_hash_algorithm,
            backend=default_backend()
        )
        
        return certificate
    
    def create_certificate_signing_request(
        self,
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        common_name: str,
        organization: Optional[str] = None,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        dns_names: Optional[List[str]] = None,
        ip_addresses: Optional[List[str]] = None
    ) -> x509.CertificateSigningRequest:
        """
        Create a Certificate Signing Request (CSR).
        
        Args:
            private_key: The private key to use for signing
            common_name: The common name (CN) for the certificate
            organization: The organization (O) for the certificate
            country: The country (C) for the certificate
            state: The state/province (ST) for the certificate
            locality: The locality (L) for the certificate
            dns_names: List of DNS names to include as subject alternative names
            ip_addresses: List of IP addresses to include as subject alternative names
            
        Returns:
            A Certificate Signing Request (CSR)
            
        Raises:
            ValueError: If the parameters are invalid
        """
        # Create a name for the CSR subject
        name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        
        if organization:
            name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if country:
            name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        if state:
            name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
            
        subject = x509.Name(name_attributes)
        
        # Create CSR builder
        csr_builder = x509.CertificateSigningRequestBuilder(subject_name=subject)
        
        # Add subject alternative names if provided
        san_list = []
        if dns_names:
            for dns_name in dns_names:
                san_list.append(x509.DNSName(dns_name))
        
        if ip_addresses:
            for ip_addr in ip_addresses:
                san_list.append(x509.IPAddress(ipaddress.ip_address(ip_addr)))
        
        if san_list:
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )
        
        # Sign the CSR with the private key
        csr = csr_builder.sign(
            private_key=private_key,
            algorithm=self.default_hash_algorithm,
            backend=default_backend()
        )
        
        return csr
    
    def sign_certificate_request(
        self,
        csr: x509.CertificateSigningRequest,
        ca_private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        ca_certificate: x509.Certificate,
        valid_days: int = 365,
        is_ca: bool = False,
        path_length: Optional[int] = None
    ) -> x509.Certificate:
        """
        Sign a Certificate Signing Request (CSR) to create a certificate.
        
        Args:
            csr: The CSR to sign
            ca_private_key: The CA private key to use for signing
            ca_certificate: The CA certificate
            valid_days: Number of days the certificate will be valid
            is_ca: Whether the certificate is for a CA
            path_length: Maximum path length for CA certificates
            
        Returns:
            A signed X.509 certificate
            
        Raises:
            ValueError: If the parameters are invalid
        """
        # Verify the CSR signature
        if not self.verify_csr_signature(csr):
            raise ValueError("CSR signature is invalid")
        
        # Create certificate builder
        now = datetime.datetime.utcnow()
        cert_builder = x509.CertificateBuilder(
            issuer_name=ca_certificate.subject,
            subject_name=csr.subject,
            public_key=csr.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=now,
            not_valid_after=now + datetime.timedelta(days=valid_days)
        )
        
        # Add basic constraints extension
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length),
            critical=True
        )
        
        # Add key usage extension
        key_usage_params = {
            'digital_signature': True,
            'content_commitment': False,
            'key_encipherment': True,
            'data_encipherment': False,
            'key_agreement': False,
            'key_cert_sign': is_ca,
            'crl_sign': is_ca,
            'encipher_only': False,
            'decipher_only': False
        }
        
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(**key_usage_params),
            critical=True
        )
        
        # Copy extensions from CSR
        for extension in csr.extensions:
            cert_builder = cert_builder.add_extension(
                extension.value,
                critical=extension.critical
            )
        
        # Sign the certificate with the CA private key
        certificate = cert_builder.sign(
            private_key=ca_private_key,
            algorithm=self.default_hash_algorithm,
            backend=default_backend()
        )
        
        return certificate
    
    def verify_csr_signature(self, csr: x509.CertificateSigningRequest) -> bool:
        """
        Verify the signature on a Certificate Signing Request (CSR).
        
        Args:
            csr: The CSR to verify
            
        Returns:
            True if the signature is valid, False otherwise
        """
        try:
            csr.public_key().verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                csr.signature_hash_algorithm
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            logger.error(f"Error verifying CSR signature: {str(e)}")
            return False
    
    def verify_certificate_signature(
        self,
        certificate: x509.Certificate,
        issuer_certificate: x509.Certificate
    ) -> bool:
        """
        Verify the signature on a certificate.
        
        Args:
            certificate: The certificate to verify
            issuer_certificate: The issuer's certificate
            
        Returns:
            True if the signature is valid, False otherwise
        """
        try:
            issuer_public_key = issuer_certificate.public_key()
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            logger.error(f"Error verifying certificate signature: {str(e)}")
            return False
    
    def load_certificate_from_pem(self, pem_data: bytes) -> x509.Certificate:
        """
        Load a certificate from PEM-encoded data.
        
        Args:
            pem_data: PEM-encoded certificate data
            
        Returns:
            An X.509 certificate
            
        Raises:
            ValueError: If the PEM data is invalid
        """
        try:
            return x509.load_pem_x509_certificate(pem_data, default_backend())
        except Exception as e:
            raise ValueError(f"Invalid PEM certificate data: {str(e)}")
    
    def load_certificate_from_der(self, der_data: bytes) -> x509.Certificate:
        """
        Load a certificate from DER-encoded data.
        
        Args:
            der_data: DER-encoded certificate data
            
        Returns:
            An X.509 certificate
            
        Raises:
            ValueError: If the DER data is invalid
        """
        try:
            return x509.load_der_x509_certificate(der_data, default_backend())
        except Exception as e:
            raise ValueError(f"Invalid DER certificate data: {str(e)}")
    
    def load_csr_from_pem(self, pem_data: bytes) -> x509.CertificateSigningRequest:
        """
        Load a CSR from PEM-encoded data.
        
        Args:
            pem_data: PEM-encoded CSR data
            
        Returns:
            A Certificate Signing Request
            
        Raises:
            ValueError: If the PEM data is invalid
        """
        try:
            return x509.load_pem_x509_csr(pem_data, default_backend())
        except Exception as e:
            raise ValueError(f"Invalid PEM CSR data: {str(e)}")
    
    def certificate_to_pem(self, certificate: x509.Certificate) -> bytes:
        """
        Convert a certificate to PEM format.
        
        Args:
            certificate: The certificate to convert
            
        Returns:
            PEM-encoded certificate data
        """
        return certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )
    
    def certificate_to_der(self, certificate: x509.Certificate) -> bytes:
        """
        Convert a certificate to DER format.
        
        Args:
            certificate: The certificate to convert
            
        Returns:
            DER-encoded certificate data
        """
        return certificate.public_bytes(
            encoding=serialization.Encoding.DER
        )
    
    def csr_to_pem(self, csr: x509.CertificateSigningRequest) -> bytes:
        """
        Convert a CSR to PEM format.
        
        Args:
            csr: The CSR to convert
            
        Returns:
            PEM-encoded CSR data
        """
        return csr.public_bytes(
            encoding=serialization.Encoding.PEM
        )
    
    def get_certificate_info(self, certificate: x509.Certificate) -> Dict[str, Any]:
        """
        Get information about a certificate.
        
        Args:
            certificate: The certificate to get information about
            
        Returns:
            A dictionary with certificate information
        """
        # Extract subject information
        subject_info = {}
        for attr in certificate.subject:
            oid_name = attr.oid._name
            subject_info[oid_name] = attr.value
        
        # Extract issuer information
        issuer_info = {}
        for attr in certificate.issuer:
            oid_name = attr.oid._name
            issuer_info[oid_name] = attr.value
        
        # Extract extensions
        extensions = {}
        for ext in certificate.extensions:
            ext_name = ext.oid._name
            if ext_name == 'subjectAltName':
                san_values = []
                for san in ext.value:
                    if isinstance(san, x509.DNSName):
                        san_values.append(f"DNS:{san.value}")
                    elif isinstance(san, x509.IPAddress):
                        san_values.append(f"IP:{san.value}")
                extensions[ext_name] = san_values
            elif ext_name == 'basicConstraints':
                extensions[ext_name] = {
                    'ca': ext.value.ca,
                    'path_length': ext.value.path_length
                }
            else:
                extensions[ext_name] = str(ext.value)
        
        # Build the result
        return {
            'subject': subject_info,
            'issuer': issuer_info,
            'serial_number': certificate.serial_number,
            'not_valid_before': certificate.not_valid_before,
            'not_valid_after': certificate.not_valid_after,
            'extensions': extensions,
            'signature_algorithm': certificate.signature_algorithm_oid._name,
            'public_key_type': type(certificate.public_key()).__name__
        }
    
    def verify_certificate_chain(
        self,
        certificate: x509.Certificate,
        trusted_certs: List[x509.Certificate]
    ) -> bool:
        """
        Verify a certificate against a list of trusted certificates.
        
        Args:
            certificate: The certificate to verify
            trusted_certs: List of trusted certificates
            
        Returns:
            True if the certificate is valid, False otherwise
        """
        # Check if the certificate is in the trusted list
        for trusted_cert in trusted_certs:
            if certificate.subject == trusted_cert.subject:
                # Check if it's the same certificate
                if certificate == trusted_cert:
                    return True
        
        # Check if the certificate was issued by any of the trusted certificates
        for trusted_cert in trusted_certs:
            if certificate.issuer == trusted_cert.subject:
                # Verify the signature
                if self.verify_certificate_signature(certificate, trusted_cert):
                    # Check validity period
                    now = datetime.datetime.utcnow()
                    if certificate.not_valid_before <= now <= certificate.not_valid_after:
                        return True
        
        return False
    
    def check_certificate_revocation(
        self,
        certificate: x509.Certificate,
        crl_data: Optional[bytes] = None,
        ocsp_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check if a certificate has been revoked.
        
        Args:
            certificate: The certificate to check
            crl_data: Certificate Revocation List data (optional)
            ocsp_url: URL for OCSP checking (optional)
            
        Returns:
            A dictionary with revocation status information
        """
        result = {
            'revoked': False,
            'checked_crl': False,
            'checked_ocsp': False,
            'error': None
        }
        
        # Check CRL if provided
        if crl_data:
            try:
                crl = x509.load_der_x509_crl(crl_data, default_backend())
                result['checked_crl'] = True
                
                # Check if the certificate is in the CRL
                for revoked_cert in crl:
                    if revoked_cert.serial_number == certificate.serial_number:
                        result['revoked'] = True
                        result['revocation_date'] = revoked_cert.revocation_date
                        result['revocation_reason'] = revoked_cert.reason
                        return result
            except Exception as e:
                result['error'] = f"Error checking CRL: {str(e)}"
        
        # OCSP checking would be implemented here
        # This is a more complex implementation that would require
        # making HTTP requests to the OCSP responder
        
        return result
