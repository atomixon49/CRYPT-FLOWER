"""
Certificate Revocation Module

This module provides functionality for verifying the revocation status of X.509 certificates
using Certificate Revocation Lists (CRLs) and Online Certificate Status Protocol (OCSP).
"""

import os
import time
import logging
import requests
import tempfile
from typing import Dict, List, Any, Optional, Union, Tuple
from urllib.parse import urljoin

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cert_revocation")

class CertificateRevocationChecker:
    """
    Checks the revocation status of X.509 certificates.

    This class provides methods for:
    - Checking certificate revocation using CRLs
    - Checking certificate revocation using OCSP
    - Managing CRL caches
    """

    def __init__(self, cache_dir: Optional[str] = None, cache_timeout: int = 3600):
        """
        Initialize the certificate revocation checker.

        Args:
            cache_dir: Directory to use for caching CRLs (if None, a temporary directory will be used)
            cache_timeout: Time in seconds after which cached CRLs expire (default: 1 hour)
        """
        # Set up cache directory
        if cache_dir:
            self.cache_dir = cache_dir
            os.makedirs(cache_dir, exist_ok=True)
        else:
            self.cache_dir = tempfile.mkdtemp(prefix="crl_cache_")

        self.cache_timeout = cache_timeout

        # Dictionary to track CRL cache information
        self.crl_cache_info = {}

        # Import cryptography modules
        try:
            from cryptography import x509
            from cryptography.x509.oid import ExtensionOID
            from cryptography.hazmat.primitives import hashes
            self.crypto_available = True
        except ImportError:
            logger.warning("Cryptography library not available. Certificate revocation checking will not work.")
            self.crypto_available = False

    def check_revocation(self,
                        certificate: bytes,
                        issuer_certificate: Optional[bytes] = None,
                        check_crl: bool = True,
                        check_ocsp: bool = True,
                        force_refresh: bool = False) -> Dict[str, Any]:
        """
        Check the revocation status of a certificate.

        Args:
            certificate: The certificate to check (DER-encoded)
            issuer_certificate: The issuer's certificate (DER-encoded)
            check_crl: Whether to check CRLs
            check_ocsp: Whether to check OCSP
            force_refresh: Whether to force a refresh of cached CRLs

        Returns:
            Dictionary with revocation status information

        Raises:
            ValueError: If checking fails
        """
        if not self.crypto_available:
            raise ValueError("Cryptography library not available")

        try:
            from cryptography import x509
            from cryptography.x509.oid import ExtensionOID

            # Load the certificate
            cert = x509.load_der_x509_certificate(certificate)

            # Load the issuer certificate if provided
            issuer_cert = None
            if issuer_certificate:
                issuer_cert = x509.load_der_x509_certificate(issuer_certificate)

            # Initialize results
            results = {
                'revoked': False,
                'status': 'good',
                'crl_checked': False,
                'ocsp_checked': False,
                'crl_results': [],
                'ocsp_results': []
            }

            # Check CRLs if requested
            if check_crl:
                crl_results = self._check_crl(cert, issuer_cert, force_refresh)
                results['crl_checked'] = True
                results['crl_results'] = crl_results

                # If any CRL check indicates revocation, mark as revoked
                for result in crl_results:
                    if result.get('revoked'):
                        results['revoked'] = True
                        results['status'] = 'revoked'
                        results['revocation_reason'] = result.get('reason')
                        results['revocation_time'] = result.get('revocation_time')
                        break

            # Check OCSP if requested and not already revoked
            if check_ocsp and not results['revoked']:
                ocsp_results = self._check_ocsp(cert, issuer_cert)
                results['ocsp_checked'] = True
                results['ocsp_results'] = ocsp_results

                # If any OCSP check indicates revocation, mark as revoked
                for result in ocsp_results:
                    if result.get('revoked'):
                        results['revoked'] = True
                        results['status'] = 'revoked'
                        results['revocation_reason'] = result.get('reason')
                        results['revocation_time'] = result.get('revocation_time')
                        break

            # If no checks were performed, mark as unknown
            if not results['crl_checked'] and not results['ocsp_checked']:
                results['status'] = 'unknown'

            return results

        except Exception as e:
            logger.error(f"Error checking certificate revocation: {str(e)}")
            raise ValueError(f"Failed to check certificate revocation: {str(e)}")

    def _check_crl(self,
                  certificate: Any,
                  issuer_certificate: Optional[Any] = None,
                  force_refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Check the revocation status of a certificate using CRLs.

        Args:
            certificate: The certificate to check
            issuer_certificate: The issuer's certificate
            force_refresh: Whether to force a refresh of cached CRLs

        Returns:
            List of dictionaries with CRL check results
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import ExtensionOID

            # Get CRL distribution points from the certificate
            try:
                crl_dps = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.CRL_DISTRIBUTION_POINTS
                ).value
            except x509.ExtensionNotFound:
                return [{
                    'status': 'unknown',
                    'error': 'No CRL distribution points found in certificate'
                }]

            results = []

            # Check each CRL distribution point
            for dp in crl_dps:
                for full_name in dp.full_name:
                    if isinstance(full_name, x509.UniformResourceIdentifier):
                        crl_url = full_name.value

                        try:
                            # Download and check the CRL
                            result = self._check_crl_url(
                                certificate=certificate,
                                issuer_certificate=issuer_certificate,
                                crl_url=crl_url,
                                force_refresh=force_refresh
                            )

                            results.append(result)

                        except Exception as e:
                            results.append({
                                'status': 'error',
                                'crl_url': crl_url,
                                'error': str(e)
                            })

            return results

        except Exception as e:
            logger.error(f"Error checking CRLs: {str(e)}")
            return [{
                'status': 'error',
                'error': f"Failed to check CRLs: {str(e)}"
            }]

    def _check_crl_url(self,
                      certificate: Any,
                      issuer_certificate: Optional[Any],
                      crl_url: str,
                      force_refresh: bool = False) -> Dict[str, Any]:
        """
        Check a certificate against a specific CRL URL.

        Args:
            certificate: The certificate to check
            issuer_certificate: The issuer's certificate
            crl_url: URL of the CRL
            force_refresh: Whether to force a refresh of the cached CRL

        Returns:
            Dictionary with CRL check results
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import ExtensionOID
            from cryptography.hazmat.primitives.asymmetric import padding

            # Get the CRL (from cache or download)
            crl_data, crl_info = self._get_crl(crl_url, force_refresh)

            if not crl_data:
                return {
                    'status': 'error',
                    'crl_url': crl_url,
                    'error': 'Failed to retrieve CRL'
                }

            # Load the CRL
            crl = x509.load_der_x509_crl(crl_data)

            # Verify the CRL is signed by the issuer
            if issuer_certificate:
                try:
                    # Get the public key from the issuer certificate
                    issuer_public_key = issuer_certificate.public_key()

                    # Verify the CRL signature
                    issuer_public_key.verify(
                        crl.signature,
                        crl.tbs_certlist_bytes,
                        padding.PKCS1v15(),
                        crl.signature_hash_algorithm
                    )

                    # Signature verification successful
                    logger.debug(f"CRL signature verification successful for {crl_url}")
                except Exception as e:
                    logger.warning(f"CRL signature verification failed for {crl_url}: {str(e)}")
                    return {
                        'status': 'error',
                        'crl_url': crl_url,
                        'error': f"CRL signature verification failed: {str(e)}"
                    }

            # Check if the certificate is in the CRL
            cert_serial = certificate.serial_number

            for revoked_cert in crl:
                if revoked_cert.serial_number == cert_serial:
                    # Certificate is revoked
                    reason = None
                    try:
                        reason_ext = revoked_cert.extensions.get_extension_for_oid(
                            ExtensionOID.CRL_REASON
                        )
                        reason = reason_ext.value.reason.name
                    except x509.ExtensionNotFound:
                        pass

                    return {
                        'status': 'revoked',
                        'revoked': True,
                        'crl_url': crl_url,
                        'reason': reason,
                        'revocation_time': revoked_cert.revocation_date.timestamp(),
                        'revocation_time_str': revoked_cert.revocation_date.strftime('%Y-%m-%d %H:%M:%S %Z')
                    }

            # Certificate is not in the CRL
            return {
                'status': 'good',
                'revoked': False,
                'crl_url': crl_url,
                'crl_last_update': crl.last_update.timestamp(),
                'crl_last_update_str': crl.last_update.strftime('%Y-%m-%d %H:%M:%S %Z'),
                'crl_next_update': crl.next_update.timestamp() if crl.next_update else None,
                'crl_next_update_str': crl.next_update.strftime('%Y-%m-%d %H:%M:%S %Z') if crl.next_update else None
            }

        except Exception as e:
            logger.error(f"Error checking CRL URL {crl_url}: {str(e)}")
            return {
                'status': 'error',
                'crl_url': crl_url,
                'error': f"Failed to check CRL: {str(e)}"
            }

    def _get_crl(self, crl_url: str, force_refresh: bool = False) -> Tuple[Optional[bytes], Dict[str, Any]]:
        """
        Get a CRL from cache or download it.

        Args:
            crl_url: URL of the CRL
            force_refresh: Whether to force a refresh of the cached CRL

        Returns:
            Tuple of (CRL data, CRL info)
        """
        # Generate a cache filename from the URL
        import hashlib
        cache_filename = hashlib.md5(crl_url.encode()).hexdigest() + ".crl"
        cache_path = os.path.join(self.cache_dir, cache_filename)

        # Check if we have a cached CRL
        if os.path.exists(cache_path) and not force_refresh:
            # Check if the cache is still valid
            cache_info = self.crl_cache_info.get(crl_url, {})
            cache_time = cache_info.get('cache_time', 0)

            if time.time() - cache_time < self.cache_timeout:
                # Cache is still valid
                try:
                    with open(cache_path, 'rb') as f:
                        crl_data = f.read()

                    return crl_data, cache_info
                except Exception as e:
                    logger.warning(f"Error reading cached CRL: {str(e)}")

        # Download the CRL
        try:
            response = requests.get(crl_url, timeout=30)
            response.raise_for_status()

            crl_data = response.content

            # Save to cache
            with open(cache_path, 'wb') as f:
                f.write(crl_data)

            # Update cache info
            cache_info = {
                'url': crl_url,
                'cache_time': time.time(),
                'size': len(crl_data)
            }

            self.crl_cache_info[crl_url] = cache_info

            return crl_data, cache_info

        except Exception as e:
            logger.error(f"Error downloading CRL from {crl_url}: {str(e)}")
            return None, {'error': str(e)}

    def _check_ocsp(self,
                   certificate: Any,
                   issuer_certificate: Optional[Any] = None) -> List[Dict[str, Any]]:
        """
        Check the revocation status of a certificate using OCSP.

        Args:
            certificate: The certificate to check
            issuer_certificate: The issuer's certificate

        Returns:
            List of dictionaries with OCSP check results
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
            from cryptography.hazmat.primitives import serialization

            # Get OCSP responders from the certificate
            try:
                aia = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                ).value

                ocsp_responders = [
                    access.access_location.value
                    for access in aia
                    if access.access_method == AuthorityInformationAccessOID.OCSP
                ]

                if not ocsp_responders:
                    return [{
                        'status': 'unknown',
                        'error': 'No OCSP responders found in certificate'
                    }]

            except x509.ExtensionNotFound:
                return [{
                    'status': 'unknown',
                    'error': 'No Authority Information Access extension found in certificate'
                }]

            results = []

            # Check each OCSP responder
            for ocsp_url in ocsp_responders:
                try:
                    # Create and send OCSP request
                    result = self._check_ocsp_url(
                        certificate=certificate,
                        issuer_certificate=issuer_certificate,
                        ocsp_url=ocsp_url
                    )

                    results.append(result)

                except Exception as e:
                    results.append({
                        'status': 'error',
                        'ocsp_url': ocsp_url,
                        'error': str(e)
                    })

            return results

        except Exception as e:
            logger.error(f"Error checking OCSP: {str(e)}")
            return [{
                'status': 'error',
                'error': f"Failed to check OCSP: {str(e)}"
            }]

    def _check_ocsp_url(self,
                       certificate: Any,
                       issuer_certificate: Optional[Any],
                       ocsp_url: str) -> Dict[str, Any]:
        """
        Check a certificate against a specific OCSP responder.

        Args:
            certificate: The certificate to check
            issuer_certificate: The issuer's certificate
            ocsp_url: URL of the OCSP responder

        Returns:
            Dictionary with OCSP check results
        """
        try:
            from cryptography.x509.ocsp import OCSPRequestBuilder
            from cryptography.hazmat.primitives import hashes, serialization
            import asn1crypto.ocsp

            # We need the issuer certificate for OCSP
            if not issuer_certificate:
                return {
                    'status': 'error',
                    'ocsp_url': ocsp_url,
                    'error': 'Issuer certificate is required for OCSP checking'
                }

            # Create OCSP request
            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(certificate, issuer_certificate, hashes.SHA1())
            ocsp_request = builder.build()

            # Encode the request
            ocsp_request_der = ocsp_request.public_bytes(encoding=serialization.Encoding.DER)

            # Send the request to the OCSP responder
            headers = {
                'Content-Type': 'application/ocsp-request',
                'Accept': 'application/ocsp-response'
            }

            response = requests.post(
                ocsp_url,
                data=ocsp_request_der,
                headers=headers,
                timeout=30
            )

            # Check the response
            if response.status_code != 200:
                return {
                    'status': 'error',
                    'ocsp_url': ocsp_url,
                    'error': f"OCSP responder returned error: {response.status_code} {response.reason}"
                }

            # Parse the OCSP response
            try:
                ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)

                # Check the response status
                response_status = ocsp_response['response_status'].native
                if response_status != 'successful':
                    return {
                        'status': 'error',
                        'ocsp_url': ocsp_url,
                        'error': f"OCSP response status: {response_status}"
                    }
            except Exception as e:
                logger.error(f"Error parsing OCSP response from {ocsp_url}: {str(e)}")
                return {
                    'status': 'error',
                    'ocsp_url': ocsp_url,
                    'error': f"Failed to parse OCSP response: {str(e)}",
                    'response_content': response.content.hex()[:100] + '...' if len(response.content) > 100 else response.content.hex()
                }

            # Get the response data
            response_data = ocsp_response['response_bytes']['response'].parsed

            # Get the certificate status
            cert_status = response_data['tbs_response_data']['responses'][0]['cert_status'].name

            if cert_status == 'good':
                # Certificate is not revoked
                return {
                    'status': 'good',
                    'revoked': False,
                    'ocsp_url': ocsp_url,
                    'this_update': response_data['tbs_response_data']['responses'][0]['this_update'].native.timestamp(),
                    'this_update_str': response_data['tbs_response_data']['responses'][0]['this_update'].native.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    'next_update': response_data['tbs_response_data']['responses'][0]['next_update'].native.timestamp() if 'next_update' in response_data['tbs_response_data']['responses'][0] else None,
                    'next_update_str': response_data['tbs_response_data']['responses'][0]['next_update'].native.strftime('%Y-%m-%d %H:%M:%S %Z') if 'next_update' in response_data['tbs_response_data']['responses'][0] else None
                }

            elif cert_status == 'revoked':
                # Certificate is revoked
                revoked_info = response_data['tbs_response_data']['responses'][0]['cert_status'].chosen

                reason = None
                if 'revocation_reason' in revoked_info:
                    reason = revoked_info['revocation_reason'].native

                return {
                    'status': 'revoked',
                    'revoked': True,
                    'ocsp_url': ocsp_url,
                    'reason': reason,
                    'revocation_time': revoked_info['revocation_time'].native.timestamp(),
                    'revocation_time_str': revoked_info['revocation_time'].native.strftime('%Y-%m-%d %H:%M:%S %Z')
                }

            else:  # 'unknown'
                # Certificate status is unknown
                return {
                    'status': 'unknown',
                    'ocsp_url': ocsp_url
                }

        except Exception as e:
            logger.error(f"Error checking OCSP URL {ocsp_url}: {str(e)}")
            return {
                'status': 'error',
                'ocsp_url': ocsp_url,
                'error': f"Failed to check OCSP: {str(e)}"
            }

    def check_certificate_with_ocsp(self,
                               certificate: bytes,
                               issuer_certificate: bytes,
                               ocsp_url: str) -> Dict[str, Any]:
        """
        Check a certificate against a specific OCSP responder.

        Args:
            certificate: The certificate to check (DER-encoded)
            issuer_certificate: The issuer's certificate (DER-encoded)
            ocsp_url: URL of the OCSP responder

        Returns:
            Dictionary with check results

        Raises:
            ValueError: If checking fails
        """
        if not self.crypto_available:
            raise ValueError("Cryptography library not available")

        try:
            from cryptography import x509
            from cryptography.x509.ocsp import OCSPRequestBuilder
            from cryptography.hazmat.primitives import hashes, serialization
            import asn1crypto.ocsp

            # Load the certificate and issuer certificate
            cert = x509.load_der_x509_certificate(certificate)
            issuer_cert = x509.load_der_x509_certificate(issuer_certificate)

            # Create OCSP request
            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
            ocsp_request = builder.build()

            # Encode the request
            ocsp_request_der = ocsp_request.public_bytes(encoding=serialization.Encoding.DER)

            # Send the request to the OCSP responder
            headers = {
                'Content-Type': 'application/ocsp-request',
                'Accept': 'application/ocsp-response'
            }

            response = requests.post(
                ocsp_url,
                data=ocsp_request_der,
                headers=headers,
                timeout=30
            )

            # Check the response
            if response.status_code != 200:
                return {
                    'status': 'error',
                    'ocsp_url': ocsp_url,
                    'error': f"OCSP responder returned error: {response.status_code} {response.reason}"
                }

            # Parse the OCSP response
            try:
                ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)

                # Check the response status
                response_status = ocsp_response['response_status'].native
                if response_status != 'successful':
                    return {
                        'status': 'error',
                        'ocsp_url': ocsp_url,
                        'error': f"OCSP response status: {response_status}"
                    }
            except Exception as e:
                logger.error(f"Error parsing OCSP response from {ocsp_url}: {str(e)}")
                return {
                    'status': 'error',
                    'ocsp_url': ocsp_url,
                    'error': f"Failed to parse OCSP response: {str(e)}",
                    'response_content': response.content.hex()[:100] + '...' if len(response.content) > 100 else response.content.hex()
                }

            # Get the response data
            response_data = ocsp_response['response_bytes']['response'].parsed

            # Get the certificate status
            cert_status = response_data['tbs_response_data']['responses'][0]['cert_status'].name

            if cert_status == 'good':
                # Certificate is not revoked
                return {
                    'status': 'good',
                    'revoked': False,
                    'ocsp_url': ocsp_url,
                    'this_update': response_data['tbs_response_data']['responses'][0]['this_update'].native.timestamp(),
                    'this_update_str': response_data['tbs_response_data']['responses'][0]['this_update'].native.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    'next_update': response_data['tbs_response_data']['responses'][0]['next_update'].native.timestamp() if 'next_update' in response_data['tbs_response_data']['responses'][0] else None,
                    'next_update_str': response_data['tbs_response_data']['responses'][0]['next_update'].native.strftime('%Y-%m-%d %H:%M:%S %Z') if 'next_update' in response_data['tbs_response_data']['responses'][0] else None
                }

            elif cert_status == 'revoked':
                # Certificate is revoked
                revoked_info = response_data['tbs_response_data']['responses'][0]['cert_status'].chosen

                reason = None
                if 'revocation_reason' in revoked_info:
                    reason = revoked_info['revocation_reason'].native

                return {
                    'status': 'revoked',
                    'revoked': True,
                    'ocsp_url': ocsp_url,
                    'reason': reason,
                    'revocation_time': revoked_info['revocation_time'].native.timestamp(),
                    'revocation_time_str': revoked_info['revocation_time'].native.strftime('%Y-%m-%d %H:%M:%S %Z')
                }

            else:  # 'unknown'
                # Certificate status is unknown
                return {
                    'status': 'unknown',
                    'ocsp_url': ocsp_url
                }

        except Exception as e:
            logger.error(f"Error checking certificate with OCSP: {str(e)}")
            raise ValueError(f"Failed to check certificate with OCSP: {str(e)}")

    def clear_cache(self) -> None:
        """
        Clear the CRL cache.
        """
        try:
            # Remove all files in the cache directory
            for filename in os.listdir(self.cache_dir):
                file_path = os.path.join(self.cache_dir, filename)
                if os.path.isfile(file_path):
                    os.unlink(file_path)

            # Clear the cache info dictionary
            self.crl_cache_info = {}

            logger.info("CRL cache cleared")

        except Exception as e:
            logger.error(f"Error clearing CRL cache: {str(e)}")

    def check_certificate_against_crl(self,
                                 certificate: bytes,
                                 crl_data: bytes,
                                 issuer_certificate: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Check a certificate against a specific CRL provided as data.

        Args:
            certificate: The certificate to check (DER-encoded)
            crl_data: The CRL data (DER-encoded)
            issuer_certificate: The issuer's certificate (DER-encoded)

        Returns:
            Dictionary with check results

        Raises:
            ValueError: If checking fails
        """
        if not self.crypto_available:
            raise ValueError("Cryptography library not available")

        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import padding

            # Load the certificate
            cert = x509.load_der_x509_certificate(certificate)

            # Load the CRL
            crl = x509.load_der_x509_crl(crl_data)

            # Load the issuer certificate if provided
            issuer_cert = None
            if issuer_certificate:
                issuer_cert = x509.load_der_x509_certificate(issuer_certificate)

                # Verify the CRL is signed by the issuer
                try:
                    # Get the public key from the issuer certificate
                    issuer_public_key = issuer_cert.public_key()

                    # Verify the CRL signature
                    issuer_public_key.verify(
                        crl.signature,
                        crl.tbs_certlist_bytes,
                        padding.PKCS1v15(),
                        crl.signature_hash_algorithm
                    )
                except Exception as e:
                    logger.warning(f"CRL signature verification failed: {str(e)}")
                    return {
                        'status': 'error',
                        'error': f"CRL signature verification failed: {str(e)}"
                    }

            # Check if the certificate is in the CRL
            cert_serial = cert.serial_number

            for revoked_cert in crl:
                if revoked_cert.serial_number == cert_serial:
                    # Certificate is revoked
                    reason = None
                    try:
                        from cryptography.x509.oid import ExtensionOID
                        reason_ext = revoked_cert.extensions.get_extension_for_oid(
                            ExtensionOID.CRL_REASON
                        )
                        reason = reason_ext.value.reason.name
                    except x509.ExtensionNotFound:
                        pass

                    return {
                        'status': 'revoked',
                        'revoked': True,
                        'reason': reason,
                        'revocation_time': revoked_cert.revocation_date.timestamp(),
                        'revocation_time_str': revoked_cert.revocation_date.strftime('%Y-%m-%d %H:%M:%S %Z')
                    }

            # Certificate is not in the CRL
            return {
                'status': 'good',
                'revoked': False,
                'crl_last_update': crl.last_update.timestamp(),
                'crl_last_update_str': crl.last_update.strftime('%Y-%m-%d %H:%M:%S %Z'),
                'crl_next_update': crl.next_update.timestamp() if crl.next_update else None,
                'crl_next_update_str': crl.next_update.strftime('%Y-%m-%d %H:%M:%S %Z') if crl.next_update else None
            }

        except Exception as e:
            logger.error(f"Error checking certificate against CRL: {str(e)}")
            raise ValueError(f"Failed to check certificate against CRL: {str(e)}")

    def get_cache_info(self) -> Dict[str, Any]:
        """
        Get information about the CRL cache.

        Returns:
            Dictionary with cache information
        """
        try:
            # Count files and total size
            file_count = 0
            total_size = 0

            for filename in os.listdir(self.cache_dir):
                file_path = os.path.join(self.cache_dir, filename)
                if os.path.isfile(file_path):
                    file_count += 1
                    total_size += os.path.getsize(file_path)

            # Get cache entries
            cache_entries = []
            for url, info in self.crl_cache_info.items():
                cache_entries.append({
                    'url': url,
                    'cache_time': info.get('cache_time'),
                    'cache_time_str': time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(info.get('cache_time', 0))),
                    'size': info.get('size'),
                    'expires': info.get('cache_time', 0) + self.cache_timeout,
                    'expires_str': time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(info.get('cache_time', 0) + self.cache_timeout))
                })

            return {
                'cache_dir': self.cache_dir,
                'cache_timeout': self.cache_timeout,
                'file_count': file_count,
                'total_size': total_size,
                'cache_entries': cache_entries
            }

        except Exception as e:
            logger.error(f"Error getting cache info: {str(e)}")
            return {
                'error': f"Failed to get cache info: {str(e)}"
            }
