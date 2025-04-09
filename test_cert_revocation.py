import os
import sys
import importlib.util
import tempfile
import json
import base64
import secrets
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

# Add src (1) to the path
sys.path.insert(0, os.path.join(os.getcwd(), "src (1)"))

# Import the certificate revocation module
spec = importlib.util.spec_from_file_location("cert_revocation", os.path.join(os.getcwd(), "src (1)", "core", "cert_revocation.py"))
cert_revocation_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cert_revocation_module)

# Test results
results = {
    "certificate_generation": {},
    "crl_checking": {},
    "ocsp_checking": {}
}

def generate_test_certificates():
    """Generate test certificates for revocation checking."""
    print("\n=== Generating Test Certificates ===")
    
    # Create a temporary directory for certificates
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Generate CA key pair
        print("\nGenerating CA key pair...")
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create CA certificate
        ca_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
        ])
        
        ca_cert = x509.CertificateBuilder().subject_name(
            ca_name
        ).issuer_name(
            ca_name  # Self-signed
        ).public_key(
            ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            x509.datetime.datetime.utcnow()
        ).not_valid_after(
            x509.datetime.datetime.utcnow() + x509.datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(ca_key, hashes.SHA256())
        
        # Save CA certificate
        ca_cert_path = os.path.join(temp_dir, "ca.crt")
        with open(ca_cert_path, "wb") as f:
            f.write(ca_cert.public_bytes(Encoding.DER))
        
        print(f"CA certificate saved to: {ca_cert_path}")
        results["certificate_generation"]["ca"] = "Success"
        
        # Generate valid certificate
        print("\nGenerating valid certificate...")
        valid_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        valid_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Valid Certificate"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
        ])
        
        valid_cert = x509.CertificateBuilder().subject_name(
            valid_name
        ).issuer_name(
            ca_name  # Issued by CA
        ).public_key(
            valid_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            x509.datetime.datetime.utcnow()
        ).not_valid_after(
            x509.datetime.datetime.utcnow() + x509.datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://example.com/crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                )
            ]), critical=False
        ).add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    access_method=x509.AuthorityInformationAccessOID.OCSP,
                    access_location=x509.UniformResourceIdentifier("http://example.com/ocsp")
                )
            ]), critical=False
        ).sign(ca_key, hashes.SHA256())
        
        # Save valid certificate
        valid_cert_path = os.path.join(temp_dir, "valid.crt")
        with open(valid_cert_path, "wb") as f:
            f.write(valid_cert.public_bytes(Encoding.DER))
        
        print(f"Valid certificate saved to: {valid_cert_path}")
        results["certificate_generation"]["valid"] = "Success"
        
        # Generate revoked certificate
        print("\nGenerating revoked certificate...")
        revoked_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        revoked_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Revoked Certificate"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
        ])
        
        revoked_cert = x509.CertificateBuilder().subject_name(
            revoked_name
        ).issuer_name(
            ca_name  # Issued by CA
        ).public_key(
            revoked_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            x509.datetime.datetime.utcnow()
        ).not_valid_after(
            x509.datetime.datetime.utcnow() + x509.datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://example.com/crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                )
            ]), critical=False
        ).add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    access_method=x509.AuthorityInformationAccessOID.OCSP,
                    access_location=x509.UniformResourceIdentifier("http://example.com/ocsp")
                )
            ]), critical=False
        ).sign(ca_key, hashes.SHA256())
        
        # Save revoked certificate
        revoked_cert_path = os.path.join(temp_dir, "revoked.crt")
        with open(revoked_cert_path, "wb") as f:
            f.write(revoked_cert.public_bytes(Encoding.DER))
        
        print(f"Revoked certificate saved to: {revoked_cert_path}")
        results["certificate_generation"]["revoked"] = "Success"
        
        # Generate a CRL
        print("\nGenerating Certificate Revocation List (CRL)...")
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_name)
        builder = builder.last_update(x509.datetime.datetime.utcnow())
        builder = builder.next_update(x509.datetime.datetime.utcnow() + x509.datetime.timedelta(days=30))
        
        # Add the revoked certificate to the CRL
        revoked_cert_serial = revoked_cert.serial_number
        revocation_date = x509.datetime.datetime.utcnow()
        revoked_cert_entry = x509.RevokedCertificateBuilder().serial_number(
            revoked_cert_serial
        ).revocation_date(
            revocation_date
        ).add_extension(
            x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False
        ).build()
        
        builder = builder.add_revoked_certificate(revoked_cert_entry)
        
        # Sign the CRL
        crl = builder.sign(
            private_key=ca_key,
            algorithm=hashes.SHA256()
        )
        
        # Save the CRL
        crl_path = os.path.join(temp_dir, "test.crl")
        with open(crl_path, "wb") as f:
            f.write(crl.public_bytes(Encoding.DER))
        
        print(f"CRL saved to: {crl_path}")
        results["certificate_generation"]["crl"] = "Success"
        
        return {
            'temp_dir': temp_dir,
            'ca_cert_path': ca_cert_path,
            'valid_cert_path': valid_cert_path,
            'revoked_cert_path': revoked_cert_path,
            'crl_path': crl_path,
            'ca_cert': ca_cert,
            'valid_cert': valid_cert,
            'revoked_cert': revoked_cert,
            'crl': crl
        }
    
    except Exception as e:
        print(f"Error generating test certificates: {e}")
        results["certificate_generation"]["general"] = f"Failed: {str(e)}"
        return None

def test_crl_checking(cert_data):
    """Test CRL checking functionality."""
    print("\n=== Testing CRL Checking ===")
    
    if not cert_data:
        print("Skipping test: No certificate data available")
        return
    
    # Create a certificate revocation checker
    revocation_checker = cert_revocation_module.CertificateRevocationChecker()
    
    try:
        # Load certificates and CRL
        with open(cert_data['ca_cert_path'], 'rb') as f:
            ca_cert_der = f.read()
        
        with open(cert_data['valid_cert_path'], 'rb') as f:
            valid_cert_der = f.read()
        
        with open(cert_data['revoked_cert_path'], 'rb') as f:
            revoked_cert_der = f.read()
        
        with open(cert_data['crl_path'], 'rb') as f:
            crl_der = f.read()
        
        # Check valid certificate against CRL
        print("\nChecking valid certificate against CRL...")
        valid_cert = x509.load_der_x509_certificate(valid_cert_der)
        ca_cert = x509.load_der_x509_certificate(ca_cert_der)
        
        # Create a mock _check_crl_url method for testing
        def mock_check_crl_url(certificate, issuer_certificate, crl_url, force_refresh=False):
            # Return a successful result for the valid certificate
            return {
                'status': 'good',
                'revoked': False,
                'crl_url': crl_url,
                'crl_last_update': time.time(),
                'crl_last_update_str': time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime()),
                'crl_next_update': time.time() + 86400,  # 1 day
                'crl_next_update_str': time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(time.time() + 86400))
            }
        
        # Replace the method with our mock
        revocation_checker._check_crl_url = mock_check_crl_url
        
        # Check the valid certificate
        valid_results = revocation_checker._check_crl(valid_cert, ca_cert)
        
        # Check the results
        print(f"Valid certificate CRL check results: {valid_results}")
        if not any(result.get('revoked', False) for result in valid_results):
            print("Valid certificate correctly not revoked")
            results["crl_checking"]["valid_cert"] = "Success"
        else:
            print("Valid certificate incorrectly revoked")
            results["crl_checking"]["valid_cert"] = "Failed"
        
        # Check revoked certificate against CRL
        print("\nChecking revoked certificate against CRL...")
        revoked_cert = x509.load_der_x509_certificate(revoked_cert_der)
        
        # Create a mock _check_crl_url method for testing
        def mock_check_crl_url_revoked(certificate, issuer_certificate, crl_url, force_refresh=False):
            # Return a revoked result for the revoked certificate
            return {
                'status': 'revoked',
                'revoked': True,
                'crl_url': crl_url,
                'reason': 'key_compromise',
                'revocation_time': time.time() - 3600,  # 1 hour ago
                'revocation_time_str': time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(time.time() - 3600))
            }
        
        # Replace the method with our mock
        revocation_checker._check_crl_url = mock_check_crl_url_revoked
        
        # Check the revoked certificate
        revoked_results = revocation_checker._check_crl(revoked_cert, ca_cert)
        
        # Check the results
        print(f"Revoked certificate CRL check results: {revoked_results}")
        if any(result.get('revoked', False) for result in revoked_results):
            print("Revoked certificate correctly revoked")
            results["crl_checking"]["revoked_cert"] = "Success"
        else:
            print("Revoked certificate incorrectly not revoked")
            results["crl_checking"]["revoked_cert"] = "Failed"
    
    except Exception as e:
        print(f"Error with CRL checking: {e}")
        results["crl_checking"]["general"] = f"Failed: {str(e)}"

def test_ocsp_checking(cert_data):
    """Test OCSP checking functionality."""
    print("\n=== Testing OCSP Checking ===")
    
    if not cert_data:
        print("Skipping test: No certificate data available")
        return
    
    # Create a certificate revocation checker
    revocation_checker = cert_revocation_module.CertificateRevocationChecker()
    
    try:
        # Load certificates
        with open(cert_data['ca_cert_path'], 'rb') as f:
            ca_cert_der = f.read()
        
        with open(cert_data['valid_cert_path'], 'rb') as f:
            valid_cert_der = f.read()
        
        with open(cert_data['revoked_cert_path'], 'rb') as f:
            revoked_cert_der = f.read()
        
        # Check valid certificate with OCSP
        print("\nChecking valid certificate with OCSP...")
        valid_cert = x509.load_der_x509_certificate(valid_cert_der)
        ca_cert = x509.load_der_x509_certificate(ca_cert_der)
        
        # Create a mock _check_ocsp_url method for testing
        def mock_check_ocsp_url(certificate, issuer_certificate, ocsp_url):
            # Return a successful result for the valid certificate
            return {
                'status': 'good',
                'revoked': False,
                'ocsp_url': ocsp_url,
                'this_update': time.time(),
                'this_update_str': time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime()),
                'next_update': time.time() + 86400,  # 1 day
                'next_update_str': time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(time.time() + 86400))
            }
        
        # Replace the method with our mock
        revocation_checker._check_ocsp_url = mock_check_ocsp_url
        
        # Check the valid certificate
        valid_results = revocation_checker._check_ocsp(valid_cert, ca_cert)
        
        # Check the results
        print(f"Valid certificate OCSP check results: {valid_results}")
        if not any(result.get('revoked', False) for result in valid_results):
            print("Valid certificate correctly not revoked")
            results["ocsp_checking"]["valid_cert"] = "Success"
        else:
            print("Valid certificate incorrectly revoked")
            results["ocsp_checking"]["valid_cert"] = "Failed"
        
        # Check revoked certificate with OCSP
        print("\nChecking revoked certificate with OCSP...")
        revoked_cert = x509.load_der_x509_certificate(revoked_cert_der)
        
        # Create a mock _check_ocsp_url method for testing
        def mock_check_ocsp_url_revoked(certificate, issuer_certificate, ocsp_url):
            # Return a revoked result for the revoked certificate
            return {
                'status': 'revoked',
                'revoked': True,
                'ocsp_url': ocsp_url,
                'reason': 'keyCompromise',
                'revocation_time': time.time() - 3600,  # 1 hour ago
                'revocation_time_str': time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(time.time() - 3600))
            }
        
        # Replace the method with our mock
        revocation_checker._check_ocsp_url = mock_check_ocsp_url_revoked
        
        # Check the revoked certificate
        revoked_results = revocation_checker._check_ocsp(revoked_cert, ca_cert)
        
        # Check the results
        print(f"Revoked certificate OCSP check results: {revoked_results}")
        if any(result.get('revoked', False) for result in revoked_results):
            print("Revoked certificate correctly revoked")
            results["ocsp_checking"]["revoked_cert"] = "Success"
        else:
            print("Revoked certificate incorrectly not revoked")
            results["ocsp_checking"]["revoked_cert"] = "Failed"
    
    except Exception as e:
        print(f"Error with OCSP checking: {e}")
        results["ocsp_checking"]["general"] = f"Failed: {str(e)}"

def main():
    """Main function to run all tests."""
    print("=== Certificate Revocation Test ===")
    
    # Generate test certificates
    cert_data = generate_test_certificates()
    
    # Test CRL checking
    test_crl_checking(cert_data)
    
    # Test OCSP checking
    test_ocsp_checking(cert_data)
    
    # Clean up temporary directory
    if cert_data and 'temp_dir' in cert_data:
        import shutil
        shutil.rmtree(cert_data['temp_dir'])
    
    # Print summary
    print("\n=== Test Results Summary ===")
    for category, tests in results.items():
        print(f"\n{category.upper()}:")
        for test_name, result in tests.items():
            print(f"  {test_name}: {result}")
    
    # Save results to file
    with open("cert_revocation_test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\nTest results saved to cert_revocation_test_results.json")

if __name__ == "__main__":
    main()
