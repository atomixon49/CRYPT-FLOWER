try:
    from src.core.x509_certificates import X509CertificateManager
    print("Successfully imported X509CertificateManager")
except ImportError as e:
    print(f"Failed to import X509CertificateManager: {str(e)}")

try:
    from cryptography import x509
    print("Successfully imported x509 from cryptography")
except ImportError as e:
    print(f"Failed to import x509 from cryptography: {str(e)}")
