"""
Key Management Module

This module handles all aspects of cryptographic key management including:
- Key generation
- Key derivation
- Key storage
- Key rotation
"""

import os
import secrets
import base64
import hashlib
import time
import datetime
from typing import Tuple, Dict, Optional, Union, List, Any
from .key_storage import KeyStorage

# Try to import X.509 certificate module
try:
    from .x509_certificates import X509CertificateManager
    X509_AVAILABLE = True
except ImportError:
    X509_AVAILABLE = False

# Try to import post-quantum module
try:
    from .post_quantum import PostQuantumCrypto
    POSTQUANTUM_AVAILABLE = True
except ImportError:
    POSTQUANTUM_AVAILABLE = False

# Constants
KEY_SIZES = {
    'AES': [128, 192, 256],
    'ChaCha20': [256],
}

# Post-quantum algorithms
PQ_SIGN_ALGORITHMS = ['DILITHIUM2', 'DILITHIUM3', 'DILITHIUM5']
PQ_KEM_ALGORITHMS = ['KYBER512', 'KYBER768', 'KYBER1024']

# NTRU algorithms (will be added to PQ_KEM_ALGORITHMS if available)
NTRU_ALGORITHMS = ['NTRU-HPS-2048-509', 'NTRU-HPS-2048-677', 'NTRU-HPS-4096-821', 'NTRU-HRSS-701']

class KeyManager:
    """
    Manages cryptographic keys for the system.

    This class handles key generation, storage, retrieval, and rotation.
    It implements best practices for key management and provides a secure
    interface for other components to access keys.
    """

    def __init__(self, storage_path: Optional[str] = None, master_password: Optional[str] = None):
        """
        Initialize the KeyManager.

        Args:
            storage_path: Optional path to store keys. If None, uses default location.
            master_password: Master password for key storage. If None, keys will be ephemeral.
        """
        self.storage_path = storage_path
        self.active_keys: Dict[str, Dict] = {}
        self.key_storage = None
        self.persistent_storage = False

        # Initialize post-quantum crypto if available
        self.pq_crypto = None
        if POSTQUANTUM_AVAILABLE:
            try:
                self.pq_crypto = PostQuantumCrypto()

                # Add NTRU algorithms to PQ_KEM_ALGORITHMS if available
                global PQ_KEM_ALGORITHMS
                if hasattr(self.pq_crypto, 'NTRU_AVAILABLE') and getattr(self.pq_crypto, 'NTRU_AVAILABLE'):
                    # Make a copy to avoid modifying the original list
                    PQ_KEM_ALGORITHMS = PQ_KEM_ALGORITHMS + NTRU_ALGORITHMS
            except ImportError:
                # Post-quantum crypto is not available
                pass

        # Initialize X.509 certificate manager if available
        self.x509_manager = None
        if X509_AVAILABLE:
            try:
                self.x509_manager = X509CertificateManager()
            except ImportError:
                # X.509 certificate manager is not available
                pass

        # Initialize key storage if master password is provided
        if master_password:
            self.initialize_storage(master_password)

    def initialize_storage(self, master_password: str) -> bool:
        """
        Initialize the key storage with a master password.

        Args:
            master_password: Master password to protect the key storage

        Returns:
            True if successful, False otherwise
        """
        try:
            # Create key storage
            self.key_storage = KeyStorage(self.storage_path)

            # Check if storage exists
            if os.path.exists(self.key_storage.storage_path):
                # Load existing storage
                if self.key_storage.load_storage(master_password):
                    # Load keys into memory
                    for key_id, key_data in self.key_storage.keys.items():
                        self.active_keys[key_id] = key_data
                    self.persistent_storage = True
                    return True
                return False
            else:
                # Create new storage
                if self.key_storage.create_new_storage(master_password):
                    self.persistent_storage = True
                    return True
                return False
        except Exception as e:
            print(f"Failed to initialize key storage: {str(e)}")
            self.key_storage = None
            self.persistent_storage = False
            return False

    def generate_symmetric_key(self, algorithm: str = 'AES', key_size: int = 256) -> bytes:
        """
        Generate a new symmetric key.

        Args:
            algorithm: The algorithm to generate a key for ('AES' or 'ChaCha20')
            key_size: The size of the key in bits

        Returns:
            The generated key as bytes

        Raises:
            ValueError: If the algorithm or key size is not supported
        """
        if algorithm not in KEY_SIZES:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported algorithms: {list(KEY_SIZES.keys())}")

        if key_size not in KEY_SIZES[algorithm]:
            raise ValueError(f"Unsupported key size for {algorithm}: {key_size}. Supported sizes: {KEY_SIZES[algorithm]}")

        # Generate a cryptographically secure random key
        key_bytes = secrets.token_bytes(key_size // 8)

        # Store key metadata
        key_id = self._generate_key_id()
        key_data = {
            'algorithm': algorithm,
            'key_size': key_size,
            'created': time.time(),
            'key': key_bytes,
            'purpose': 'symmetric_encryption'
        }

        # Store in memory
        self.active_keys[key_id] = key_data

        # Store in persistent storage if available
        if self.persistent_storage and self.key_storage:
            self.key_storage.add_key(key_id, key_data)
            self.key_storage.save()

        return key_bytes

    def derive_key_from_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Derive a cryptographic key from a password.

        This is a placeholder implementation. In a real system, we would use a proper
        key derivation function like Argon2, PBKDF2, or scrypt with appropriate parameters.

        Args:
            password: The password to derive the key from
            salt: Optional salt. If None, a new random salt will be generated

        Returns:
            A tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(16)

        # This is a simplified implementation for demonstration
        # In production, use a proper KDF like Argon2
        derived_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations=100000,  # Minimum recommended iterations
            dklen=32  # 256 bits
        )

        return derived_key, salt

    def _generate_key_id(self) -> str:
        """
        Generate a unique identifier for a key.

        Returns:
            A unique key ID
        """
        # Generate a random ID and ensure it doesn't collide with existing IDs
        while True:
            key_id = base64.urlsafe_b64encode(os.urandom(16)).decode('ascii')
            if key_id not in self.active_keys:
                return key_id

    def generate_x509_certificate(self,
                                private_key_id: str,
                                common_name: str,
                                organization: Optional[str] = None,
                                country: Optional[str] = None,
                                state: Optional[str] = None,
                                locality: Optional[str] = None,
                                valid_days: int = 365,
                                dns_names: Optional[List[str]] = None,
                                ip_addresses: Optional[List[str]] = None) -> str:
        """
        Generate a self-signed X.509 certificate using an existing private key.

        Args:
            private_key_id: ID of the private key to use for signing
            common_name: The common name (CN) for the certificate
            organization: The organization (O) for the certificate
            country: The country (C) for the certificate
            state: The state/province (ST) for the certificate
            locality: The locality (L) for the certificate
            valid_days: Number of days the certificate will be valid
            dns_names: List of DNS names to include as subject alternative names
            ip_addresses: List of IP addresses to include as subject alternative names

        Returns:
            The ID of the generated certificate

        Raises:
            ValueError: If the private key doesn't exist or X.509 support is not available
        """
        if not X509_AVAILABLE or not self.x509_manager:
            raise ValueError("X.509 certificate support is not available")

        # Get the private key
        key_data = self.active_keys.get(private_key_id)
        if not key_data:
            raise ValueError(f"Private key with ID {private_key_id} not found")

        # Check if this is an RSA or ECC key
        algorithm = key_data.get('algorithm')
        if algorithm not in ['RSA', 'ECC']:
            raise ValueError(f"X.509 certificates can only be generated with RSA or ECC keys, not {algorithm}")

        # Load the private key
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.backends import default_backend
        private_key = load_pem_private_key(
            key_data['key'],
            password=None,
            backend=default_backend()
        )

        # Generate the certificate
        certificate = self.x509_manager.generate_self_signed_certificate(
            private_key=private_key,
            common_name=common_name,
            organization=organization,
            country=country,
            state=state,
            locality=locality,
            valid_days=valid_days,
            dns_names=dns_names,
            ip_addresses=ip_addresses
        )

        # Convert to PEM format
        cert_pem = self.x509_manager.certificate_to_pem(certificate)

        # Store the certificate
        cert_id = f"{key_data.get('key_id_base')}.cert"
        cert_data = {
            'algorithm': algorithm,
            'created': time.time(),
            'key': cert_pem,
            'purpose': 'x509_certificate',
            'key_type': 'certificate',
            'key_id_base': key_data.get('key_id_base'),
            'subject': {
                'common_name': common_name,
                'organization': organization,
                'country': country,
                'state': state,
                'locality': locality
            },
            'valid_days': valid_days,
            'not_valid_after': time.time() + (valid_days * 24 * 60 * 60)
        }

        # Store in memory
        self.active_keys[cert_id] = cert_data

        # Store in persistent storage if available
        if self.persistent_storage and self.key_storage:
            self.key_storage.add_key(cert_id, cert_data)
            self.key_storage.save()

        return cert_id

    def create_certificate_signing_request(self,
                                         private_key_id: str,
                                         common_name: str,
                                         organization: Optional[str] = None,
                                         country: Optional[str] = None,
                                         state: Optional[str] = None,
                                         locality: Optional[str] = None,
                                         dns_names: Optional[List[str]] = None,
                                         ip_addresses: Optional[List[str]] = None) -> bytes:
        """
        Create a Certificate Signing Request (CSR) using an existing private key.

        Args:
            private_key_id: ID of the private key to use for signing
            common_name: The common name (CN) for the certificate
            organization: The organization (O) for the certificate
            country: The country (C) for the certificate
            state: The state/province (ST) for the certificate
            locality: The locality (L) for the certificate
            dns_names: List of DNS names to include as subject alternative names
            ip_addresses: List of IP addresses to include as subject alternative names

        Returns:
            The CSR in PEM format

        Raises:
            ValueError: If the private key doesn't exist or X.509 support is not available
        """
        if not X509_AVAILABLE or not self.x509_manager:
            raise ValueError("X.509 certificate support is not available")

        # Get the private key
        key_data = self.active_keys.get(private_key_id)
        if not key_data:
            raise ValueError(f"Private key with ID {private_key_id} not found")

        # Check if this is an RSA or ECC key
        algorithm = key_data.get('algorithm')
        if algorithm not in ['RSA', 'ECC']:
            raise ValueError(f"X.509 CSRs can only be generated with RSA or ECC keys, not {algorithm}")

        # Load the private key
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.backends import default_backend
        private_key = load_pem_private_key(
            key_data['key'],
            password=None,
            backend=default_backend()
        )

        # Create the CSR
        csr = self.x509_manager.create_certificate_signing_request(
            private_key=private_key,
            common_name=common_name,
            organization=organization,
            country=country,
            state=state,
            locality=locality,
            dns_names=dns_names,
            ip_addresses=ip_addresses
        )

        # Convert to PEM format
        csr_pem = self.x509_manager.csr_to_pem(csr)

        # Store the CSR
        csr_id = f"{key_data.get('key_id_base')}.csr"
        csr_data = {
            'algorithm': algorithm,
            'created': time.time(),
            'key': csr_pem,
            'purpose': 'certificate_signing_request',
            'key_type': 'csr',
            'key_id_base': key_data.get('key_id_base'),
            'subject': {
                'common_name': common_name,
                'organization': organization,
                'country': country,
                'state': state,
                'locality': locality
            }
        }

        # Store in memory
        self.active_keys[csr_id] = csr_data

        # Store in persistent storage if available
        if self.persistent_storage and self.key_storage:
            self.key_storage.add_key(csr_id, csr_data)
            self.key_storage.save()

        return csr_pem

    def import_certificate(self, certificate_data: bytes, key_id_base: Optional[str] = None) -> str:
        """
        Import an X.509 certificate.

        Args:
            certificate_data: The certificate data in PEM or DER format
            key_id_base: Optional key ID base to associate with an existing key pair

        Returns:
            The ID of the imported certificate

        Raises:
            ValueError: If the certificate is invalid or X.509 support is not available
        """
        if not X509_AVAILABLE or not self.x509_manager:
            raise ValueError("X.509 certificate support is not available")

        # Try to load the certificate
        try:
            # Try PEM format first
            certificate = self.x509_manager.load_certificate_from_pem(certificate_data)
        except ValueError:
            try:
                # Try DER format
                certificate = self.x509_manager.load_certificate_from_der(certificate_data)
            except ValueError as e:
                raise ValueError(f"Invalid certificate data: {str(e)}")

        # Get certificate info
        cert_info = self.x509_manager.get_certificate_info(certificate)

        # Convert to PEM format for storage
        cert_pem = self.x509_manager.certificate_to_pem(certificate)

        # Generate a key ID if not provided
        if not key_id_base:
            key_id_base = self._generate_key_id()

        # Store the certificate
        cert_id = f"{key_id_base}.cert"
        cert_data = {
            'algorithm': 'X509',
            'created': time.time(),
            'key': cert_pem,
            'purpose': 'x509_certificate',
            'key_type': 'certificate',
            'key_id_base': key_id_base,
            'subject': cert_info['subject'],
            'issuer': cert_info['issuer'],
            'not_valid_before': cert_info['not_valid_before'].timestamp(),
            'not_valid_after': cert_info['not_valid_after'].timestamp(),
            'serial_number': cert_info['serial_number']
        }

        # Store in memory
        self.active_keys[cert_id] = cert_data

        # Store in persistent storage if available
        if self.persistent_storage and self.key_storage:
            self.key_storage.add_key(cert_id, cert_data)
            self.key_storage.save()

        return cert_id

    def verify_certificate(self, cert_id: str, trusted_cert_ids: List[str]) -> Dict[str, Any]:
        """
        Verify a certificate against a list of trusted certificates.

        Args:
            cert_id: ID of the certificate to verify
            trusted_cert_ids: List of trusted certificate IDs

        Returns:
            A dictionary with verification results

        Raises:
            ValueError: If the certificate doesn't exist or X.509 support is not available
        """
        if not X509_AVAILABLE or not self.x509_manager:
            raise ValueError("X.509 certificate support is not available")

        # Get the certificate
        cert_data = self.active_keys.get(cert_id)
        if not cert_data or cert_data.get('key_type') != 'certificate':
            raise ValueError(f"Certificate with ID {cert_id} not found")

        # Load the certificate
        certificate = self.x509_manager.load_certificate_from_pem(cert_data['key'])

        # Get the trusted certificates
        trusted_certs = []
        for trusted_id in trusted_cert_ids:
            trusted_data = self.active_keys.get(trusted_id)
            if trusted_data and trusted_data.get('key_type') == 'certificate':
                trusted_cert = self.x509_manager.load_certificate_from_pem(trusted_data['key'])
                trusted_certs.append(trusted_cert)

        # Verify the certificate
        is_valid = self.x509_manager.verify_certificate_chain(certificate, trusted_certs)

        # Check validity period
        now = time.time()
        is_expired = now > cert_data.get('not_valid_after', 0)
        is_not_yet_valid = now < cert_data.get('not_valid_before', 0)

        return {
            'valid': is_valid and not is_expired and not is_not_yet_valid,
            'chain_valid': is_valid,
            'expired': is_expired,
            'not_yet_valid': is_not_yet_valid,
            'subject': cert_data.get('subject', {}),
            'issuer': cert_data.get('issuer', {}),
            'not_valid_before': cert_data.get('not_valid_before'),
            'not_valid_after': cert_data.get('not_valid_after')
        }

    def get_key(self, key_id: str) -> Optional[bytes]:
        """
        Retrieve a key by its ID.

        Args:
            key_id: The ID of the key to retrieve

        Returns:
            The key as bytes, or None if the key doesn't exist
        """
        key_data = self.active_keys.get(key_id)
        if key_data:
            return key_data['key']
        return None

    def rotate_keys(self, max_age_days: int = 90) -> List[str]:
        """
        Rotate keys that are older than the specified age.

        Args:
            max_age_days: Maximum age of keys in days

        Returns:
            List of rotated key IDs
        """
        current_time = time.time()
        max_age_seconds = max_age_days * 24 * 60 * 60
        rotated_keys = []

        for key_id, key_data in list(self.active_keys.items()):
            if current_time - key_data['created'] > max_age_seconds:
                # Generate a new key with the same parameters
                algorithm = key_data['algorithm']
                key_size = key_data['key_size']

                # Replace the old key with a new one
                key_data['key'] = secrets.token_bytes(key_size // 8)
                key_data['created'] = current_time
                key_data['previous_rotation'] = current_time

                rotated_keys.append(key_id)

        return rotated_keys

    def secure_erase(self, key_id: str) -> bool:
        """
        Securely erase a key from memory and persistent storage.

        Args:
            key_id: The ID of the key to erase

        Returns:
            True if the key was erased, False if it didn't exist
        """
        if key_id in self.active_keys:
            # Overwrite the key with random data before removing
            key_data = self.active_keys[key_id]
            key_size = len(key_data['key'])
            key_data['key'] = os.urandom(key_size)

            # Remove the key from the dictionary
            del self.active_keys[key_id]

            # Remove from persistent storage if available
            if self.persistent_storage and self.key_storage:
                self.key_storage.remove_key(key_id)
                self.key_storage.save()

            return True
        return False

    def save_keys(self) -> bool:
        """
        Save all keys to persistent storage.

        Returns:
            True if successful, False otherwise
        """
        if self.persistent_storage and self.key_storage:
            return self.key_storage.save()
        return False

    def change_master_password(self, current_password: str, new_password: str) -> bool:
        """
        Change the master password for the key storage.

        Args:
            current_password: Current master password
            new_password: New master password

        Returns:
            True if successful, False otherwise
        """
        if self.persistent_storage and self.key_storage:
            return self.key_storage.change_master_password(current_password, new_password)
        return False

    def list_keys(self) -> List[Dict[str, Any]]:
        """
        List all keys with their metadata (excluding the actual key material).

        Returns:
            List of dictionaries containing key metadata
        """
        result = []
        for key_id, key_data in self.active_keys.items():
            # Create a copy without the actual key material
            key_info = key_data.copy()
            if 'key' in key_info:
                del key_info['key']
            key_info['id'] = key_id
            result.append(key_info)
        return result

    def generate_asymmetric_keypair(self, algorithm: str = 'RSA', key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Generate a new asymmetric key pair.

        Args:
            algorithm: The algorithm to generate a key for ('RSA', 'ECC', or post-quantum algorithms)
            key_size: The size of the key in bits (for RSA/ECC)

        Returns:
            A tuple containing (public_key, private_key)

        Raises:
            ValueError: If the algorithm or key size is not supported
        """
        # Check if this is a post-quantum algorithm
        if algorithm in PQ_SIGN_ALGORITHMS or algorithm in PQ_KEM_ALGORITHMS:
            return self.generate_postquantum_keypair(algorithm)

        # Import cryptography modules here to avoid dependency issues
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        from cryptography.hazmat.primitives import serialization

        if algorithm == 'RSA':
            # Generate RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )

            # Serialize keys
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        elif algorithm == 'ECC':
            # Determine curve based on key size
            if key_size <= 256:
                curve = ec.SECP256R1()
            elif key_size <= 384:
                curve = ec.SECP384R1()
            else:
                curve = ec.SECP521R1()

            # Generate ECC key pair
            private_key = ec.generate_private_key(curve)

            # Serialize keys
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported algorithms: RSA, ECC, {', '.join(PQ_SIGN_ALGORITHMS)}, {', '.join(PQ_KEM_ALGORITHMS)}")

        # Store key metadata
        key_id_base = self._generate_key_id()

        # Store private key
        private_key_id = f"{key_id_base}.private"
        private_key_data = {
            'algorithm': algorithm,
            'key_size': key_size,
            'created': time.time(),
            'key': private_bytes,
            'purpose': 'asymmetric_encryption',
            'key_type': 'private',
            'key_id_base': key_id_base
        }
        self.active_keys[private_key_id] = private_key_data

        # Store public key
        public_key_id = f"{key_id_base}.public"
        public_key_data = {
            'algorithm': algorithm,
            'key_size': key_size,
            'created': time.time(),
            'key': public_bytes,
            'purpose': 'asymmetric_encryption',
            'key_type': 'public',
            'key_id_base': key_id_base
        }
        self.active_keys[public_key_id] = public_key_data

        # Save to storage if available
        if self.persistent_storage and self.key_storage:
            self.key_storage.save_keys(self.active_keys)

        return public_bytes, private_bytes

    def generate_postquantum_keypair(self, algorithm: str) -> Tuple[bytes, bytes]:
        """
        Generate a new post-quantum key pair.

        Args:
            algorithm: The post-quantum algorithm to use

        Returns:
            A tuple containing (public_key, private_key)

        Raises:
            ValueError: If the algorithm is not supported or post-quantum crypto is not available
        """
        if not POSTQUANTUM_AVAILABLE or not self.pq_crypto:
            raise ValueError("Post-quantum cryptography is not available. Please install the pqcrypto library.")

        # Generate key pair based on algorithm type
        if algorithm in PQ_SIGN_ALGORITHMS:
            # Generate signature key pair
            public_key, private_key = self.pq_crypto.generate_sign_keypair(algorithm)
            purpose = 'digital_signature'
        elif algorithm in PQ_KEM_ALGORITHMS:
            # Generate KEM key pair
            public_key, private_key = self.pq_crypto.generate_kem_keypair(algorithm)
            purpose = 'key_encapsulation'
        else:
            raise ValueError(f"Unsupported post-quantum algorithm: {algorithm}. Supported algorithms: {', '.join(PQ_SIGN_ALGORITHMS)}, {', '.join(PQ_KEM_ALGORITHMS)}")

        # Store key metadata
        key_id_base = self._generate_key_id()

        # Store private key
        private_key_id = f"{key_id_base}.private"
        private_key_data = {
            'algorithm': algorithm,
            'created': time.time(),
            'key': private_key,
            'purpose': purpose,
            'key_type': 'private',
            'key_id_base': key_id_base,
            'post_quantum': True
        }
        self.active_keys[private_key_id] = private_key_data

        # Store public key
        public_key_id = f"{key_id_base}.public"
        public_key_data = {
            'algorithm': algorithm,
            'created': time.time(),
            'key': public_key,
            'purpose': purpose,
            'key_type': 'public',
            'key_id_base': key_id_base,
            'post_quantum': True
        }
        self.active_keys[public_key_id] = public_key_data

        # Save to storage if available
        if self.persistent_storage and self.key_storage:
            self.key_storage.save_keys(self.active_keys)

        return public_key, private_key
