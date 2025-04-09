"""
PKCS#11 Interface for Hardware Security Modules (HSMs).

This module provides an interface for interacting with HSMs using the PKCS#11 standard.
It supports key generation, encryption, decryption, signing, and verification operations
using hardware-backed keys.

Features:
- Support for symmetric and asymmetric key generation
- Support for various encryption algorithms (AES-GCM, AES-CBC, etc.)
- Support for various signature algorithms (RSA-SHA256, ECDSA, etc.)
- Support for key import and export (where allowed by the HSM)
- Support for key attributes management
- Integration with post-quantum algorithms (where supported by the HSM)

Note: This implementation requires the python-pkcs11 library, which can be installed with:
pip install python-pkcs11
"""

import os
import logging
import binascii
from typing import Dict, Any, Optional, Tuple, List, Union, Callable

# Import PKCS#11 library (if available)
try:
    import pkcs11
    from pkcs11 import Mechanism, KeyType, ObjectClass, Attribute
    from pkcs11.util.rsa import encode_rsa_public_key
    PKCS11_AVAILABLE = True
except ImportError:
    PKCS11_AVAILABLE = False

# Try to import post-quantum module
try:
    from .post_quantum import PostQuantumCrypto
    POSTQUANTUM_AVAILABLE = True
except ImportError:
    POSTQUANTUM_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pkcs11_interface")


class PKCS11Error(Exception):
    """Exception raised for PKCS#11 related errors."""
    pass


class PKCS11Interface:
    """
    Interface for interacting with HSMs using PKCS#11.

    This class provides methods for performing cryptographic operations
    using hardware security modules that support the PKCS#11 standard.
    """

    def __init__(self,
                library_path: str,
                token_label: Optional[str] = None,
                pin: Optional[str] = None,
                use_post_quantum: bool = True):
        """
        Initialize the PKCS#11 interface.

        Args:
            library_path: Path to the PKCS#11 library (.so, .dll, .dylib)
            token_label: Label of the token to use (if None, use the first available token)
            pin: PIN for the token (if None, operations requiring authentication will fail)
            use_post_quantum: Whether to use post-quantum algorithms when available

        Raises:
            PKCS11Error: If PKCS#11 support is not available or initialization fails
        """
        if not PKCS11_AVAILABLE:
            raise PKCS11Error("PKCS#11 support is not available. Please install python-pkcs11.")

        self.library_path = library_path
        self.token_label = token_label
        self.pin = pin
        self.use_post_quantum = use_post_quantum and POSTQUANTUM_AVAILABLE

        # Initialize post-quantum crypto if available and requested
        self.pq_crypto = None
        if self.use_post_quantum and POSTQUANTUM_AVAILABLE:
            try:
                self.pq_crypto = PostQuantumCrypto()
                logger.info("Post-quantum cryptography support enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize post-quantum cryptography: {str(e)}")
                self.use_post_quantum = False

        # Initialize the library
        try:
            self.lib = pkcs11.lib(library_path)
            logger.info(f"Loaded PKCS#11 library: {library_path}")
        except Exception as e:
            raise PKCS11Error(f"Failed to load PKCS#11 library: {str(e)}")

        # Get available slots and tokens
        self.slots = self.lib.get_slots()
        if not self.slots:
            raise PKCS11Error("No PKCS#11 slots available")

        # Find the token
        self.token = None
        if token_label:
            for slot in self.slots:
                try:
                    token = slot.get_token()
                    if token.label == token_label:
                        self.token = token
                        break
                except Exception:
                    continue

            if not self.token:
                raise PKCS11Error(f"Token with label '{token_label}' not found")
        else:
            # Use the first available token
            try:
                self.token = self.slots[0].get_token()
            except Exception as e:
                raise PKCS11Error(f"Failed to get token: {str(e)}")

        logger.info(f"Using token: {self.token.label}")

    def open_session(self, read_only: bool = False) -> pkcs11.Session:
        """
        Open a session with the token.

        Args:
            read_only: Whether to open a read-only session

        Returns:
            An open session with the token

        Raises:
            PKCS11Error: If opening the session fails
        """
        try:
            session = self.token.open_session(read_only=read_only)
            if self.pin:
                session.login(self.pin)
            return session
        except Exception as e:
            raise PKCS11Error(f"Failed to open session: {str(e)}")

    def generate_key(self,
                    key_type: str,
                    key_size: int,
                    key_label: str,
                    key_id: Optional[bytes] = None,
                    extractable: bool = False,
                    post_quantum: bool = False) -> Dict[str, Any]:
        """
        Generate a key or key pair on the HSM.

        Args:
            key_type: Type of key to generate ('AES', 'RSA', 'EC', 'KYBER', 'DILITHIUM', etc.)
            key_size: Size of the key in bits
            key_label: Label for the key
            key_id: ID for the key (if None, a random ID will be generated)
            extractable: Whether the key can be extracted from the HSM
            post_quantum: Whether to use post-quantum algorithms

        Returns:
            Dictionary with key information

        Raises:
            PKCS11Error: If key generation fails
        """
        if not key_id:
            key_id = os.urandom(16)

        # Check if post-quantum algorithms are requested and available
        if post_quantum and self.use_post_quantum and key_type.upper() in ['KYBER', 'DILITHIUM']:
            return self._generate_post_quantum_key(key_type, key_size, key_label, key_id, extractable)

        try:
            with self.open_session() as session:
                if key_type.upper() == 'AES':
                    # Generate AES key
                    key = session.generate_key(
                        KeyType.AES,
                        key_size,
                        label=key_label,
                        id=key_id,
                        extractable=extractable
                    )

                    return {
                        'type': 'symmetric',
                        'algorithm': 'AES',
                        'key_size': key_size,
                        'label': key_label,
                        'id': binascii.hexlify(key_id).decode('utf-8'),
                        'handle': str(key)
                    }

                elif key_type.upper() == 'RSA':
                    # Generate RSA key pair
                    public, private = session.generate_keypair(
                        KeyType.RSA,
                        key_size,
                        label=key_label,
                        id=key_id,
                        store=True,
                        public_template={
                            Attribute.ENCRYPT: True,
                            Attribute.VERIFY: True,
                            Attribute.EXTRACTABLE: True
                        },
                        private_template={
                            Attribute.DECRYPT: True,
                            Attribute.SIGN: True,
                            Attribute.EXTRACTABLE: extractable
                        }
                    )

                    # Get the public key in a standard format
                    public_key_der = encode_rsa_public_key(public)

                    return {
                        'type': 'asymmetric',
                        'algorithm': 'RSA',
                        'key_size': key_size,
                        'label': key_label,
                        'id': binascii.hexlify(key_id).decode('utf-8'),
                        'public_handle': str(public),
                        'private_handle': str(private),
                        'public_key': binascii.hexlify(public_key_der).decode('utf-8')
                    }

                elif key_type.upper() == 'EC':
                    # Generate EC key pair
                    public, private = session.generate_keypair(
                        KeyType.EC,
                        {
                            Attribute.EC_PARAMS: self._get_ec_params(key_size)
                        },
                        label=key_label,
                        id=key_id,
                        store=True,
                        public_template={
                            Attribute.VERIFY: True,
                            Attribute.EXTRACTABLE: True
                        },
                        private_template={
                            Attribute.SIGN: True,
                            Attribute.EXTRACTABLE: extractable
                        }
                    )

                    return {
                        'type': 'asymmetric',
                        'algorithm': 'EC',
                        'key_size': key_size,
                        'label': key_label,
                        'id': binascii.hexlify(key_id).decode('utf-8'),
                        'public_handle': str(public),
                        'private_handle': str(private)
                    }

                else:
                    raise PKCS11Error(f"Unsupported key type: {key_type}")

        except Exception as e:
            raise PKCS11Error(f"Failed to generate key: {str(e)}")

    def find_key(self,
                key_id: str,
                key_type: Optional[str] = None,
                key_class: Optional[str] = None) -> Optional[pkcs11.Object]:
        """
        Find a key on the HSM.

        Args:
            key_id: ID of the key to find (hex encoded)
            key_type: Type of key to find ('AES', 'RSA', 'EC', etc.)
            key_class: Class of key to find ('public', 'private', 'secret')

        Returns:
            The key object if found, None otherwise

        Raises:
            PKCS11Error: If finding the key fails
        """
        try:
            # Convert hex key_id to bytes
            key_id_bytes = binascii.unhexlify(key_id)

            # Determine key class
            key_class_attr = None
            if key_class:
                if key_class.lower() == 'public':
                    key_class_attr = ObjectClass.PUBLIC_KEY
                elif key_class.lower() == 'private':
                    key_class_attr = ObjectClass.PRIVATE_KEY
                elif key_class.lower() == 'secret':
                    key_class_attr = ObjectClass.SECRET_KEY

            # Determine key type
            key_type_attr = None
            if key_type:
                if key_type.upper() == 'AES':
                    key_type_attr = KeyType.AES
                elif key_type.upper() == 'RSA':
                    key_type_attr = KeyType.RSA
                elif key_type.upper() == 'EC':
                    key_type_attr = KeyType.EC

            with self.open_session(read_only=True) as session:
                # Build search template
                template = {
                    Attribute.ID: key_id_bytes
                }

                if key_class_attr:
                    template[Attribute.CLASS] = key_class_attr

                if key_type_attr:
                    template[Attribute.KEY_TYPE] = key_type_attr

                # Find keys matching the template
                keys = list(session.get_objects(template))

                if not keys:
                    return None

                return keys[0]

        except Exception as e:
            raise PKCS11Error(f"Failed to find key: {str(e)}")

    def encrypt(self,
               data: bytes,
               key_id: str,
               algorithm: str,
               params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Encrypt data using a key on the HSM.

        Args:
            data: Data to encrypt
            key_id: ID of the key to use (hex encoded)
            algorithm: Encryption algorithm to use
            params: Additional parameters for the algorithm

        Returns:
            Dictionary with encryption result

        Raises:
            PKCS11Error: If encryption fails
        """
        try:
            # Find the key
            key_type = 'AES' if algorithm.startswith('AES') else 'RSA'
            key_class = 'secret' if key_type == 'AES' else 'public'

            key = self.find_key(key_id, key_type, key_class)
            if not key:
                raise PKCS11Error(f"Key not found: {key_id}")

            # Determine the mechanism
            mechanism = self._get_mechanism(algorithm, params)

            with self.open_session(read_only=True) as session:
                # Encrypt the data
                ciphertext = key.encrypt(data, mechanism=mechanism)

                result = {
                    'algorithm': algorithm,
                    'ciphertext': ciphertext
                }

                # Add additional parameters if needed
                if params:
                    for param_name, param_value in params.items():
                        if isinstance(param_value, bytes):
                            result[param_name] = param_value

                return result

        except Exception as e:
            raise PKCS11Error(f"Failed to encrypt data: {str(e)}")

    def decrypt(self,
               ciphertext: bytes,
               key_id: str,
               algorithm: str,
               params: Optional[Dict[str, Any]] = None) -> bytes:
        """
        Decrypt data using a key on the HSM.

        Args:
            ciphertext: Data to decrypt
            key_id: ID of the key to use (hex encoded)
            algorithm: Decryption algorithm to use
            params: Additional parameters for the algorithm

        Returns:
            Decrypted data

        Raises:
            PKCS11Error: If decryption fails
        """
        try:
            # Find the key
            key_type = 'AES' if algorithm.startswith('AES') else 'RSA'
            key_class = 'secret' if key_type == 'AES' else 'private'

            key = self.find_key(key_id, key_type, key_class)
            if not key:
                raise PKCS11Error(f"Key not found: {key_id}")

            # Determine the mechanism
            mechanism = self._get_mechanism(algorithm, params)

            with self.open_session(read_only=True) as session:
                # Decrypt the data
                plaintext = key.decrypt(ciphertext, mechanism=mechanism)
                return plaintext

        except Exception as e:
            raise PKCS11Error(f"Failed to decrypt data: {str(e)}")

    def sign(self,
            data: bytes,
            key_id: str,
            algorithm: str,
            params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Sign data using a key on the HSM.

        Args:
            data: Data to sign
            key_id: ID of the key to use (hex encoded)
            algorithm: Signature algorithm to use
            params: Additional parameters for the algorithm

        Returns:
            Dictionary with signature result

        Raises:
            PKCS11Error: If signing fails
        """
        try:
            # Find the key
            key_type = 'RSA' if algorithm.startswith('RSA') else 'EC'
            key = self.find_key(key_id, key_type, 'private')
            if not key:
                raise PKCS11Error(f"Key not found: {key_id}")

            # Determine the mechanism
            mechanism = self._get_mechanism(algorithm, params)

            with self.open_session(read_only=True) as session:
                # Sign the data
                signature = key.sign(data, mechanism=mechanism)

                return {
                    'algorithm': algorithm,
                    'signature': signature
                }

        except Exception as e:
            raise PKCS11Error(f"Failed to sign data: {str(e)}")

    def verify(self,
              data: bytes,
              signature: bytes,
              key_id: str,
              algorithm: str,
              params: Optional[Dict[str, Any]] = None) -> bool:
        """
        Verify a signature using a key on the HSM.

        Args:
            data: Original data that was signed
            signature: Signature to verify
            key_id: ID of the key to use (hex encoded)
            algorithm: Signature algorithm to use
            params: Additional parameters for the algorithm

        Returns:
            True if the signature is valid, False otherwise

        Raises:
            PKCS11Error: If verification fails
        """
        try:
            # Find the key
            key_type = 'RSA' if algorithm.startswith('RSA') else 'EC'
            key = self.find_key(key_id, key_type, 'public')
            if not key:
                raise PKCS11Error(f"Key not found: {key_id}")

            # Determine the mechanism
            mechanism = self._get_mechanism(algorithm, params)

            with self.open_session(read_only=True) as session:
                # Verify the signature
                try:
                    key.verify(data, signature, mechanism=mechanism)
                    return True
                except pkcs11.SignatureInvalid:
                    return False

        except pkcs11.SignatureInvalid:
            return False
        except Exception as e:
            raise PKCS11Error(f"Failed to verify signature: {str(e)}")

    def list_keys(self,
                 key_type: Optional[str] = None,
                 key_class: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List keys on the HSM.

        Args:
            key_type: Type of keys to list ('AES', 'RSA', 'EC', etc.)
            key_class: Class of keys to list ('public', 'private', 'secret')

        Returns:
            List of dictionaries with key information

        Raises:
            PKCS11Error: If listing keys fails
        """
        try:
            # Determine key class
            key_class_attr = None
            if key_class:
                if key_class.lower() == 'public':
                    key_class_attr = ObjectClass.PUBLIC_KEY
                elif key_class.lower() == 'private':
                    key_class_attr = ObjectClass.PRIVATE_KEY
                elif key_class.lower() == 'secret':
                    key_class_attr = ObjectClass.SECRET_KEY

            # Determine key type
            key_type_attr = None
            if key_type:
                if key_type.upper() == 'AES':
                    key_type_attr = KeyType.AES
                elif key_type.upper() == 'RSA':
                    key_type_attr = KeyType.RSA
                elif key_type.upper() == 'EC':
                    key_type_attr = KeyType.EC

            with self.open_session(read_only=True) as session:
                # Build search template
                template = {}

                if key_class_attr:
                    template[Attribute.CLASS] = key_class_attr

                if key_type_attr:
                    template[Attribute.KEY_TYPE] = key_type_attr

                # Find keys matching the template
                keys = []
                for key in session.get_objects(template):
                    key_info = {
                        'handle': str(key),
                        'label': key[Attribute.LABEL] if Attribute.LABEL in key else None,
                        'id': binascii.hexlify(key[Attribute.ID]).decode('utf-8') if Attribute.ID in key else None,
                        'class': self._get_key_class_name(key[Attribute.CLASS]) if Attribute.CLASS in key else None,
                        'type': self._get_key_type_name(key[Attribute.KEY_TYPE]) if Attribute.KEY_TYPE in key else None
                    }

                    # Add key size if available
                    if Attribute.MODULUS in key:
                        key_info['key_size'] = len(key[Attribute.MODULUS]) * 8
                    elif Attribute.VALUE_LEN in key:
                        key_info['key_size'] = key[Attribute.VALUE_LEN] * 8

                    keys.append(key_info)

                return keys

        except Exception as e:
            raise PKCS11Error(f"Failed to list keys: {str(e)}")

    def delete_key(self, key_id: str, key_class: Optional[str] = None) -> bool:
        """
        Delete a key from the HSM.

        Args:
            key_id: ID of the key to delete (hex encoded)
            key_class: Class of key to delete ('public', 'private', 'secret')

        Returns:
            True if the key was deleted, False otherwise

        Raises:
            PKCS11Error: If deleting the key fails
        """
        try:
            # Find the key
            key = self.find_key(key_id, key_class=key_class)
            if not key:
                return False

            with self.open_session() as session:
                # Delete the key
                key.destroy()
                return True

        except Exception as e:
            raise PKCS11Error(f"Failed to delete key: {str(e)}")

    def _get_mechanism(self, algorithm: str, params: Optional[Dict[str, Any]] = None) -> Mechanism:
        """
        Get the PKCS#11 mechanism for an algorithm.

        Args:
            algorithm: Algorithm name
            params: Additional parameters for the algorithm

        Returns:
            PKCS#11 mechanism

        Raises:
            PKCS11Error: If the algorithm is not supported
        """
        if algorithm.upper() == 'AES-CBC':
            if not params or 'iv' not in params:
                raise PKCS11Error("IV required for AES-CBC")
            return Mechanism.AES_CBC_PAD, params['iv']

        elif algorithm.upper() == 'AES-GCM':
            if not params or 'iv' not in params:
                raise PKCS11Error("IV required for AES-GCM")

            gcm_params = {
                'iv': params['iv']
            }

            if 'aad' in params:
                gcm_params['aad'] = params['aad']

            return Mechanism.AES_GCM, gcm_params

        elif algorithm.upper() == 'RSA-PKCS':
            return Mechanism.RSA_PKCS

        elif algorithm.upper() == 'RSA-PKCS-PSS':
            if not params or 'hash_alg' not in params:
                # Default to SHA-256
                hash_alg = Mechanism.SHA256
            else:
                hash_alg = self._get_hash_mechanism(params['hash_alg'])

            return Mechanism.RSA_PKCS_PSS, {
                'hash_alg': hash_alg,
                'mgf': Mechanism.MGF1_SHA256,
                'salt_len': 32
            }

        elif algorithm.upper() == 'ECDSA':
            if not params or 'hash_alg' not in params:
                # Default to SHA-256
                return Mechanism.ECDSA
            else:
                hash_alg = self._get_hash_mechanism(params['hash_alg'])
                return Mechanism.ECDSA, {'hash_alg': hash_alg}

        else:
            raise PKCS11Error(f"Unsupported algorithm: {algorithm}")

    def _get_hash_mechanism(self, hash_alg: str) -> Mechanism:
        """
        Get the PKCS#11 mechanism for a hash algorithm.

        Args:
            hash_alg: Hash algorithm name

        Returns:
            PKCS#11 mechanism

        Raises:
            PKCS11Error: If the hash algorithm is not supported
        """
        if hash_alg.upper() == 'SHA1':
            return Mechanism.SHA_1
        elif hash_alg.upper() == 'SHA256':
            return Mechanism.SHA256
        elif hash_alg.upper() == 'SHA384':
            return Mechanism.SHA384
        elif hash_alg.upper() == 'SHA512':
            return Mechanism.SHA512
        else:
            raise PKCS11Error(f"Unsupported hash algorithm: {hash_alg}")

    def _get_ec_params(self, key_size: int) -> bytes:
        """
        Get the EC parameters for a key size.

        Args:
            key_size: Key size in bits

        Returns:
            EC parameters as bytes

        Raises:
            PKCS11Error: If the key size is not supported
        """
        # OIDs for common curves
        if key_size == 256:
            # P-256 (secp256r1)
            return b'\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07'
        elif key_size == 384:
            # P-384 (secp384r1)
            return b'\x06\x05\x2B\x81\x04\x00\x22'
        elif key_size == 521:
            # P-521 (secp521r1)
            return b'\x06\x05\x2B\x81\x04\x00\x23'
        else:
            raise PKCS11Error(f"Unsupported EC key size: {key_size}")

    def _get_key_class_name(self, key_class: ObjectClass) -> str:
        """
        Get the name of a key class.

        Args:
            key_class: PKCS#11 key class

        Returns:
            Name of the key class
        """
        if key_class == ObjectClass.PUBLIC_KEY:
            return 'public'
        elif key_class == ObjectClass.PRIVATE_KEY:
            return 'private'
        elif key_class == ObjectClass.SECRET_KEY:
            return 'secret'
        else:
            return 'unknown'

    def _get_key_type_name(self, key_type: KeyType) -> str:
        """
        Get the name of a key type.

        Args:
            key_type: PKCS#11 key type

        Returns:
            Name of the key type
        """
        if key_type == KeyType.AES:
            return 'AES'
        elif key_type == KeyType.RSA:
            return 'RSA'
        elif key_type == KeyType.EC:
            return 'EC'
        else:
            return 'unknown'

    def _generate_post_quantum_key(self,
                                key_type: str,
                                key_size: int,
                                key_label: str,
                                key_id: bytes,
                                extractable: bool = False) -> Dict[str, Any]:
        """
        Generate a post-quantum key pair using the post-quantum module.

        Since most HSMs don't natively support post-quantum algorithms yet,
        this method generates the keys using the post-quantum module and
        then imports them into the HSM as raw data objects.

        Args:
            key_type: Type of post-quantum key to generate ('KYBER', 'DILITHIUM', etc.)
            key_size: Size variant (e.g., 512, 768, 1024 for Kyber)
            key_label: Label for the key
            key_id: ID for the key
            extractable: Whether the key can be extracted from the HSM

        Returns:
            Dictionary with key information

        Raises:
            PKCS11Error: If key generation fails
        """
        if not self.use_post_quantum or not self.pq_crypto:
            raise PKCS11Error("Post-quantum cryptography is not available")

        try:
            # Determine the specific algorithm based on key type and size
            algorithm = f"{key_type.upper()}{key_size}"

            # Generate the key pair using the post-quantum module
            if key_type.upper() == 'KYBER':
                # For KEM algorithms like Kyber
                public_key, private_key = self.pq_crypto.generate_kem_keypair(algorithm)
                key_purpose = 'key_encapsulation'
            elif key_type.upper() == 'DILITHIUM':
                # For signature algorithms like Dilithium
                public_key, private_key = self.pq_crypto.generate_signature_keypair(algorithm)
                key_purpose = 'signature'
            else:
                raise PKCS11Error(f"Unsupported post-quantum algorithm: {key_type}")

            # Store the keys in the HSM as raw data objects
            with self.open_session() as session:
                # Create a data object for the private key
                private_obj = session.create_object({
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: True,
                    Attribute.LABEL: f"{key_label}.private",
                    Attribute.ID: key_id + b'.private',
                    Attribute.APPLICATION: "post-quantum",
                    Attribute.VALUE: private_key,
                    Attribute.EXTRACTABLE: extractable
                })

                # Create a data object for the public key
                public_obj = session.create_object({
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: False,
                    Attribute.LABEL: f"{key_label}.public",
                    Attribute.ID: key_id + b'.public',
                    Attribute.APPLICATION: "post-quantum",
                    Attribute.VALUE: public_key
                })

                # Return key information
                return {
                    'type': 'asymmetric',
                    'algorithm': algorithm,
                    'key_size': key_size,
                    'id': binascii.hexlify(key_id).decode('ascii'),
                    'label': key_label,
                    'extractable': extractable,
                    'purpose': key_purpose,
                    'post_quantum': True
                }

        except Exception as e:
            logger.error(f"Failed to generate post-quantum key: {str(e)}")
            raise PKCS11Error(f"Failed to generate post-quantum key: {str(e)}")
