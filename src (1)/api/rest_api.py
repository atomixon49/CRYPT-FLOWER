"""
RESTful API for cryptographic operations.

This module provides a RESTful API for integrating the cryptographic system
with external applications. It supports operations such as encryption, decryption,
signing, verification, and key management.
"""

import os
import json
import base64
import logging
import secrets
import time
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta

# Flask imports
from flask import Flask, request, jsonify, Response, g
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from flasgger import swag_from

# Import Swagger configuration
from .swagger import configure_swagger

# Authentication imports
import jwt
from functools import wraps

# Import core components
from ..core.key_management import KeyManager
from ..core.encryption import EncryptionEngine
from ..core.signatures import SignatureEngine
from ..core.crypto_audit import CryptoAuditLogger, AuditEventType, AuditSeverity
from ..core.jwt_interface import JWTInterface, JWTError
from ..core.hsm_key_manager import HSMKeyManager, PKCS11_AVAILABLE

# Import plugin components
from ..plugins.plugin_manager import PluginManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("crypto_api")

# Initialize Flask app
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
CORS(app)

# Load configuration
from .config import DefaultConfig
app.config.from_object(DefaultConfig)
if 'CRYPTO_API_CONFIG' in os.environ:
    app.config.from_envvar('CRYPTO_API_CONFIG')

# Configure Swagger
configure_swagger(app)

# Initialize core components
key_manager = KeyManager(
    storage_path=app.config.get('KEYS_FILE', 'keys.json')
)
encryption_engine = EncryptionEngine()
signature_engine = SignatureEngine()
audit_logger = CryptoAuditLogger()

# Initialize JWT interface
try:
    jwt_interface = JWTInterface(key_manager=key_manager)
    JWT_INTERFACE_AVAILABLE = True
except JWTError:
    logger.warning("JWT interface not available. JWE/JWS endpoints will not work.")
    JWT_INTERFACE_AVAILABLE = False

# Initialize HSM key manager
hsm_key_manager = None
if PKCS11_AVAILABLE:
    try:
        # Get HSM configuration from environment or config
        library_path = os.environ.get('HSM_LIBRARY_PATH', app.config.get('HSM_LIBRARY_PATH'))
        token_label = os.environ.get('HSM_TOKEN_LABEL', app.config.get('HSM_TOKEN_LABEL'))
        pin = os.environ.get('HSM_PIN', app.config.get('HSM_PIN'))

        if library_path:
            hsm_key_manager = HSMKeyManager(key_manager, library_path, token_label, pin)
            logger.info(f"Initialized HSM key manager with library: {library_path}")
    except Exception as e:
        logger.warning(f"Failed to initialize HSM key manager: {str(e)}")

# Initialize plugin manager
plugin_manager = None
try:
    plugin_manager = PluginManager()
    logger.info(f"Initialized plugin manager with {len(plugin_manager.plugin_classes)} plugins")
except Exception as e:
    logger.warning(f"Failed to initialize plugin manager: {str(e)}")

# JWT Secret key
JWT_SECRET = app.config.get('JWT_SECRET', secrets.token_hex(32))
JWT_ALGORITHM = app.config.get('JWT_ALGORITHM', 'HS256')
JWT_EXPIRATION = app.config.get('JWT_EXPIRATION', 3600)  # 1 hour


def get_token_from_header() -> Optional[str]:
    """Extract JWT token from the Authorization header."""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None

    parts = auth_header.split()
    if parts[0].lower() != 'bearer' or len(parts) != 2:
        return None

    return parts[1]


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")


def requires_auth(f):
    """Decorator to require authentication for API endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_header()
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        try:
            payload = decode_token(token)
            g.user = payload
        except ValueError as e:
            return jsonify({"error": str(e)}), 401

        return f(*args, **kwargs)

    return decorated


def requires_admin(f):
    """Decorator to require admin privileges for API endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_header()
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        try:
            payload = decode_token(token)
            if not payload.get('admin', False):
                return jsonify({"error": "Admin privileges required"}), 403
            g.user = payload
        except ValueError as e:
            return jsonify({"error": str(e)}), 401

        return f(*args, **kwargs)

    return decorated


def log_api_call(event_type: AuditEventType, description: str, severity: AuditSeverity = AuditSeverity.INFO, metadata: Optional[Dict[str, Any]] = None):
    """Log an API call to the audit log."""
    user_id = g.user.get('sub', 'anonymous') if hasattr(g, 'user') else 'anonymous'

    # Add request information to metadata
    request_metadata = {
        'ip_address': request.remote_addr,
        'user_agent': request.user_agent.string,
        'endpoint': request.endpoint,
        'method': request.method
    }

    # Merge with provided metadata
    full_metadata = metadata or {}
    full_metadata.update(request_metadata)

    # Log the event
    audit_logger.log_event(
        event_type=event_type,
        description=description,
        user_id=user_id,
        severity=severity,
        metadata=full_metadata
    )


@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """Authenticate a user and return a JWT token."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # In a real implementation, validate against a user database
    # For demonstration, we'll use a simple check
    if username == app.config.get('ADMIN_USERNAME') and password == app.config.get('ADMIN_PASSWORD'):
        # Generate token
        payload = {
            'sub': username,
            'admin': True,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=JWT_EXPIRATION)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

        # Log the successful login
        log_api_call(
            event_type=AuditEventType.AUTHENTICATION,
            description=f"User {username} logged in",
            metadata={'success': True}
        )

        return jsonify({
            'token': token,
            'expires_in': JWT_EXPIRATION
        })

    # Log the failed login attempt
    log_api_call(
        event_type=AuditEventType.AUTHENTICATION,
        description=f"Failed login attempt for user {username}",
        severity=AuditSeverity.WARNING,
        metadata={'success': False}
    )

    return jsonify({"error": "Invalid credentials"}), 401


@app.route('/api/v1/keys', methods=['GET'])
@requires_auth
def list_keys():
    """List available keys."""
    try:
        # Get keys from key manager
        keys = []
        for key_id, key_info in key_manager.active_keys.items():
            # Filter out sensitive information
            safe_key_info = {
                'key_id': key_id,
                'algorithm': key_info.get('algorithm'),
                'created': key_info.get('created'),
                'type': key_info.get('type')
            }

            # Add key size if available
            if 'key_size' in key_info:
                safe_key_info['key_size'] = key_info['key_size']

            keys.append(safe_key_info)

        # Log the API call
        log_api_call(
            event_type=AuditEventType.KEY_MANAGEMENT,
            description="Listed keys"
        )

        return jsonify({'keys': keys})

    except Exception as e:
        # Log the error
        log_api_call(
            event_type=AuditEventType.ERROR,
            description=f"Error listing keys: {str(e)}",
            severity=AuditSeverity.ERROR
        )

        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/keys', methods=['POST'])
@requires_auth
def generate_key():
    """Generate a new key."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        key_type = data.get('type', 'symmetric')
        algorithm = data.get('algorithm')
        key_size = data.get('key_size')

        if not algorithm:
            return jsonify({"error": "Algorithm required"}), 400

        # Generate the key based on type
        if key_type == 'symmetric':
            if not key_size:
                key_size = 256  # Default to 256 bits

            key_id = key_manager.generate_symmetric_key(
                algorithm=algorithm,
                key_size=key_size
            )
        elif key_type == 'asymmetric':
            if not key_size:
                key_size = 2048  # Default to 2048 bits

            public_key, private_key = key_manager.generate_asymmetric_keypair(
                algorithm=algorithm,
                key_size=key_size
            )
            key_id = public_key.split('.')[0]  # Base key ID without .public/.private
        else:
            return jsonify({"error": "Invalid key type"}), 400

        # Log the API call
        log_api_call(
            event_type=AuditEventType.KEY_GENERATION,
            description=f"Generated {key_type} key with algorithm {algorithm}",
            metadata={
                'key_id': key_id,
                'algorithm': algorithm,
                'key_size': key_size
            }
        )

        return jsonify({
            'key_id': key_id,
            'type': key_type,
            'algorithm': algorithm,
            'key_size': key_size
        })

    except Exception as e:
        # Log the error
        log_api_call(
            event_type=AuditEventType.ERROR,
            description=f"Error generating key: {str(e)}",
            severity=AuditSeverity.ERROR
        )

        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/keys/<key_id>', methods=['DELETE'])
@requires_admin
def delete_key(key_id):
    """Delete a key."""
    try:
        # Check if the key exists
        if key_id not in key_manager.active_keys:
            return jsonify({"error": "Key not found"}), 404

        # Delete the key
        del key_manager.active_keys[key_id]

        # Save the key manager state
        key_manager.save_keys()

        # Log the API call
        log_api_call(
            event_type=AuditEventType.KEY_DELETION,
            description=f"Deleted key {key_id}",
            metadata={'key_id': key_id}
        )

        return jsonify({'success': True})

    except Exception as e:
        # Log the error
        log_api_call(
            event_type=AuditEventType.ERROR,
            description=f"Error deleting key {key_id}: {str(e)}",
            severity=AuditSeverity.ERROR,
            metadata={'key_id': key_id}
        )

        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/encrypt', methods=['POST'])
@requires_auth
def encrypt_data():
    """Encrypt data."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        # Get parameters
        plaintext = data.get('data')
        key_id = data.get('key_id')
        algorithm = data.get('algorithm', 'AES-GCM')

        if not plaintext:
            return jsonify({"error": "Data required"}), 400

        if not key_id:
            return jsonify({"error": "Key ID required"}), 400

        # Check if the key exists
        if key_id not in key_manager.active_keys:
            return jsonify({"error": "Key not found"}), 404

        # Get the key
        key = key_manager.get_key(key_id)

        # Convert plaintext to bytes if it's a string
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            # Assume it's base64 encoded
            try:
                plaintext_bytes = base64.b64decode(plaintext)
            except Exception:
                return jsonify({"error": "Invalid data format"}), 400

        # Encrypt the data
        encryption_result = encryption_engine.encrypt(
            data=plaintext_bytes,
            key=key,
            algorithm=algorithm
        )

        # Convert binary data to base64 for JSON
        result = {
            'algorithm': encryption_result['algorithm'],
            'ciphertext': base64.b64encode(encryption_result['ciphertext']).decode('utf-8')
        }

        # Add additional fields if present
        if 'nonce' in encryption_result:
            result['nonce'] = base64.b64encode(encryption_result['nonce']).decode('utf-8')

        if 'tag' in encryption_result:
            result['tag'] = base64.b64encode(encryption_result['tag']).decode('utf-8')

        # Log the API call
        log_api_call(
            event_type=AuditEventType.ENCRYPTION,
            description=f"Encrypted data using algorithm {algorithm}",
            metadata={
                'key_id': key_id,
                'algorithm': algorithm,
                'data_size': len(plaintext_bytes)
            }
        )

        return jsonify(result)

    except Exception as e:
        # Log the error
        log_api_call(
            event_type=AuditEventType.ERROR,
            description=f"Error encrypting data: {str(e)}",
            severity=AuditSeverity.ERROR
        )

        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/decrypt', methods=['POST'])
@requires_auth
def decrypt_data():
    """Decrypt data."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        # Get parameters
        ciphertext = data.get('ciphertext')
        key_id = data.get('key_id')
        algorithm = data.get('algorithm')
        nonce = data.get('nonce')
        tag = data.get('tag')

        if not ciphertext:
            return jsonify({"error": "Ciphertext required"}), 400

        if not key_id:
            return jsonify({"error": "Key ID required"}), 400

        if not algorithm:
            return jsonify({"error": "Algorithm required"}), 400

        # Check if the key exists
        if key_id not in key_manager.active_keys:
            return jsonify({"error": "Key not found"}), 404

        # Get the key
        key = key_manager.get_key(key_id)

        # Decode base64 data
        try:
            ciphertext_bytes = base64.b64decode(ciphertext)
            nonce_bytes = base64.b64decode(nonce) if nonce else None
            tag_bytes = base64.b64decode(tag) if tag else None
        except Exception:
            return jsonify({"error": "Invalid data format"}), 400

        # Create encryption result
        encryption_result = {
            'algorithm': algorithm,
            'ciphertext': ciphertext_bytes
        }

        if nonce_bytes:
            encryption_result['nonce'] = nonce_bytes

        if tag_bytes:
            encryption_result['tag'] = tag_bytes

        # Decrypt the data
        plaintext = encryption_engine.decrypt(
            encryption_result=encryption_result,
            key=key
        )

        # Log the API call
        log_api_call(
            event_type=AuditEventType.DECRYPTION,
            description=f"Decrypted data using algorithm {algorithm}",
            metadata={
                'key_id': key_id,
                'algorithm': algorithm,
                'data_size': len(plaintext)
            }
        )

        # Return the plaintext as base64
        return jsonify({
            'plaintext': base64.b64encode(plaintext).decode('utf-8')
        })

    except Exception as e:
        # Log the error
        log_api_call(
            event_type=AuditEventType.ERROR,
            description=f"Error decrypting data: {str(e)}",
            severity=AuditSeverity.ERROR
        )

        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/sign', methods=['POST'])
@requires_auth
def sign_data():
    """Sign data."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        # Get parameters
        message = data.get('data')
        key_id = data.get('key_id')
        algorithm = data.get('algorithm', 'RSA-PSS')

        if not message:
            return jsonify({"error": "Data required"}), 400

        if not key_id:
            return jsonify({"error": "Key ID required"}), 400

        # Check if the key exists and is a private key
        if not key_id.endswith('.private'):
            key_id = f"{key_id}.private"

        if key_id not in key_manager.active_keys:
            return jsonify({"error": "Private key not found"}), 404

        # Get the key
        private_key = key_manager.get_key(key_id)

        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            # Assume it's base64 encoded
            try:
                message_bytes = base64.b64decode(message)
            except Exception:
                return jsonify({"error": "Invalid data format"}), 400

        # Sign the data
        signature_result = signature_engine.sign(
            data=message_bytes,
            private_key=private_key,
            algorithm=algorithm
        )

        # Convert binary data to base64 for JSON
        result = {
            'algorithm': signature_result['algorithm'],
            'signature': base64.b64encode(signature_result['signature']).decode('utf-8')
        }

        # Log the API call
        log_api_call(
            event_type=AuditEventType.SIGNATURE,
            description=f"Signed data using algorithm {algorithm}",
            metadata={
                'key_id': key_id,
                'algorithm': algorithm,
                'data_size': len(message_bytes)
            }
        )

        return jsonify(result)

    except Exception as e:
        # Log the error
        log_api_call(
            event_type=AuditEventType.ERROR,
            description=f"Error signing data: {str(e)}",
            severity=AuditSeverity.ERROR
        )

        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/verify', methods=['POST'])
@requires_auth
def verify_signature():
    """Verify a signature."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        # Get parameters
        message = data.get('data')
        signature = data.get('signature')
        key_id = data.get('key_id')
        algorithm = data.get('algorithm')

        if not message:
            return jsonify({"error": "Data required"}), 400

        if not signature:
            return jsonify({"error": "Signature required"}), 400

        if not key_id:
            return jsonify({"error": "Key ID required"}), 400

        if not algorithm:
            return jsonify({"error": "Algorithm required"}), 400

        # Check if the key exists and is a public key
        if not key_id.endswith('.public'):
            key_id = f"{key_id}.public"

        if key_id not in key_manager.active_keys:
            return jsonify({"error": "Public key not found"}), 404

        # Get the key
        public_key = key_manager.get_key(key_id)

        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            # Assume it's base64 encoded
            try:
                message_bytes = base64.b64decode(message)
            except Exception:
                return jsonify({"error": "Invalid data format"}), 400

        # Decode signature
        try:
            signature_bytes = base64.b64decode(signature)
        except Exception:
            return jsonify({"error": "Invalid signature format"}), 400

        # Create signature result
        signature_result = {
            'algorithm': algorithm,
            'signature': signature_bytes
        }

        # Verify the signature
        is_valid = signature_engine.verify(
            data=message_bytes,
            signature_result=signature_result,
            public_key=public_key
        )

        # Log the API call
        log_api_call(
            event_type=AuditEventType.VERIFICATION,
            description=f"Verified signature using algorithm {algorithm}",
            metadata={
                'key_id': key_id,
                'algorithm': algorithm,
                'data_size': len(message_bytes),
                'valid': is_valid
            }
        )

        return jsonify({
            'valid': is_valid
        })

    except Exception as e:
        # Log the error
        log_api_call(
            event_type=AuditEventType.ERROR,
            description=f"Error verifying signature: {str(e)}",
            severity=AuditSeverity.ERROR
        )

        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'timestamp': time.time()
    })


@app.route('/api/v1/audit/events', methods=['GET'])
@requires_admin
def list_audit_events():
    """List audit events."""
    try:
        # Get query parameters
        event_type = request.args.get('event_type')
        severity = request.args.get('severity')
        user_id = request.args.get('user_id')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        limit = request.args.get('limit', 100)

        # Convert parameters
        if start_time:
            start_time = float(start_time)

        if end_time:
            end_time = float(end_time)

        if limit:
            limit = int(limit)

        # Build filters
        filters = {}
        if event_type:
            filters['event_type'] = event_type

        if severity:
            filters['severity'] = severity

        if user_id:
            filters['user_id'] = user_id

        # Get events
        events = audit_logger.get_events(
            filters=filters,
            start_time=start_time,
            end_time=end_time,
            limit=limit
        )

        # Convert events to dictionaries
        event_dicts = [event.to_dict() for event in events]

        # Log the API call
        log_api_call(
            event_type=AuditEventType.AUDIT,
            description="Listed audit events",
            metadata={
                'filters': filters,
                'start_time': start_time,
                'end_time': end_time,
                'limit': limit,
                'count': len(events)
            }
        )

        return jsonify({
            'events': event_dicts,
            'count': len(events)
        })

    except Exception as e:
        # Log the error
        log_api_call(
            event_type=AuditEventType.ERROR,
            description=f"Error listing audit events: {str(e)}",
            severity=AuditSeverity.ERROR
        )

        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/audit/report', methods=['GET'])
@requires_admin
def generate_audit_report():
    """Generate an audit report."""
    try:
        # Get query parameters
        event_type = request.args.get('event_type')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')

        # Convert parameters
        if start_time:
            start_time = float(start_time)

        if end_time:
            end_time = float(end_time)

        # Build filters
        filters = {}
        if event_type:
            filters['event_type'] = event_type

        # Generate report
        report = audit_logger.generate_report(
            title="Audit Report",
            filters=filters
        )

        # Log the API call
        log_api_call(
            event_type=AuditEventType.AUDIT,
            description="Generated audit report",
            metadata={
                'filters': filters,
                'start_time': start_time,
                'end_time': end_time
            }
        )

        return jsonify(report)

    except Exception as e:
        # Log the error
        log_api_call(
            event_type=AuditEventType.ERROR,
            description=f"Error generating audit report: {str(e)}",
            severity=AuditSeverity.ERROR
        )

        return jsonify({"error": str(e)}), 500


# Error handlers
@app.errorhandler(400)
def bad_request(error):
    """Handle bad request errors."""
    return jsonify({"error": "Bad request"}), 400


@app.errorhandler(401)
def unauthorized(error):
    """Handle unauthorized errors."""
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error):
    """Handle forbidden errors."""
    return jsonify({"error": "Forbidden"}), 403


@app.errorhandler(404)
def not_found(error):
    """Handle not found errors."""
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(error):
    """Handle server errors."""
    return jsonify({"error": "Internal server error"}), 500


# JWE/JWS Endpoints

@app.route('/api/v1/jws/create', methods=['POST'])
@requires_auth
@swag_from('swagger_docs/jws.yml')
def create_jws():
    """Create a JWS token."""
    if not JWT_INTERFACE_AVAILABLE:
        return jsonify({"error": "JWT interface not available"}), 501

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        # Get parameters
        payload = data.get('payload')
        key_id = data.get('key_id')
        algorithm = data.get('algorithm', 'RS256')
        headers = data.get('headers')

        if not payload:
            return jsonify({"error": "Payload required"}), 400

        if not key_id:
            return jsonify({"error": "Key ID required"}), 400

        # Check if the algorithm is supported
        if algorithm not in jwt_interface.SUPPORTED_SIGNING_ALGORITHMS:
            return jsonify({"error": f"Unsupported algorithm: {algorithm}"}), 400

        # Check if the key exists and is a private key
        if not key_id.endswith('.private'):
            key_id = f"{key_id}.private"

        if key_id not in key_manager.active_keys:
            return jsonify({"error": "Private key not found"}), 404

        # Create JWS
        jws_token = jwt_interface.create_jws_with_key_id(
            payload=payload,
            key_id=key_id,
            algorithm=algorithm,
            headers=headers
        )

        # Log the operation
        log_api_call(
            event_type=AuditEventType.SIGNATURE,
            description=f"Created JWS token with algorithm {algorithm}",
            metadata={
                'key_id': key_id,
                'algorithm': algorithm
            }
        )

        return jsonify({
            'jws': jws_token,
            'algorithm': algorithm
        })

    except Exception as e:
        logger.error(f"Error creating JWS: {str(e)}")
        return jsonify({"error": f"Failed to create JWS: {str(e)}"}), 500


@app.route('/api/v1/jws/verify', methods=['POST'])
@requires_auth
@swag_from('swagger_docs/verify_jws.yml')
def verify_jws():
    """Verify a JWS token."""
    if not JWT_INTERFACE_AVAILABLE:
        return jsonify({"error": "JWT interface not available"}), 501

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        # Get parameters
        token = data.get('token')
        key_id = data.get('key_id')
        algorithms = data.get('algorithms')

        if not token:
            return jsonify({"error": "Token required"}), 400

        if not key_id:
            return jsonify({"error": "Key ID required"}), 400

        # Check if the key exists and is a public key
        if not key_id.endswith('.public'):
            key_id = f"{key_id}.public"

        if key_id not in key_manager.active_keys:
            return jsonify({"error": "Public key not found"}), 404

        # Verify JWS
        result = jwt_interface.verify_jws_with_key_id(
            token=token,
            key_id=key_id,
            algorithms=algorithms
        )

        # Log the operation
        log_api_call(
            event_type=AuditEventType.VERIFICATION,
            description=f"Verified JWS token",
            metadata={
                'key_id': key_id,
                'valid': result['valid']
            }
        )

        # Convert payload to string if it's bytes
        if isinstance(result['payload'], bytes):
            try:
                result['payload'] = json.loads(result['payload'].decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                result['payload'] = base64.b64encode(result['payload']).decode('utf-8')

        return jsonify({
            'valid': result['valid'],
            'payload': result['payload'],
            'headers': result['headers']
        })

    except Exception as e:
        logger.error(f"Error verifying JWS: {str(e)}")
        return jsonify({"error": f"Failed to verify JWS: {str(e)}"}), 500


@app.route('/api/v1/jwe/create', methods=['POST'])
@requires_auth
@swag_from('swagger_docs/jwe.yml')
def create_jwe():
    """Create a JWE token."""
    if not JWT_INTERFACE_AVAILABLE:
        return jsonify({"error": "JWT interface not available"}), 501

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        # Get parameters
        payload = data.get('payload')
        key_id = data.get('key_id')
        algorithm = data.get('algorithm', 'RSA-OAEP')
        encryption = data.get('encryption', 'A256GCM')
        headers = data.get('headers')

        if not payload:
            return jsonify({"error": "Payload required"}), 400

        if not key_id:
            return jsonify({"error": "Key ID required"}), 400

        # Check if the algorithms are supported
        if algorithm not in jwt_interface.SUPPORTED_KEY_ENCRYPTION_ALGORITHMS:
            return jsonify({"error": f"Unsupported key encryption algorithm: {algorithm}"}), 400

        if encryption not in jwt_interface.SUPPORTED_CONTENT_ENCRYPTION_ALGORITHMS:
            return jsonify({"error": f"Unsupported content encryption algorithm: {encryption}"}), 400

        # Check if the key exists and is a public key
        if not key_id.endswith('.public'):
            key_id = f"{key_id}.public"

        if key_id not in key_manager.active_keys:
            return jsonify({"error": "Public key not found"}), 404

        # Create JWE
        jwe_token = jwt_interface.create_jwe_with_key_id(
            payload=payload,
            key_id=key_id,
            algorithm=algorithm,
            encryption=encryption,
            headers=headers
        )

        # Log the operation
        log_api_call(
            event_type=AuditEventType.ENCRYPTION,
            description=f"Created JWE token with algorithms {algorithm}/{encryption}",
            metadata={
                'key_id': key_id,
                'algorithm': algorithm,
                'encryption': encryption
            }
        )

        return jsonify({
            'jwe': jwe_token,
            'algorithm': algorithm,
            'encryption': encryption
        })

    except Exception as e:
        logger.error(f"Error creating JWE: {str(e)}")
        return jsonify({"error": f"Failed to create JWE: {str(e)}"}), 500


@app.route('/api/v1/jwe/decrypt', methods=['POST'])
@requires_auth
@swag_from('swagger_docs/decrypt_jwe.yml')
def decrypt_jwe():
    """Decrypt a JWE token."""
    if not JWT_INTERFACE_AVAILABLE:
        return jsonify({"error": "JWT interface not available"}), 501

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        # Get parameters
        token = data.get('token')
        key_id = data.get('key_id')

        if not token:
            return jsonify({"error": "Token required"}), 400

        if not key_id:
            return jsonify({"error": "Key ID required"}), 400

        # Check if the key exists and is a private key
        if not key_id.endswith('.private'):
            key_id = f"{key_id}.private"

        if key_id not in key_manager.active_keys:
            return jsonify({"error": "Private key not found"}), 404

        # Decrypt JWE
        result = jwt_interface.decrypt_jwe_with_key_id(
            token=token,
            key_id=key_id
        )

        # Log the operation
        log_api_call(
            event_type=AuditEventType.DECRYPTION,
            description=f"Decrypted JWE token",
            metadata={
                'key_id': key_id
            }
        )

        # Convert payload to string if it's bytes
        if isinstance(result['payload'], bytes):
            try:
                result['payload'] = json.loads(result['payload'].decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                result['payload'] = base64.b64encode(result['payload']).decode('utf-8')

        return jsonify({
            'payload': result['payload'],
            'headers': result['headers']
        })

    except Exception as e:
        logger.error(f"Error decrypting JWE: {str(e)}")
        return jsonify({"error": f"Failed to decrypt JWE: {str(e)}"}), 500


@app.route('/api/v1/jwk/export', methods=['GET'])
@requires_auth
@swag_from('swagger_docs/jwk.yml')
def export_jwk():
    """Export a key as JWK."""
    if not JWT_INTERFACE_AVAILABLE:
        return jsonify({"error": "JWT interface not available"}), 501

    try:
        # Get parameters
        key_id = request.args.get('key_id')

        if not key_id:
            return jsonify({"error": "Key ID required"}), 400

        # Check if the key exists
        if key_id not in key_manager.active_keys:
            return jsonify({"error": "Key not found"}), 404

        # Get the key
        key = key_manager.get_key(key_id)

        # Create JWK
        jwk_data = jwt_interface.create_jwk(key, kid=key_id)

        # Log the operation
        log_api_call(
            event_type=AuditEventType.KEY_EXPORT,
            description=f"Exported key as JWK",
            metadata={
                'key_id': key_id
            }
        )

        return jsonify(jwk_data)

    except Exception as e:
        logger.error(f"Error exporting JWK: {str(e)}")
        return jsonify({"error": f"Failed to export JWK: {str(e)}"}), 500


@app.route('/api/v1/jwks', methods=['GET'])
@requires_auth
@swag_from('swagger_docs/jwks.yml')
def get_jwks():
    """Get a JWK Set (JWKS) of all public keys."""
    if not JWT_INTERFACE_AVAILABLE:
        return jsonify({"error": "JWT interface not available"}), 501

    try:
        # Get all public keys
        jwks = []
        for key_id, key_info in key_manager.active_keys.items():
            if key_id.endswith('.public'):
                key = key_manager.get_key(key_id)
                jwk_data = jwt_interface.create_jwk(key, kid=key_id)
                jwks.append(jwk_data)

        # Create JWKS
        jwks_data = jwt_interface.create_jwks(jwks)

        # Log the operation
        log_api_call(
            event_type=AuditEventType.KEY_EXPORT,
            description=f"Exported JWKS",
            metadata={
                'num_keys': len(jwks)
            }
        )

        return jsonify(jwks_data)

    except Exception as e:
        logger.error(f"Error getting JWKS: {str(e)}")
        return jsonify({"error": f"Failed to get JWKS: {str(e)}"}), 500


# Register HSM API blueprint
if PKCS11_AVAILABLE and hsm_key_manager:
    try:
        from .hsm_api import hsm_api
        app.register_blueprint(hsm_api)
        logger.info("Registered HSM API blueprint")
    except Exception as e:
        logger.warning(f"Failed to register HSM API blueprint: {str(e)}")

# Register Plugins API blueprint
if plugin_manager:
    try:
        from .plugins_api import plugins_api
        app.register_blueprint(plugins_api)
        logger.info("Registered Plugins API blueprint")
    except Exception as e:
        logger.warning(f"Failed to register Plugins API blueprint: {str(e)}")

if __name__ == '__main__':
    app.run(debug=app.config.get('DEBUG', False),
            host=app.config.get('HOST', '0.0.0.0'),
            port=app.config.get('PORT', 5000))
