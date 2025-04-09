"""
HSM API Module

This module provides RESTful API endpoints for Hardware Security Module (HSM) operations.
It allows clients to interact with HSMs through the PKCS#11 standard.
"""

import os
import json
import base64
import logging
from typing import Dict, Any, Optional, List

from flask import Blueprint, request, jsonify, g
from flasgger import swag_from

from ..core.hsm_key_manager import HSMKeyManager, PKCS11_AVAILABLE
from .rest_api import requires_auth, log_api_call
from ..core.crypto_audit import AuditEventType, AuditSeverity

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hsm_api")

# Create Blueprint
hsm_api = Blueprint('hsm_api', __name__)

# Global HSM key manager instance
hsm_key_manager = None

def initialize_hsm_api(key_manager, config):
    """
    Initialize the HSM API with the given key manager and configuration.
    
    Args:
        key_manager: KeyManager instance
        config: API configuration
    
    Returns:
        True if initialization was successful, False otherwise
    """
    global hsm_key_manager
    
    if not PKCS11_AVAILABLE:
        logger.warning("PKCS#11 support is not available. HSM API will not work.")
        return False
    
    # Get HSM configuration from environment or config
    library_path = os.environ.get('HSM_LIBRARY_PATH', config.get('HSM_LIBRARY_PATH'))
    token_label = os.environ.get('HSM_TOKEN_LABEL', config.get('HSM_TOKEN_LABEL'))
    pin = os.environ.get('HSM_PIN', config.get('HSM_PIN'))
    
    if not library_path:
        logger.warning("HSM library path not configured. HSM API will not work.")
        return False
    
    try:
        # Initialize HSM key manager
        hsm_key_manager = HSMKeyManager(key_manager, library_path, token_label, pin)
        logger.info(f"Initialized HSM API with library: {library_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize HSM API: {str(e)}")
        return False

@hsm_api.route('/api/v1/hsm/slots', methods=['GET'])
@requires_auth
@swag_from('swagger_docs/hsm_slots.yml')
def list_slots():
    """List available HSM slots."""
    if not hsm_key_manager:
        return jsonify({"error": "HSM support is not available"}), 501
    
    try:
        # List slots
        slots = hsm_key_manager.list_slots()
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.HSM_OPERATION,
            description="Listed HSM slots",
            metadata={
                'num_slots': len(slots)
            }
        )
        
        return jsonify({"slots": slots})
    
    except Exception as e:
        logger.error(f"Error listing HSM slots: {str(e)}")
        return jsonify({"error": f"Failed to list HSM slots: {str(e)}"}), 500

@hsm_api.route('/api/v1/hsm/keys', methods=['GET'])
@requires_auth
def list_keys():
    """List keys on the HSM."""
    if not hsm_key_manager:
        return jsonify({"error": "HSM support is not available"}), 501
    
    try:
        # List keys
        keys = hsm_key_manager.list_keys()
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.HSM_OPERATION,
            description="Listed HSM keys",
            metadata={
                'num_keys': len(keys)
            }
        )
        
        return jsonify({"keys": keys})
    
    except Exception as e:
        logger.error(f"Error listing HSM keys: {str(e)}")
        return jsonify({"error": f"Failed to list HSM keys: {str(e)}"}), 500

@hsm_api.route('/api/v1/hsm/keys', methods=['POST'])
@requires_auth
@swag_from('swagger_docs/hsm_generate_key.yml')
def generate_key():
    """Generate a key on the HSM."""
    if not hsm_key_manager:
        return jsonify({"error": "HSM support is not available"}), 501
    
    try:
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request: no JSON data"}), 400
        
        # Extract parameters
        key_type = data.get('key_type')
        key_size = data.get('key_size')
        key_label = data.get('key_label')
        extractable = data.get('extractable', False)
        
        # Validate parameters
        if not key_type:
            return jsonify({"error": "Missing required parameter: key_type"}), 400
        if not key_size:
            return jsonify({"error": "Missing required parameter: key_size"}), 400
        if not key_label:
            return jsonify({"error": "Missing required parameter: key_label"}), 400
        
        # Generate key
        key_id = hsm_key_manager.generate_key(
            key_type=key_type,
            key_size=key_size,
            key_label=key_label,
            extractable=extractable
        )
        
        # Get key info
        key_info = hsm_key_manager.hsm_keys.get(key_id, {})
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.KEY_GENERATION,
            description=f"Generated {key_type} key on HSM",
            metadata={
                'key_id': key_id,
                'key_type': key_type,
                'key_size': key_size,
                'key_label': key_label,
                'hsm_backed': True
            }
        )
        
        return jsonify({
            "key_id": key_id,
            "key_type": key_type,
            "key_label": key_label,
            "algorithm": key_info.get('algorithm', key_type),
            "extractable": extractable
        }), 201
    
    except Exception as e:
        logger.error(f"Error generating HSM key: {str(e)}")
        return jsonify({"error": f"Failed to generate HSM key: {str(e)}"}), 500

@hsm_api.route('/api/v1/hsm/encrypt', methods=['POST'])
@requires_auth
@swag_from('swagger_docs/hsm_encrypt.yml')
def encrypt():
    """Encrypt data using an HSM key."""
    if not hsm_key_manager:
        return jsonify({"error": "HSM support is not available"}), 501
    
    try:
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request: no JSON data"}), 400
        
        # Extract parameters
        data_b64 = data.get('data')
        key_id = data.get('key_id')
        algorithm = data.get('algorithm', 'AES-GCM')
        params = data.get('params', {})
        
        # Validate parameters
        if not data_b64:
            return jsonify({"error": "Missing required parameter: data"}), 400
        if not key_id:
            return jsonify({"error": "Missing required parameter: key_id"}), 400
        
        # Decode base64 data
        try:
            binary_data = base64.b64decode(data_b64)
        except Exception:
            return jsonify({"error": "Invalid data: must be base64 encoded"}), 400
        
        # Process params
        processed_params = {}
        if params:
            for param_name, param_value in params.items():
                if param_name in ('iv', 'aad') and isinstance(param_value, str):
                    try:
                        processed_params[param_name] = base64.b64decode(param_value)
                    except Exception:
                        return jsonify({"error": f"Invalid {param_name}: must be base64 encoded"}), 400
                else:
                    processed_params[param_name] = param_value
        
        # Encrypt data
        result = hsm_key_manager.encrypt(
            data=binary_data,
            key_id=key_id,
            algorithm=algorithm,
            params=processed_params
        )
        
        # Convert binary values to base64
        response = {"algorithm": algorithm}
        for key, value in result.items():
            if isinstance(value, bytes):
                response[key] = base64.b64encode(value).decode('ascii')
            else:
                response[key] = value
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.ENCRYPTION,
            description=f"Encrypted data with HSM key using {algorithm}",
            metadata={
                'key_id': key_id,
                'algorithm': algorithm,
                'hsm_backed': True
            }
        )
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Error encrypting with HSM key: {str(e)}")
        return jsonify({"error": f"Failed to encrypt with HSM key: {str(e)}"}), 500

@hsm_api.route('/api/v1/hsm/decrypt', methods=['POST'])
@requires_auth
def decrypt():
    """Decrypt data using an HSM key."""
    if not hsm_key_manager:
        return jsonify({"error": "HSM support is not available"}), 501
    
    try:
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request: no JSON data"}), 400
        
        # Extract parameters
        ciphertext_b64 = data.get('ciphertext')
        key_id = data.get('key_id')
        algorithm = data.get('algorithm', 'AES-GCM')
        params = data.get('params', {})
        
        # Validate parameters
        if not ciphertext_b64:
            return jsonify({"error": "Missing required parameter: ciphertext"}), 400
        if not key_id:
            return jsonify({"error": "Missing required parameter: key_id"}), 400
        
        # Decode base64 data
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
        except Exception:
            return jsonify({"error": "Invalid ciphertext: must be base64 encoded"}), 400
        
        # Process params
        processed_params = {}
        if params:
            for param_name, param_value in params.items():
                if param_name in ('iv', 'aad', 'tag') and isinstance(param_value, str):
                    try:
                        processed_params[param_name] = base64.b64decode(param_value)
                    except Exception:
                        return jsonify({"error": f"Invalid {param_name}: must be base64 encoded"}), 400
                else:
                    processed_params[param_name] = param_value
        
        # Decrypt data
        plaintext = hsm_key_manager.decrypt(
            ciphertext=ciphertext,
            key_id=key_id,
            algorithm=algorithm,
            params=processed_params
        )
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.DECRYPTION,
            description=f"Decrypted data with HSM key using {algorithm}",
            metadata={
                'key_id': key_id,
                'algorithm': algorithm,
                'hsm_backed': True
            }
        )
        
        return jsonify({
            "plaintext": base64.b64encode(plaintext).decode('ascii'),
            "algorithm": algorithm
        })
    
    except Exception as e:
        logger.error(f"Error decrypting with HSM key: {str(e)}")
        return jsonify({"error": f"Failed to decrypt with HSM key: {str(e)}"}), 500

@hsm_api.route('/api/v1/hsm/sign', methods=['POST'])
@requires_auth
def sign():
    """Sign data using an HSM key."""
    if not hsm_key_manager:
        return jsonify({"error": "HSM support is not available"}), 501
    
    try:
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request: no JSON data"}), 400
        
        # Extract parameters
        data_b64 = data.get('data')
        key_id = data.get('key_id')
        algorithm = data.get('algorithm', 'RSA-SHA256')
        params = data.get('params', {})
        
        # Validate parameters
        if not data_b64:
            return jsonify({"error": "Missing required parameter: data"}), 400
        if not key_id:
            return jsonify({"error": "Missing required parameter: key_id"}), 400
        
        # Decode base64 data
        try:
            binary_data = base64.b64decode(data_b64)
        except Exception:
            return jsonify({"error": "Invalid data: must be base64 encoded"}), 400
        
        # Sign data
        signature = hsm_key_manager.sign(
            data=binary_data,
            key_id=key_id,
            algorithm=algorithm,
            params=params
        )
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.SIGNATURE,
            description=f"Signed data with HSM key using {algorithm}",
            metadata={
                'key_id': key_id,
                'algorithm': algorithm,
                'hsm_backed': True
            }
        )
        
        return jsonify({
            "signature": base64.b64encode(signature).decode('ascii'),
            "algorithm": algorithm
        })
    
    except Exception as e:
        logger.error(f"Error signing with HSM key: {str(e)}")
        return jsonify({"error": f"Failed to sign with HSM key: {str(e)}"}), 500

@hsm_api.route('/api/v1/hsm/verify', methods=['POST'])
@requires_auth
def verify():
    """Verify a signature using an HSM key."""
    if not hsm_key_manager:
        return jsonify({"error": "HSM support is not available"}), 501
    
    try:
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request: no JSON data"}), 400
        
        # Extract parameters
        data_b64 = data.get('data')
        signature_b64 = data.get('signature')
        key_id = data.get('key_id')
        algorithm = data.get('algorithm', 'RSA-SHA256')
        params = data.get('params', {})
        
        # Validate parameters
        if not data_b64:
            return jsonify({"error": "Missing required parameter: data"}), 400
        if not signature_b64:
            return jsonify({"error": "Missing required parameter: signature"}), 400
        if not key_id:
            return jsonify({"error": "Missing required parameter: key_id"}), 400
        
        # Decode base64 data
        try:
            binary_data = base64.b64decode(data_b64)
            signature = base64.b64decode(signature_b64)
        except Exception:
            return jsonify({"error": "Invalid data or signature: must be base64 encoded"}), 400
        
        # Verify signature
        is_valid = hsm_key_manager.verify(
            data=binary_data,
            signature=signature,
            key_id=key_id,
            algorithm=algorithm,
            params=params
        )
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.VERIFICATION,
            description=f"Verified signature with HSM key using {algorithm}",
            metadata={
                'key_id': key_id,
                'algorithm': algorithm,
                'hsm_backed': True,
                'valid': is_valid
            }
        )
        
        return jsonify({
            "valid": is_valid,
            "algorithm": algorithm
        })
    
    except Exception as e:
        logger.error(f"Error verifying with HSM key: {str(e)}")
        return jsonify({"error": f"Failed to verify with HSM key: {str(e)}"}), 500

@hsm_api.route('/api/v1/hsm/keys/<key_id>', methods=['DELETE'])
@requires_auth
def delete_key(key_id):
    """Delete a key from the HSM."""
    if not hsm_key_manager:
        return jsonify({"error": "HSM support is not available"}), 501
    
    try:
        # Delete key
        result = hsm_key_manager.delete_key(key_id)
        
        if not result:
            return jsonify({"error": f"Key not found: {key_id}"}), 404
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.KEY_DELETION,
            description=f"Deleted key from HSM",
            metadata={
                'key_id': key_id,
                'hsm_backed': True
            }
        )
        
        return jsonify({"success": True})
    
    except Exception as e:
        logger.error(f"Error deleting HSM key: {str(e)}")
        return jsonify({"error": f"Failed to delete HSM key: {str(e)}"}), 500
