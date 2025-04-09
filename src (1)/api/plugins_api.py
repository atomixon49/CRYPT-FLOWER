"""
Plugins API Module

This module provides RESTful API endpoints for document management system plugins.
It allows clients to interact with document management systems through plugins.
"""

import os
import json
import base64
import logging
from typing import Dict, Any, Optional, List

from flask import Blueprint, request, jsonify, g
from flasgger import swag_from

from ..plugins.plugin_manager import PluginManager
from .rest_api import requires_auth, log_api_call
from ..core.crypto_audit import AuditEventType, AuditSeverity

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("plugins_api")

# Create Blueprint
plugins_api = Blueprint('plugins_api', __name__)

# Global plugin manager instance
plugin_manager = None

def initialize_plugins_api():
    """
    Initialize the plugins API.
    
    Returns:
        True if initialization was successful, False otherwise
    """
    global plugin_manager
    
    try:
        # Initialize plugin manager
        plugin_manager = PluginManager()
        logger.info(f"Initialized plugins API with {len(plugin_manager.plugin_classes)} plugins")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize plugins API: {str(e)}")
        return False

@plugins_api.route('/api/v1/plugins', methods=['GET'])
@requires_auth
@swag_from('swagger_docs/plugins_list.yml')
def list_plugins():
    """List available document management system plugins."""
    if not plugin_manager:
        return jsonify({"error": "Plugin support is not available"}), 501
    
    try:
        # List plugins
        plugins = plugin_manager.list_plugins()
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.PLUGIN_OPERATION,
            description="Listed plugins",
            metadata={
                'num_plugins': len(plugins)
            }
        )
        
        return jsonify({"plugins": plugins})
    
    except Exception as e:
        logger.error(f"Error listing plugins: {str(e)}")
        return jsonify({"error": f"Failed to list plugins: {str(e)}"}), 500

@plugins_api.route('/api/v1/plugins/<plugin_id>/configure', methods=['POST'])
@requires_auth
def configure_plugin(plugin_id):
    """Configure a document management system plugin."""
    if not plugin_manager:
        return jsonify({"error": "Plugin support is not available"}), 501
    
    try:
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request: no JSON data"}), 400
        
        # Configure plugin
        result = plugin_manager.configure_plugin(plugin_id, data)
        
        if not result:
            return jsonify({"error": f"Failed to configure plugin: {plugin_id}"}), 400
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.PLUGIN_OPERATION,
            description=f"Configured plugin: {plugin_id}",
            metadata={
                'plugin_id': plugin_id
            }
        )
        
        return jsonify({"success": True})
    
    except Exception as e:
        logger.error(f"Error configuring plugin {plugin_id}: {str(e)}")
        return jsonify({"error": f"Failed to configure plugin: {str(e)}"}), 500

@plugins_api.route('/api/v1/plugins/<plugin_id>/unconfigure', methods=['POST'])
@requires_auth
def unconfigure_plugin(plugin_id):
    """Remove configuration for a document management system plugin."""
    if not plugin_manager:
        return jsonify({"error": "Plugin support is not available"}), 501
    
    try:
        # Unconfigure plugin
        result = plugin_manager.unconfigure_plugin(plugin_id)
        
        if not result:
            return jsonify({"error": f"Plugin not configured: {plugin_id}"}), 400
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.PLUGIN_OPERATION,
            description=f"Unconfigured plugin: {plugin_id}",
            metadata={
                'plugin_id': plugin_id
            }
        )
        
        return jsonify({"success": True})
    
    except Exception as e:
        logger.error(f"Error unconfiguring plugin {plugin_id}: {str(e)}")
        return jsonify({"error": f"Failed to unconfigure plugin: {str(e)}"}), 500

@plugins_api.route('/api/v1/plugins/<plugin_id>/documents', methods=['GET'])
@requires_auth
def list_documents(plugin_id):
    """List documents in a folder using a plugin."""
    if not plugin_manager:
        return jsonify({"error": "Plugin support is not available"}), 501
    
    try:
        # Get plugin
        plugin = plugin_manager.get_plugin(plugin_id)
        if not plugin:
            return jsonify({"error": f"Plugin not found: {plugin_id}"}), 404
        
        # Check if plugin is connected
        if not plugin.is_connected():
            return jsonify({"error": f"Plugin not connected: {plugin_id}"}), 400
        
        # Get folder path from query parameters
        folder_path = request.args.get('folder_path', '/')
        
        # List documents
        documents = plugin.list_documents(folder_path)
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.PLUGIN_OPERATION,
            description=f"Listed documents using plugin: {plugin_id}",
            metadata={
                'plugin_id': plugin_id,
                'folder_path': folder_path,
                'num_documents': len(documents)
            }
        )
        
        return jsonify({"documents": documents})
    
    except Exception as e:
        logger.error(f"Error listing documents with plugin {plugin_id}: {str(e)}")
        return jsonify({"error": f"Failed to list documents: {str(e)}"}), 500

@plugins_api.route('/api/v1/plugins/<plugin_id>/documents/<path:document_id>', methods=['GET'])
@requires_auth
def get_document(plugin_id, document_id):
    """Get a document using a plugin."""
    if not plugin_manager:
        return jsonify({"error": "Plugin support is not available"}), 501
    
    try:
        # Get plugin
        plugin = plugin_manager.get_plugin(plugin_id)
        if not plugin:
            return jsonify({"error": f"Plugin not found: {plugin_id}"}), 404
        
        # Check if plugin is connected
        if not plugin.is_connected():
            return jsonify({"error": f"Plugin not connected: {plugin_id}"}), 400
        
        # Get document
        content, metadata = plugin.get_document(document_id)
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.PLUGIN_OPERATION,
            description=f"Retrieved document using plugin: {plugin_id}",
            metadata={
                'plugin_id': plugin_id,
                'document_id': document_id
            }
        )
        
        # Return document content and metadata
        return jsonify({
            "content": base64.b64encode(content).decode('ascii'),
            "metadata": metadata
        })
    
    except Exception as e:
        logger.error(f"Error getting document with plugin {plugin_id}: {str(e)}")
        return jsonify({"error": f"Failed to get document: {str(e)}"}), 500

@plugins_api.route('/api/v1/plugins/<plugin_id>/encrypt', methods=['POST'])
@requires_auth
@swag_from('swagger_docs/plugin_encrypt_document.yml')
def encrypt_document(plugin_id):
    """Encrypt a document using a plugin."""
    if not plugin_manager:
        return jsonify({"error": "Plugin support is not available"}), 501
    
    try:
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request: no JSON data"}), 400
        
        # Extract parameters
        document_id = data.get('document_id')
        key_id = data.get('key_id')
        algorithm = data.get('algorithm', 'AES-GCM')
        metadata = data.get('metadata', {})
        connection_params = data.get('connection_params')
        
        # Validate parameters
        if not document_id:
            return jsonify({"error": "Missing required parameter: document_id"}), 400
        if not key_id:
            return jsonify({"error": "Missing required parameter: key_id"}), 400
        
        # Get plugin
        plugin = plugin_manager.get_plugin(plugin_id)
        if not plugin:
            return jsonify({"error": f"Plugin not found: {plugin_id}"}), 404
        
        # Connect if connection parameters provided
        if connection_params:
            if not plugin.connect(connection_params):
                return jsonify({"error": f"Failed to connect to plugin: {plugin_id}"}), 400
        
        # Check if plugin is connected
        if not plugin.is_connected():
            return jsonify({"error": f"Plugin not connected: {plugin_id}"}), 400
        
        # Encrypt document
        encrypted_doc_id = plugin.encrypt_document(document_id, key_id, algorithm, metadata)
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.ENCRYPTION,
            description=f"Encrypted document using plugin: {plugin_id}",
            metadata={
                'plugin_id': plugin_id,
                'document_id': document_id,
                'key_id': key_id,
                'algorithm': algorithm
            }
        )
        
        return jsonify({
            "document_id": encrypted_doc_id,
            "algorithm": algorithm,
            "key_id": key_id,
            "timestamp": metadata.get('timestamp'),
            "metadata": metadata
        })
    
    except Exception as e:
        logger.error(f"Error encrypting document with plugin {plugin_id}: {str(e)}")
        return jsonify({"error": f"Failed to encrypt document: {str(e)}"}), 500

@plugins_api.route('/api/v1/plugins/<plugin_id>/decrypt', methods=['POST'])
@requires_auth
def decrypt_document(plugin_id):
    """Decrypt a document using a plugin."""
    if not plugin_manager:
        return jsonify({"error": "Plugin support is not available"}), 501
    
    try:
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request: no JSON data"}), 400
        
        # Extract parameters
        document_id = data.get('document_id')
        key_id = data.get('key_id')
        connection_params = data.get('connection_params')
        
        # Validate parameters
        if not document_id:
            return jsonify({"error": "Missing required parameter: document_id"}), 400
        
        # Get plugin
        plugin = plugin_manager.get_plugin(plugin_id)
        if not plugin:
            return jsonify({"error": f"Plugin not found: {plugin_id}"}), 404
        
        # Connect if connection parameters provided
        if connection_params:
            if not plugin.connect(connection_params):
                return jsonify({"error": f"Failed to connect to plugin: {plugin_id}"}), 400
        
        # Check if plugin is connected
        if not plugin.is_connected():
            return jsonify({"error": f"Plugin not connected: {plugin_id}"}), 400
        
        # Decrypt document
        decrypted_doc_id = plugin.decrypt_document(document_id, key_id)
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.DECRYPTION,
            description=f"Decrypted document using plugin: {plugin_id}",
            metadata={
                'plugin_id': plugin_id,
                'document_id': document_id,
                'key_id': key_id
            }
        )
        
        return jsonify({
            "document_id": decrypted_doc_id
        })
    
    except Exception as e:
        logger.error(f"Error decrypting document with plugin {plugin_id}: {str(e)}")
        return jsonify({"error": f"Failed to decrypt document: {str(e)}"}), 500

@plugins_api.route('/api/v1/plugins/<plugin_id>/sign', methods=['POST'])
@requires_auth
def sign_document(plugin_id):
    """Sign a document using a plugin."""
    if not plugin_manager:
        return jsonify({"error": "Plugin support is not available"}), 501
    
    try:
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request: no JSON data"}), 400
        
        # Extract parameters
        document_id = data.get('document_id')
        key_id = data.get('key_id')
        algorithm = data.get('algorithm', 'RSA-SHA256')
        metadata = data.get('metadata', {})
        connection_params = data.get('connection_params')
        
        # Validate parameters
        if not document_id:
            return jsonify({"error": "Missing required parameter: document_id"}), 400
        if not key_id:
            return jsonify({"error": "Missing required parameter: key_id"}), 400
        
        # Get plugin
        plugin = plugin_manager.get_plugin(plugin_id)
        if not plugin:
            return jsonify({"error": f"Plugin not found: {plugin_id}"}), 404
        
        # Connect if connection parameters provided
        if connection_params:
            if not plugin.connect(connection_params):
                return jsonify({"error": f"Failed to connect to plugin: {plugin_id}"}), 400
        
        # Check if plugin is connected
        if not plugin.is_connected():
            return jsonify({"error": f"Plugin not connected: {plugin_id}"}), 400
        
        # Sign document
        signature_id = plugin.sign_document(document_id, key_id, algorithm, metadata)
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.SIGNATURE,
            description=f"Signed document using plugin: {plugin_id}",
            metadata={
                'plugin_id': plugin_id,
                'document_id': document_id,
                'key_id': key_id,
                'algorithm': algorithm
            }
        )
        
        return jsonify({
            "signature_id": signature_id,
            "algorithm": algorithm,
            "key_id": key_id,
            "document_id": document_id,
            "timestamp": metadata.get('timestamp')
        })
    
    except Exception as e:
        logger.error(f"Error signing document with plugin {plugin_id}: {str(e)}")
        return jsonify({"error": f"Failed to sign document: {str(e)}"}), 500

@plugins_api.route('/api/v1/plugins/<plugin_id>/verify', methods=['POST'])
@requires_auth
def verify_document(plugin_id):
    """Verify a document signature using a plugin."""
    if not plugin_manager:
        return jsonify({"error": "Plugin support is not available"}), 501
    
    try:
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request: no JSON data"}), 400
        
        # Extract parameters
        document_id = data.get('document_id')
        signature_id = data.get('signature_id')
        key_id = data.get('key_id')
        connection_params = data.get('connection_params')
        
        # Validate parameters
        if not document_id:
            return jsonify({"error": "Missing required parameter: document_id"}), 400
        if not signature_id:
            return jsonify({"error": "Missing required parameter: signature_id"}), 400
        
        # Get plugin
        plugin = plugin_manager.get_plugin(plugin_id)
        if not plugin:
            return jsonify({"error": f"Plugin not found: {plugin_id}"}), 404
        
        # Connect if connection parameters provided
        if connection_params:
            if not plugin.connect(connection_params):
                return jsonify({"error": f"Failed to connect to plugin: {plugin_id}"}), 400
        
        # Check if plugin is connected
        if not plugin.is_connected():
            return jsonify({"error": f"Plugin not connected: {plugin_id}"}), 400
        
        # Verify document
        is_valid = plugin.verify_document(document_id, signature_id, key_id)
        
        # Log the operation
        log_api_call(
            event_type=AuditEventType.VERIFICATION,
            description=f"Verified document using plugin: {plugin_id}",
            metadata={
                'plugin_id': plugin_id,
                'document_id': document_id,
                'signature_id': signature_id,
                'key_id': key_id,
                'valid': is_valid
            }
        )
        
        return jsonify({
            "valid": is_valid,
            "document_id": document_id,
            "signature_id": signature_id
        })
    
    except Exception as e:
        logger.error(f"Error verifying document with plugin {plugin_id}: {str(e)}")
        return jsonify({"error": f"Failed to verify document: {str(e)}"}), 500
