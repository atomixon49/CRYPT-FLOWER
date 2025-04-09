"""
SharePoint Plugin

This module provides a plugin for integrating with Microsoft SharePoint.
It allows for browsing, encrypting, decrypting, signing, and verifying
documents stored in SharePoint.
"""

import os
import io
import tempfile
import logging
import base64
import json
from typing import Dict, Any, Optional, List, Union, BinaryIO, Tuple

# Try to import SharePoint libraries
try:
    from office365.runtime.auth.authentication_context import AuthenticationContext
    from office365.sharepoint.client_context import ClientContext
    from office365.sharepoint.files.file import File
    from office365.sharepoint.folders.folder import Folder
    SHAREPOINT_AVAILABLE = True
except ImportError:
    SHAREPOINT_AVAILABLE = False

from ..plugin_interface import DocumentManagementPlugin

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sharepoint_plugin")


class SharePointPlugin(DocumentManagementPlugin):
    """
    Plugin for Microsoft SharePoint document management system.
    
    This plugin provides integration with SharePoint, allowing for
    browsing, encrypting, decrypting, signing, and verifying documents
    stored in SharePoint.
    """
    
    def __init__(self):
        """
        Initialize the SharePoint plugin.
        """
        self.ctx = None
        self.site_url = None
        self.username = None
        self.connected = False
        
        # Check if SharePoint libraries are available
        if not SHAREPOINT_AVAILABLE:
            logger.warning("SharePoint libraries not available. Install with: pip install Office365-REST-Python-Client")
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """
        Get information about the plugin.
        
        Returns:
            Dictionary with plugin information
        """
        return {
            'id': 'sharepoint',
            'name': 'SharePoint Plugin',
            'description': 'Plugin for Microsoft SharePoint document management system',
            'version': '1.0.0',
            'system_type': 'SharePoint',
            'capabilities': ['read', 'write', 'encrypt', 'decrypt', 'sign', 'verify'],
            'available': SHAREPOINT_AVAILABLE
        }
    
    def connect(self, connection_params: Dict[str, Any]) -> bool:
        """
        Connect to SharePoint.
        
        Args:
            connection_params: Dictionary with connection parameters including:
                - site_url: URL of the SharePoint site
                - username: Username for authentication
                - password: Password for authentication
                - auth_type: Authentication type ('username_password' or 'app')
                - client_id: Client ID for app authentication
                - client_secret: Client secret for app authentication
        
        Returns:
            True if connection was successful, False otherwise
        
        Raises:
            ValueError: If connection parameters are invalid
            ImportError: If SharePoint libraries are not available
        """
        if not SHAREPOINT_AVAILABLE:
            raise ImportError("SharePoint libraries not available. Install with: pip install Office365-REST-Python-Client")
        
        # Extract connection parameters
        site_url = connection_params.get('site_url')
        auth_type = connection_params.get('auth_type', 'username_password')
        
        if not site_url:
            raise ValueError("Missing required parameter: site_url")
        
        try:
            # Create authentication context
            auth_ctx = None
            
            if auth_type == 'username_password':
                # Username/password authentication
                username = connection_params.get('username')
                password = connection_params.get('password')
                
                if not username or not password:
                    raise ValueError("Missing required parameters for username/password authentication")
                
                auth_ctx = AuthenticationContext(site_url)
                auth_ctx.acquire_token_for_user(username, password)
                self.username = username
            
            elif auth_type == 'app':
                # App authentication
                client_id = connection_params.get('client_id')
                client_secret = connection_params.get('client_secret')
                
                if not client_id or not client_secret:
                    raise ValueError("Missing required parameters for app authentication")
                
                auth_ctx = AuthenticationContext(site_url)
                auth_ctx.acquire_token_for_app(client_id, client_secret)
                self.username = f"App:{client_id}"
            
            else:
                raise ValueError(f"Unsupported authentication type: {auth_type}")
            
            # Create client context
            self.ctx = ClientContext(site_url, auth_ctx)
            
            # Test connection
            web = self.ctx.web
            self.ctx.load(web)
            self.ctx.execute_query()
            
            # Store connection information
            self.site_url = site_url
            self.connected = True
            
            logger.info(f"Connected to SharePoint site: {site_url}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to connect to SharePoint: {str(e)}")
            self.ctx = None
            self.site_url = None
            self.username = None
            self.connected = False
            return False
    
    def disconnect(self) -> bool:
        """
        Disconnect from SharePoint.
        
        Returns:
            True if disconnection was successful, False otherwise
        """
        self.ctx = None
        self.site_url = None
        self.username = None
        self.connected = False
        return True
    
    def is_connected(self) -> bool:
        """
        Check if the plugin is connected to SharePoint.
        
        Returns:
            True if connected, False otherwise
        """
        return self.connected
    
    def list_documents(self, folder_path: str) -> List[Dict[str, Any]]:
        """
        List documents in a SharePoint folder.
        
        Args:
            folder_path: Path to the folder
        
        Returns:
            List of dictionaries with document information
        
        Raises:
            ValueError: If the folder path is invalid
            ConnectionError: If not connected to SharePoint
        """
        if not self.is_connected():
            raise ConnectionError("Not connected to SharePoint")
        
        try:
            # Get folder
            folder = self.ctx.web.get_folder_by_server_relative_url(folder_path)
            self.ctx.load(folder)
            self.ctx.execute_query()
            
            # Get files and subfolders
            files = folder.files
            self.ctx.load(files)
            subfolders = folder.folders
            self.ctx.load(subfolders)
            self.ctx.execute_query()
            
            # Prepare result
            result = []
            
            # Add files
            for file in files:
                result.append({
                    'id': file.serverRelativeUrl,
                    'name': file.name,
                    'type': 'file',
                    'size': file.length,
                    'modified': file.timeLastModified.strftime('%Y-%m-%d %H:%M:%S') if file.timeLastModified else None,
                    'url': f"{self.site_url}{file.serverRelativeUrl}"
                })
            
            # Add subfolders
            for subfolder in subfolders:
                result.append({
                    'id': subfolder.serverRelativeUrl,
                    'name': subfolder.name,
                    'type': 'folder',
                    'modified': subfolder.timeLastModified.strftime('%Y-%m-%d %H:%M:%S') if subfolder.timeLastModified else None,
                    'url': f"{self.site_url}{subfolder.serverRelativeUrl}"
                })
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to list documents in {folder_path}: {str(e)}")
            raise ValueError(f"Failed to list documents: {str(e)}")
    
    def get_document(self, document_id: str) -> Tuple[bytes, Dict[str, Any]]:
        """
        Get a document from SharePoint.
        
        Args:
            document_id: Server relative URL of the document
        
        Returns:
            Tuple containing (document_content, document_metadata)
        
        Raises:
            ValueError: If the document ID is invalid
            ConnectionError: If not connected to SharePoint
            FileNotFoundError: If the document does not exist
        """
        if not self.is_connected():
            raise ConnectionError("Not connected to SharePoint")
        
        try:
            # Get file
            file = self.ctx.web.get_file_by_server_relative_url(document_id)
            self.ctx.load(file)
            self.ctx.execute_query()
            
            # Get file content
            response = File.open_binary(self.ctx, document_id)
            
            # Get file properties
            properties = file.properties
            self.ctx.load(properties)
            self.ctx.execute_query()
            
            # Prepare metadata
            metadata = {
                'id': document_id,
                'name': file.name,
                'size': file.length,
                'modified': file.timeLastModified.strftime('%Y-%m-%d %H:%M:%S') if file.timeLastModified else None,
                'url': f"{self.site_url}{document_id}",
                'properties': {k: v for k, v in properties.items() if v is not None}
            }
            
            return response.content, metadata
        
        except Exception as e:
            logger.error(f"Failed to get document {document_id}: {str(e)}")
            raise FileNotFoundError(f"Failed to get document: {str(e)}")
    
    def save_document(self, document_id: str, content: bytes, metadata: Dict[str, Any]) -> str:
        """
        Save a document to SharePoint.
        
        Args:
            document_id: Server relative URL of the document
            content: Document content
            metadata: Document metadata
        
        Returns:
            Server relative URL of the saved document
        
        Raises:
            ValueError: If the document ID is invalid
            ConnectionError: If not connected to SharePoint
            PermissionError: If the user does not have permission to save the document
        """
        if not self.is_connected():
            raise ConnectionError("Not connected to SharePoint")
        
        try:
            # Upload file
            folder_path = os.path.dirname(document_id)
            file_name = os.path.basename(document_id)
            
            # Get folder
            folder = self.ctx.web.get_folder_by_server_relative_url(folder_path)
            
            # Upload file
            target_file = folder.upload_file(file_name, content)
            self.ctx.execute_query()
            
            # Set metadata if provided
            if metadata and 'properties' in metadata:
                file = self.ctx.web.get_file_by_server_relative_url(document_id)
                list_item = file.listItemAllFields
                self.ctx.load(list_item)
                self.ctx.execute_query()
                
                # Update properties
                for key, value in metadata['properties'].items():
                    list_item.set_property(key, value)
                
                list_item.update()
                self.ctx.execute_query()
            
            return document_id
        
        except Exception as e:
            logger.error(f"Failed to save document {document_id}: {str(e)}")
            raise PermissionError(f"Failed to save document: {str(e)}")
    
    def delete_document(self, document_id: str) -> bool:
        """
        Delete a document from SharePoint.
        
        Args:
            document_id: Server relative URL of the document
        
        Returns:
            True if the document was deleted, False otherwise
        
        Raises:
            ValueError: If the document ID is invalid
            ConnectionError: If not connected to SharePoint
            PermissionError: If the user does not have permission to delete the document
        """
        if not self.is_connected():
            raise ConnectionError("Not connected to SharePoint")
        
        try:
            # Get file
            file = self.ctx.web.get_file_by_server_relative_url(document_id)
            
            # Delete file
            file.delete_object()
            self.ctx.execute_query()
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to delete document {document_id}: {str(e)}")
            raise PermissionError(f"Failed to delete document: {str(e)}")
    
    def encrypt_document(self, document_id: str, key_id: str, algorithm: str, metadata: Dict[str, Any]) -> str:
        """
        Encrypt a document in SharePoint.
        
        Args:
            document_id: Server relative URL of the document
            key_id: ID of the key to use for encryption
            algorithm: Encryption algorithm to use
            metadata: Additional metadata to store with the encrypted document
        
        Returns:
            Server relative URL of the encrypted document
        
        Raises:
            ValueError: If the document ID or key ID is invalid
            ConnectionError: If not connected to SharePoint
            PermissionError: If the user does not have permission to encrypt the document
        """
        if not self.is_connected():
            raise ConnectionError("Not connected to SharePoint")
        
        try:
            # Get document
            content, doc_metadata = self.get_document(document_id)
            
            # Create a temporary file for encryption
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(content)
                temp_path = temp_file.name
            
            try:
                # Import encryption engine
                from ...core.encryption import EncryptionEngine
                from ...core.key_management import KeyManager
                
                # Initialize components
                key_manager = KeyManager()
                encryption_engine = EncryptionEngine()
                
                # Get the key
                key = key_manager.get_key(key_id)
                if not key:
                    raise ValueError(f"Key not found: {key_id}")
                
                # Encrypt the document
                with open(temp_path, 'rb') as f:
                    plaintext = f.read()
                
                # Encrypt the data
                encryption_result = encryption_engine.encrypt(
                    data=plaintext,
                    key=key,
                    algorithm=algorithm
                )
                
                # Prepare encrypted content
                encrypted_content = {
                    'algorithm': encryption_result['algorithm'],
                    'ciphertext': base64.b64encode(encryption_result['ciphertext']).decode('ascii'),
                    'nonce': base64.b64encode(encryption_result['nonce']).decode('ascii'),
                    'tag': base64.b64encode(encryption_result['tag']).decode('ascii') if 'tag' in encryption_result else None,
                    'key_id': key_id,
                    'original_metadata': doc_metadata,
                    'encryption_metadata': metadata
                }
                
                # Convert to JSON
                encrypted_json = json.dumps(encrypted_content).encode('utf-8')
                
                # Save encrypted document
                encrypted_doc_id = f"{document_id}.encrypted"
                return self.save_document(encrypted_doc_id, encrypted_json, metadata)
            
            finally:
                # Clean up temporary file
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
        
        except Exception as e:
            logger.error(f"Failed to encrypt document {document_id}: {str(e)}")
            raise ValueError(f"Failed to encrypt document: {str(e)}")
    
    def decrypt_document(self, document_id: str, key_id: str) -> str:
        """
        Decrypt a document in SharePoint.
        
        Args:
            document_id: Server relative URL of the encrypted document
            key_id: ID of the key to use for decryption
        
        Returns:
            Server relative URL of the decrypted document
        
        Raises:
            ValueError: If the document ID or key ID is invalid
            ConnectionError: If not connected to SharePoint
            PermissionError: If the user does not have permission to decrypt the document
        """
        if not self.is_connected():
            raise ConnectionError("Not connected to SharePoint")
        
        try:
            # Get encrypted document
            content, _ = self.get_document(document_id)
            
            # Parse JSON content
            try:
                encrypted_content = json.loads(content.decode('utf-8'))
            except json.JSONDecodeError:
                raise ValueError("Invalid encrypted document format")
            
            # Extract encryption data
            algorithm = encrypted_content.get('algorithm')
            ciphertext_b64 = encrypted_content.get('ciphertext')
            nonce_b64 = encrypted_content.get('nonce')
            tag_b64 = encrypted_content.get('tag')
            stored_key_id = encrypted_content.get('key_id')
            original_metadata = encrypted_content.get('original_metadata', {})
            
            # Validate data
            if not algorithm or not ciphertext_b64 or not nonce_b64:
                raise ValueError("Invalid encrypted document: missing required fields")
            
            # Use stored key ID if none provided
            if not key_id and stored_key_id:
                key_id = stored_key_id
            
            # Import decryption components
            from ...core.encryption import EncryptionEngine
            from ...core.key_management import KeyManager
            
            # Initialize components
            key_manager = KeyManager()
            encryption_engine = EncryptionEngine()
            
            # Get the key
            key = key_manager.get_key(key_id)
            if not key:
                raise ValueError(f"Key not found: {key_id}")
            
            # Decode base64 data
            ciphertext = base64.b64decode(ciphertext_b64)
            nonce = base64.b64decode(nonce_b64)
            tag = base64.b64decode(tag_b64) if tag_b64 else None
            
            # Prepare encryption result for decryption
            encryption_result = {
                'algorithm': algorithm,
                'ciphertext': ciphertext,
                'nonce': nonce
            }
            
            if tag:
                encryption_result['tag'] = tag
            
            # Decrypt the data
            plaintext = encryption_engine.decrypt(
                encryption_result=encryption_result,
                key=key
            )
            
            # Save decrypted document
            if document_id.endswith('.encrypted'):
                decrypted_doc_id = document_id[:-10]  # Remove .encrypted suffix
            else:
                decrypted_doc_id = f"{document_id}.decrypted"
            
            return self.save_document(decrypted_doc_id, plaintext, original_metadata)
        
        except Exception as e:
            logger.error(f"Failed to decrypt document {document_id}: {str(e)}")
            raise ValueError(f"Failed to decrypt document: {str(e)}")
    
    def sign_document(self, document_id: str, key_id: str, algorithm: str, metadata: Dict[str, Any]) -> str:
        """
        Sign a document in SharePoint.
        
        Args:
            document_id: Server relative URL of the document
            key_id: ID of the key to use for signing
            algorithm: Signature algorithm to use
            metadata: Additional metadata to store with the signature
        
        Returns:
            Server relative URL of the signature file
        
        Raises:
            ValueError: If the document ID or key ID is invalid
            ConnectionError: If not connected to SharePoint
            PermissionError: If the user does not have permission to sign the document
        """
        if not self.is_connected():
            raise ConnectionError("Not connected to SharePoint")
        
        try:
            # Get document
            content, doc_metadata = self.get_document(document_id)
            
            # Import signature components
            from ...core.signatures import SignatureEngine
            from ...core.key_management import KeyManager
            
            # Initialize components
            key_manager = KeyManager()
            signature_engine = SignatureEngine()
            
            # Get the key
            key = key_manager.get_key(key_id)
            if not key:
                raise ValueError(f"Key not found: {key_id}")
            
            # Sign the document
            signature = signature_engine.sign(
                data=content,
                key=key,
                algorithm=algorithm
            )
            
            # Prepare signature content
            signature_content = {
                'algorithm': algorithm,
                'signature': base64.b64encode(signature).decode('ascii'),
                'key_id': key_id,
                'document_id': document_id,
                'document_name': os.path.basename(document_id),
                'document_hash': base64.b64encode(signature_engine.hash(content)).decode('ascii'),
                'timestamp': metadata.get('timestamp', datetime.datetime.now().isoformat()),
                'metadata': metadata
            }
            
            # Convert to JSON
            signature_json = json.dumps(signature_content).encode('utf-8')
            
            # Save signature file
            signature_doc_id = f"{document_id}.sig"
            return self.save_document(signature_doc_id, signature_json, metadata)
        
        except Exception as e:
            logger.error(f"Failed to sign document {document_id}: {str(e)}")
            raise ValueError(f"Failed to sign document: {str(e)}")
    
    def verify_document(self, document_id: str, signature_id: str, key_id: str) -> bool:
        """
        Verify a document signature in SharePoint.
        
        Args:
            document_id: Server relative URL of the document
            signature_id: Server relative URL of the signature file
            key_id: ID of the key to use for verification
        
        Returns:
            True if the signature is valid, False otherwise
        
        Raises:
            ValueError: If the document ID, signature ID, or key ID is invalid
            ConnectionError: If not connected to SharePoint
        """
        if not self.is_connected():
            raise ConnectionError("Not connected to SharePoint")
        
        try:
            # Get document
            content, _ = self.get_document(document_id)
            
            # Get signature file
            signature_content, _ = self.get_document(signature_id)
            
            # Parse JSON content
            try:
                signature_data = json.loads(signature_content.decode('utf-8'))
            except json.JSONDecodeError:
                raise ValueError("Invalid signature format")
            
            # Extract signature data
            algorithm = signature_data.get('algorithm')
            signature_b64 = signature_data.get('signature')
            stored_key_id = signature_data.get('key_id')
            
            # Validate data
            if not algorithm or not signature_b64:
                raise ValueError("Invalid signature: missing required fields")
            
            # Use stored key ID if none provided
            if not key_id and stored_key_id:
                key_id = stored_key_id
            
            # Import signature components
            from ...core.signatures import SignatureEngine
            from ...core.key_management import KeyManager
            
            # Initialize components
            key_manager = KeyManager()
            signature_engine = SignatureEngine()
            
            # Get the key
            key = key_manager.get_key(key_id)
            if not key:
                raise ValueError(f"Key not found: {key_id}")
            
            # Decode base64 signature
            signature = base64.b64decode(signature_b64)
            
            # Verify the signature
            return signature_engine.verify(
                data=content,
                signature=signature,
                key=key,
                algorithm=algorithm
            )
        
        except Exception as e:
            logger.error(f"Failed to verify document {document_id}: {str(e)}")
            raise ValueError(f"Failed to verify document: {str(e)}")
