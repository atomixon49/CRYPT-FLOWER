"""
Plugin Interface Module

This module defines the interface for document management system plugins.
All plugins must implement this interface to be compatible with the system.
"""

import abc
from typing import Dict, Any, Optional, List, Union, BinaryIO, Tuple


class DocumentManagementPlugin(abc.ABC):
    """
    Abstract base class for document management system plugins.
    
    This class defines the interface that all document management system
    plugins must implement. It provides methods for connecting to a document
    management system, browsing documents, and performing cryptographic
    operations on documents.
    """
    
    @abc.abstractmethod
    def get_plugin_info(self) -> Dict[str, Any]:
        """
        Get information about the plugin.
        
        Returns:
            Dictionary with plugin information including:
            - id: Unique identifier for the plugin
            - name: Human-readable name of the plugin
            - description: Description of the plugin
            - version: Plugin version
            - system_type: Type of document management system
            - capabilities: List of supported capabilities
        """
        pass
    
    @abc.abstractmethod
    def connect(self, connection_params: Dict[str, Any]) -> bool:
        """
        Connect to the document management system.
        
        Args:
            connection_params: Dictionary with connection parameters
        
        Returns:
            True if connection was successful, False otherwise
        
        Raises:
            ValueError: If connection parameters are invalid
        """
        pass
    
    @abc.abstractmethod
    def disconnect(self) -> bool:
        """
        Disconnect from the document management system.
        
        Returns:
            True if disconnection was successful, False otherwise
        """
        pass
    
    @abc.abstractmethod
    def is_connected(self) -> bool:
        """
        Check if the plugin is connected to the document management system.
        
        Returns:
            True if connected, False otherwise
        """
        pass
    
    @abc.abstractmethod
    def list_documents(self, folder_path: str) -> List[Dict[str, Any]]:
        """
        List documents in a folder.
        
        Args:
            folder_path: Path to the folder
        
        Returns:
            List of dictionaries with document information
        
        Raises:
            ValueError: If the folder path is invalid
            ConnectionError: If not connected to the document management system
        """
        pass
    
    @abc.abstractmethod
    def get_document(self, document_id: str) -> Tuple[bytes, Dict[str, Any]]:
        """
        Get a document from the document management system.
        
        Args:
            document_id: ID or path of the document
        
        Returns:
            Tuple containing (document_content, document_metadata)
        
        Raises:
            ValueError: If the document ID is invalid
            ConnectionError: If not connected to the document management system
            FileNotFoundError: If the document does not exist
        """
        pass
    
    @abc.abstractmethod
    def save_document(self, document_id: str, content: bytes, metadata: Dict[str, Any]) -> str:
        """
        Save a document to the document management system.
        
        Args:
            document_id: ID or path of the document
            content: Document content
            metadata: Document metadata
        
        Returns:
            ID of the saved document
        
        Raises:
            ValueError: If the document ID is invalid
            ConnectionError: If not connected to the document management system
            PermissionError: If the user does not have permission to save the document
        """
        pass
    
    @abc.abstractmethod
    def delete_document(self, document_id: str) -> bool:
        """
        Delete a document from the document management system.
        
        Args:
            document_id: ID or path of the document
        
        Returns:
            True if the document was deleted, False otherwise
        
        Raises:
            ValueError: If the document ID is invalid
            ConnectionError: If not connected to the document management system
            PermissionError: If the user does not have permission to delete the document
        """
        pass
    
    @abc.abstractmethod
    def encrypt_document(self, document_id: str, key_id: str, algorithm: str, metadata: Dict[str, Any]) -> str:
        """
        Encrypt a document in the document management system.
        
        Args:
            document_id: ID or path of the document
            key_id: ID of the key to use for encryption
            algorithm: Encryption algorithm to use
            metadata: Additional metadata to store with the encrypted document
        
        Returns:
            ID of the encrypted document
        
        Raises:
            ValueError: If the document ID or key ID is invalid
            ConnectionError: If not connected to the document management system
            PermissionError: If the user does not have permission to encrypt the document
        """
        pass
    
    @abc.abstractmethod
    def decrypt_document(self, document_id: str, key_id: str) -> str:
        """
        Decrypt a document in the document management system.
        
        Args:
            document_id: ID or path of the document
            key_id: ID of the key to use for decryption
        
        Returns:
            ID of the decrypted document
        
        Raises:
            ValueError: If the document ID or key ID is invalid
            ConnectionError: If not connected to the document management system
            PermissionError: If the user does not have permission to decrypt the document
        """
        pass
    
    @abc.abstractmethod
    def sign_document(self, document_id: str, key_id: str, algorithm: str, metadata: Dict[str, Any]) -> str:
        """
        Sign a document in the document management system.
        
        Args:
            document_id: ID or path of the document
            key_id: ID of the key to use for signing
            algorithm: Signature algorithm to use
            metadata: Additional metadata to store with the signature
        
        Returns:
            ID or path of the signature file
        
        Raises:
            ValueError: If the document ID or key ID is invalid
            ConnectionError: If not connected to the document management system
            PermissionError: If the user does not have permission to sign the document
        """
        pass
    
    @abc.abstractmethod
    def verify_document(self, document_id: str, signature_id: str, key_id: str) -> bool:
        """
        Verify a document signature in the document management system.
        
        Args:
            document_id: ID or path of the document
            signature_id: ID or path of the signature file
            key_id: ID of the key to use for verification
        
        Returns:
            True if the signature is valid, False otherwise
        
        Raises:
            ValueError: If the document ID, signature ID, or key ID is invalid
            ConnectionError: If not connected to the document management system
        """
        pass
