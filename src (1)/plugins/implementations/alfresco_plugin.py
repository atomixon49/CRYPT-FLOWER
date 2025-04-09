"""
Alfresco Plugin

Plugin para integración con el sistema de gestión documental Alfresco.
"""

import os
import io
import json
import base64
import logging
import requests
from typing import Dict, Any, Optional, List, Tuple

from ..plugin_interface import DocumentManagementPlugin

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("alfresco_plugin")

class AlfrescoPlugin(DocumentManagementPlugin):
    """Plugin para Alfresco Content Services."""
    
    def __init__(self):
        """Inicializar el plugin de Alfresco."""
        self.base_url = None
        self.auth = None
        self.session = None
        self.connected = False
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """Obtener información del plugin."""
        return {
            'id': 'alfresco',
            'name': 'Alfresco Plugin',
            'description': 'Plugin para Alfresco Content Services',
            'version': '1.0.0',
            'system_type': 'Alfresco',
            'capabilities': ['read', 'write', 'encrypt', 'decrypt', 'sign', 'verify']
        }
    
    def connect(self, connection_params: Dict[str, Any]) -> bool:
        """Conectar a Alfresco."""
        try:
            self.base_url = connection_params.get('url')
            username = connection_params.get('username')
            password = connection_params.get('password')
            
            if not self.base_url or not username or not password:
                raise ValueError("Se requieren URL, usuario y contraseña")
            
            # Asegurar que la URL termina con /
            if not self.base_url.endswith('/'):
                self.base_url += '/'
            
            # Crear sesión
            self.session = requests.Session()
            self.auth = (username, password)
            
            # Verificar conexión
            response = self.session.get(
                f"{self.base_url}api/discovery",
                auth=self.auth
            )
            response.raise_for_status()
            
            self.connected = True
            logger.info(f"Conectado a Alfresco: {self.base_url}")
            return True
            
        except Exception as e:
            logger.error(f"Error al conectar a Alfresco: {str(e)}")
            self.session = None
            self.auth = None
            self.connected = False
            return False
    
    def disconnect(self) -> bool:
        """Desconectar de Alfresco."""
        if self.session:
            self.session.close()
        
        self.session = None
        self.auth = None
        self.connected = False
        return True
    
    def is_connected(self) -> bool:
        """Verificar si está conectado."""
        return self.connected
    
    def list_documents(self, folder_path: str) -> List[Dict[str, Any]]:
        """Listar documentos en una carpeta."""
        if not self.is_connected():
            raise ConnectionError("No conectado a Alfresco")
        
        try:
            # Convertir ruta a nodeId si es necesario
            node_id = self._get_node_id_from_path(folder_path)
            
            # Obtener contenido de la carpeta
            response = self.session.get(
                f"{self.base_url}api/nodes/{node_id}/children",
                auth=self.auth
            )
            response.raise_for_status()
            data = response.json()
            
            result = []
            for entry in data.get('list', {}).get('entries', []):
                node = entry.get('entry', {})
                item = {
                    'id': node.get('id'),
                    'name': node.get('name'),
                    'type': 'folder' if node.get('isFolder') else 'file',
                    'size': node.get('content', {}).get('sizeInBytes') if not node.get('isFolder') else None,
                    'modified': node.get('modifiedAt'),
                    'url': f"{self.base_url}api/nodes/{node.get('id')}/content"
                }
                result.append(item)
            
            return result
            
        except Exception as e:
            logger.error(f"Error al listar documentos: {str(e)}")
            raise ValueError(f"Error al listar documentos: {str(e)}")
    
    def get_document(self, document_id: str) -> Tuple[bytes, Dict[str, Any]]:
        """Obtener un documento."""
        if not self.is_connected():
            raise ConnectionError("No conectado a Alfresco")
        
        try:
            # Convertir ruta a nodeId si es necesario
            node_id = self._get_node_id_from_path(document_id)
            
            # Obtener metadatos
            response = self.session.get(
                f"{self.base_url}api/nodes/{node_id}",
                auth=self.auth
            )
            response.raise_for_status()
            metadata = response.json()
            
            # Obtener contenido
            response = self.session.get(
                f"{self.base_url}api/nodes/{node_id}/content",
                auth=self.auth
            )
            response.raise_for_status()
            content = response.content
            
            # Preparar metadatos
            meta = {
                'id': metadata.get('id'),
                'name': metadata.get('name'),
                'size': metadata.get('content', {}).get('sizeInBytes'),
                'modified': metadata.get('modifiedAt'),
                'url': f"{self.base_url}api/nodes/{metadata.get('id')}/content",
                'properties': metadata.get('properties', {})
            }
            
            return content, meta
            
        except Exception as e:
            logger.error(f"Error al obtener documento: {str(e)}")
            raise FileNotFoundError(f"Error al obtener documento: {str(e)}")
    
    def save_document(self, document_id: str, content: bytes, metadata: Dict[str, Any]) -> str:
        """Guardar un documento."""
        if not self.is_connected():
            raise ConnectionError("No conectado a Alfresco")
        
        try:
            # Determinar si es una actualización o creación
            is_update = False
            parent_id = None
            filename = os.path.basename(document_id)
            
            try:
                node_id = self._get_node_id_from_path(document_id)
                is_update = True
            except:
                # Es una creación, obtener el ID de la carpeta padre
                parent_path = os.path.dirname(document_id)
                parent_id = self._get_node_id_from_path(parent_path)
            
            if is_update:
                # Actualizar documento existente
                files = {'file': (filename, io.BytesIO(content))}
                response = self.session.put(
                    f"{self.base_url}api/nodes/{node_id}/content",
                    auth=self.auth,
                    files=files
                )
                response.raise_for_status()
                result = response.json()
                
                # Actualizar propiedades si se proporcionan
                if metadata and 'properties' in metadata:
                    props_response = self.session.put(
                        f"{self.base_url}api/nodes/{node_id}",
                        auth=self.auth,
                        json={'properties': metadata['properties']}
                    )
                    props_response.raise_for_status()
                
                return result.get('id')
            else:
                # Crear nuevo documento
                files = {'file': (filename, io.BytesIO(content))}
                response = self.session.post(
                    f"{self.base_url}api/nodes/{parent_id}/children",
                    auth=self.auth,
                    files=files
                )
                response.raise_for_status()
                result = response.json()
                
                # Actualizar propiedades si se proporcionan
                if metadata and 'properties' in metadata:
                    props_response = self.session.put(
                        f"{self.base_url}api/nodes/{result.get('id')}",
                        auth=self.auth,
                        json={'properties': metadata['properties']}
                    )
                    props_response.raise_for_status()
                
                return result.get('id')
                
        except Exception as e:
            logger.error(f"Error al guardar documento: {str(e)}")
            raise PermissionError(f"Error al guardar documento: {str(e)}")
    
    def delete_document(self, document_id: str) -> bool:
        """Eliminar un documento."""
        if not self.is_connected():
            raise ConnectionError("No conectado a Alfresco")
        
        try:
            # Convertir ruta a nodeId si es necesario
            node_id = self._get_node_id_from_path(document_id)
            
            # Eliminar documento
            response = self.session.delete(
                f"{self.base_url}api/nodes/{node_id}",
                auth=self.auth
            )
            response.raise_for_status()
            
            return True
            
        except Exception as e:
            logger.error(f"Error al eliminar documento: {str(e)}")
            raise PermissionError(f"Error al eliminar documento: {str(e)}")
    
    def encrypt_document(self, document_id: str, key_id: str, algorithm: str, metadata: Dict[str, Any]) -> str:
        """Cifrar un documento."""
        if not self.is_connected():
            raise ConnectionError("No conectado a Alfresco")
        
        try:
            # Obtener documento
            content, doc_metadata = self.get_document(document_id)
            
            # Importar motor de cifrado
            from ...core.encryption import EncryptionEngine
            from ...core.key_management import KeyManager
            
            # Inicializar componentes
            key_manager = KeyManager()
            encryption_engine = EncryptionEngine()
            
            # Obtener la clave
            key = key_manager.get_key(key_id)
            if not key:
                raise ValueError(f"Clave no encontrada: {key_id}")
            
            # Cifrar el documento
            encryption_result = encryption_engine.encrypt(
                data=content,
                key=key,
                algorithm=algorithm
            )
            
            # Preparar contenido cifrado
            encrypted_content = {
                'algorithm': encryption_result['algorithm'],
                'ciphertext': base64.b64encode(encryption_result['ciphertext']).decode('ascii'),
                'nonce': base64.b64encode(encryption_result['nonce']).decode('ascii'),
                'tag': base64.b64encode(encryption_result['tag']).decode('ascii') if 'tag' in encryption_result else None,
                'key_id': key_id,
                'original_metadata': doc_metadata,
                'encryption_metadata': metadata
            }
            
            # Convertir a JSON
            encrypted_json = json.dumps(encrypted_content).encode('utf-8')
            
            # Guardar documento cifrado
            encrypted_doc_id = f"{document_id}.encrypted"
            return self.save_document(encrypted_doc_id, encrypted_json, metadata)
            
        except Exception as e:
            logger.error(f"Error al cifrar documento: {str(e)}")
            raise ValueError(f"Error al cifrar documento: {str(e)}")
    
    def decrypt_document(self, document_id: str, key_id: str) -> str:
        """Descifrar un documento."""
        if not self.is_connected():
            raise ConnectionError("No conectado a Alfresco")
        
        try:
            # Obtener documento cifrado
            content, _ = self.get_document(document_id)
            
            # Parsear contenido JSON
            try:
                encrypted_content = json.loads(content.decode('utf-8'))
            except json.JSONDecodeError:
                raise ValueError("Formato de documento cifrado inválido")
            
            # Extraer datos de cifrado
            algorithm = encrypted_content.get('algorithm')
            ciphertext_b64 = encrypted_content.get('ciphertext')
            nonce_b64 = encrypted_content.get('nonce')
            tag_b64 = encrypted_content.get('tag')
            stored_key_id = encrypted_content.get('key_id')
            original_metadata = encrypted_content.get('original_metadata', {})
            
            # Validar datos
            if not algorithm or not ciphertext_b64 or not nonce_b64:
                raise ValueError("Documento cifrado inválido: faltan campos requeridos")
            
            # Usar ID de clave almacenada si no se proporciona
            if not key_id and stored_key_id:
                key_id = stored_key_id
            
            # Importar componentes de descifrado
            from ...core.encryption import EncryptionEngine
            from ...core.key_management import KeyManager
            
            # Inicializar componentes
            key_manager = KeyManager()
            encryption_engine = EncryptionEngine()
            
            # Obtener la clave
            key = key_manager.get_key(key_id)
            if not key:
                raise ValueError(f"Clave no encontrada: {key_id}")
            
            # Decodificar datos base64
            ciphertext = base64.b64decode(ciphertext_b64)
            nonce = base64.b64decode(nonce_b64)
            tag = base64.b64decode(tag_b64) if tag_b64 else None
            
            # Preparar resultado de cifrado para descifrado
            encryption_result = {
                'algorithm': algorithm,
                'ciphertext': ciphertext,
                'nonce': nonce
            }
            
            if tag:
                encryption_result['tag'] = tag
            
            # Descifrar los datos
            plaintext = encryption_engine.decrypt(
                encryption_result=encryption_result,
                key=key
            )
            
            # Guardar documento descifrado
            if document_id.endswith('.encrypted'):
                decrypted_doc_id = document_id[:-10]  # Eliminar sufijo .encrypted
            else:
                decrypted_doc_id = f"{document_id}.decrypted"
            
            return self.save_document(decrypted_doc_id, plaintext, original_metadata)
            
        except Exception as e:
            logger.error(f"Error al descifrar documento: {str(e)}")
            raise ValueError(f"Error al descifrar documento: {str(e)}")
    
    def sign_document(self, document_id: str, key_id: str, algorithm: str, metadata: Dict[str, Any]) -> str:
        """Firmar un documento."""
        if not self.is_connected():
            raise ConnectionError("No conectado a Alfresco")
        
        try:
            # Obtener documento
            content, doc_metadata = self.get_document(document_id)
            
            # Importar componentes de firma
            from ...core.signatures import SignatureEngine
            from ...core.key_management import KeyManager
            import datetime
            
            # Inicializar componentes
            key_manager = KeyManager()
            signature_engine = SignatureEngine()
            
            # Obtener la clave
            key = key_manager.get_key(key_id)
            if not key:
                raise ValueError(f"Clave no encontrada: {key_id}")
            
            # Firmar el documento
            signature = signature_engine.sign(
                data=content,
                key=key,
                algorithm=algorithm
            )
            
            # Preparar contenido de firma
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
            
            # Convertir a JSON
            signature_json = json.dumps(signature_content).encode('utf-8')
            
            # Guardar archivo de firma
            signature_doc_id = f"{document_id}.sig"
            return self.save_document(signature_doc_id, signature_json, metadata)
            
        except Exception as e:
            logger.error(f"Error al firmar documento: {str(e)}")
            raise ValueError(f"Error al firmar documento: {str(e)}")
    
    def verify_document(self, document_id: str, signature_id: str, key_id: str) -> bool:
        """Verificar la firma de un documento."""
        if not self.is_connected():
            raise ConnectionError("No conectado a Alfresco")
        
        try:
            # Obtener documento
            content, _ = self.get_document(document_id)
            
            # Obtener archivo de firma
            signature_content, _ = self.get_document(signature_id)
            
            # Parsear contenido JSON
            try:
                signature_data = json.loads(signature_content.decode('utf-8'))
            except json.JSONDecodeError:
                raise ValueError("Formato de firma inválido")
            
            # Extraer datos de firma
            algorithm = signature_data.get('algorithm')
            signature_b64 = signature_data.get('signature')
            stored_key_id = signature_data.get('key_id')
            
            # Validar datos
            if not algorithm or not signature_b64:
                raise ValueError("Firma inválida: faltan campos requeridos")
            
            # Usar ID de clave almacenada si no se proporciona
            if not key_id and stored_key_id:
                key_id = stored_key_id
            
            # Importar componentes de firma
            from ...core.signatures import SignatureEngine
            from ...core.key_management import KeyManager
            
            # Inicializar componentes
            key_manager = KeyManager()
            signature_engine = SignatureEngine()
            
            # Obtener la clave
            key = key_manager.get_key(key_id)
            if not key:
                raise ValueError(f"Clave no encontrada: {key_id}")
            
            # Decodificar firma base64
            signature = base64.b64decode(signature_b64)
            
            # Verificar la firma
            return signature_engine.verify(
                data=content,
                signature=signature,
                key=key,
                algorithm=algorithm
            )
            
        except Exception as e:
            logger.error(f"Error al verificar documento: {str(e)}")
            raise ValueError(f"Error al verificar documento: {str(e)}")
    
    def _get_node_id_from_path(self, path: str) -> str:
        """Convertir una ruta a un ID de nodo de Alfresco."""
        if path.startswith('/'):
            path = path[1:]
        
        # Si ya es un ID de nodo, devolverlo
        if not '/' in path and len(path) > 8:
            return path
        
        # Manejar rutas especiales
        if path == '' or path == '/':
            return '-root-'
        
        # Dividir la ruta en componentes
        components = path.split('/')
        current_id = '-root-'
        
        # Recorrer la ruta componente por componente
        for component in components:
            if not component:
                continue
                
            # Buscar el componente en los hijos del nodo actual
            response = self.session.get(
                f"{self.base_url}api/nodes/{current_id}/children",
                auth=self.auth,
                params={'where': f"(name='{component}')"}
            )
            response.raise_for_status()
            data = response.json()
            
            entries = data.get('list', {}).get('entries', [])
            if not entries:
                raise FileNotFoundError(f"No se encontró el componente '{component}' en la ruta")
            
            current_id = entries[0].get('entry', {}).get('id')
        
        return current_id
