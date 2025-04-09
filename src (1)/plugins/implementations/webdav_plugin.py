"""
WebDAV Plugin

Plugin para integración con sistemas de gestión documental que soportan WebDAV.
"""

import os
import io
import json
import base64
import logging
import datetime
from typing import Dict, Any, Optional, List, Tuple

# Intentar importar la biblioteca webdav
try:
    import webdavclient3.client as wc
    WEBDAV_AVAILABLE = True
except ImportError:
    WEBDAV_AVAILABLE = False

from ..plugin_interface import DocumentManagementPlugin

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("webdav_plugin")

class WebDAVPlugin(DocumentManagementPlugin):
    """Plugin para sistemas que soportan WebDAV."""
    
    def __init__(self):
        """Inicializar el plugin WebDAV."""
        self.client = None
        self.base_url = None
        self.connected = False
        
        if not WEBDAV_AVAILABLE:
            logger.warning("Biblioteca WebDAV no disponible. Instalar con: pip install webdavclient3")
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """Obtener información del plugin."""
        return {
            'id': 'webdav',
            'name': 'WebDAV Plugin',
            'description': 'Plugin para sistemas que soportan WebDAV',
            'version': '1.0.0',
            'system_type': 'WebDAV',
            'capabilities': ['read', 'write', 'encrypt', 'decrypt', 'sign', 'verify'],
            'available': WEBDAV_AVAILABLE
        }
    
    def connect(self, connection_params: Dict[str, Any]) -> bool:
        """Conectar al servidor WebDAV."""
        if not WEBDAV_AVAILABLE:
            raise ImportError("Biblioteca WebDAV no disponible. Instalar con: pip install webdavclient3")
        
        try:
            self.base_url = connection_params.get('url')
            username = connection_params.get('username')
            password = connection_params.get('password')
            
            if not self.base_url:
                raise ValueError("Se requiere URL del servidor WebDAV")
            
            # Crear opciones para el cliente WebDAV
            options = {
                'webdav_hostname': self.base_url,
                'webdav_login': username,
                'webdav_password': password
            }
            
            # Crear cliente WebDAV
            self.client = wc.Client(options)
            
            # Verificar conexión
            self.client.check()
            
            self.connected = True
            logger.info(f"Conectado a WebDAV: {self.base_url}")
            return True
            
        except Exception as e:
            logger.error(f"Error al conectar a WebDAV: {str(e)}")
            self.client = None
            self.connected = False
            return False
    
    def disconnect(self) -> bool:
        """Desconectar del servidor WebDAV."""
        self.client = None
        self.connected = False
        return True
    
    def is_connected(self) -> bool:
        """Verificar si está conectado."""
        return self.connected and self.client is not None
    
    def list_documents(self, folder_path: str) -> List[Dict[str, Any]]:
        """Listar documentos en una carpeta."""
        if not self.is_connected():
            raise ConnectionError("No conectado a WebDAV")
        
        try:
            # Normalizar ruta
            folder_path = self._normalize_path(folder_path)
            
            # Listar contenido
            items = self.client.list(folder_path)
            
            result = []
            for item in items:
                # Ignorar el elemento actual y el padre
                if item in ['.', '..']:
                    continue
                
                item_path = os.path.join(folder_path, item)
                is_dir = self.client.is_dir(item_path)
                
                # Obtener información del elemento
                info = self.client.info(item_path)
                
                result.append({
                    'id': item_path,
                    'name': item,
                    'type': 'folder' if is_dir else 'file',
                    'size': info.get('size', 0) if not is_dir else None,
                    'modified': info.get('modified', None),
                    'url': f"{self.base_url}{item_path}"
                })
            
            return result
            
        except Exception as e:
            logger.error(f"Error al listar documentos: {str(e)}")
            raise ValueError(f"Error al listar documentos: {str(e)}")
    
    def get_document(self, document_id: str) -> Tuple[bytes, Dict[str, Any]]:
        """Obtener un documento."""
        if not self.is_connected():
            raise ConnectionError("No conectado a WebDAV")
        
        try:
            # Normalizar ruta
            document_id = self._normalize_path(document_id)
            
            # Verificar si existe
            if not self.client.check(document_id):
                raise FileNotFoundError(f"Documento no encontrado: {document_id}")
            
            # Obtener información del documento
            info = self.client.info(document_id)
            
            # Descargar contenido
            buffer = io.BytesIO()
            self.client.download_to(document_id, buffer)
            content = buffer.getvalue()
            
            # Preparar metadatos
            metadata = {
                'id': document_id,
                'name': os.path.basename(document_id),
                'size': info.get('size', len(content)),
                'modified': info.get('modified', None),
                'url': f"{self.base_url}{document_id}",
                'properties': info
            }
            
            return content, metadata
            
        except Exception as e:
            logger.error(f"Error al obtener documento: {str(e)}")
            raise FileNotFoundError(f"Error al obtener documento: {str(e)}")
    
    def save_document(self, document_id: str, content: bytes, metadata: Dict[str, Any]) -> str:
        """Guardar un documento."""
        if not self.is_connected():
            raise ConnectionError("No conectado a WebDAV")
        
        try:
            # Normalizar ruta
            document_id = self._normalize_path(document_id)
            
            # Crear directorio padre si no existe
            parent_dir = os.path.dirname(document_id)
            if parent_dir and not self.client.check(parent_dir):
                self.client.mkdir(parent_dir)
            
            # Guardar documento
            buffer = io.BytesIO(content)
            self.client.upload_to(document_id, buffer)
            
            # WebDAV no soporta metadatos directamente, pero podríamos
            # guardar un archivo de metadatos junto al documento
            if metadata:
                metadata_id = f"{document_id}.metadata"
                metadata_content = json.dumps(metadata).encode('utf-8')
                metadata_buffer = io.BytesIO(metadata_content)
                self.client.upload_to(metadata_id, metadata_buffer)
            
            return document_id
            
        except Exception as e:
            logger.error(f"Error al guardar documento: {str(e)}")
            raise PermissionError(f"Error al guardar documento: {str(e)}")
    
    def delete_document(self, document_id: str) -> bool:
        """Eliminar un documento."""
        if not self.is_connected():
            raise ConnectionError("No conectado a WebDAV")
        
        try:
            # Normalizar ruta
            document_id = self._normalize_path(document_id)
            
            # Verificar si existe
            if not self.client.check(document_id):
                raise FileNotFoundError(f"Documento no encontrado: {document_id}")
            
            # Eliminar documento
            self.client.clean(document_id)
            
            # Eliminar archivo de metadatos si existe
            metadata_id = f"{document_id}.metadata"
            if self.client.check(metadata_id):
                self.client.clean(metadata_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Error al eliminar documento: {str(e)}")
            raise PermissionError(f"Error al eliminar documento: {str(e)}")
    
    def encrypt_document(self, document_id: str, key_id: str, algorithm: str, metadata: Dict[str, Any]) -> str:
        """Cifrar un documento."""
        if not self.is_connected():
            raise ConnectionError("No conectado a WebDAV")
        
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
            raise ConnectionError("No conectado a WebDAV")
        
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
            raise ConnectionError("No conectado a WebDAV")
        
        try:
            # Obtener documento
            content, doc_metadata = self.get_document(document_id)
            
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
            raise ConnectionError("No conectado a WebDAV")
        
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
    
    def _normalize_path(self, path: str) -> str:
        """Normalizar una ruta para WebDAV."""
        # Asegurar que la ruta comienza con /
        if not path.startswith('/'):
            path = '/' + path
        
        # Eliminar dobles barras
        while '//' in path:
            path = path.replace('//', '/')
        
        return path
