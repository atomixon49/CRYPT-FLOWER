"""
Swagger configuration for the REST API.

This module provides OpenAPI 3.0 documentation for the REST API.
"""

from flask import Flask
from flasgger import Swagger
from flasgger.utils import swag_from

def configure_swagger(app: Flask):
    """
    Configure Swagger/OpenAPI for the Flask app.

    Args:
        app: Flask application
    """
    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": "apispec",
                "route": "/apispec.json",
                "rule_filter": lambda rule: True,  # all in
                "model_filter": lambda tag: True,  # all in
                "openapi": "3.0.2",  # Use OpenAPI 3.0
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/api/docs/"
    }

    swagger_template = {
        "openapi": "3.0.2",  # OpenAPI version
        "info": {
            "title": "Cryptographic System API",
            "description": "API for cryptographic operations including encryption, decryption, signing, verification, and key management.",
            "version": "1.0.0",
            "contact": {
                "name": "API Support",
                "email": "support@example.com",
                "url": "https://example.com/support"
            },
            "license": {
                "name": "MIT License",
                "url": "https://opensource.org/licenses/MIT"
            }
        },
        "servers": [
            {
                "url": "/",
                "description": "Current server"
            }
        ],
        "components": {
            "securitySchemes": {
                "Bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\""
                }
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "string",
                            "description": "Error message"
                        }
                    }
                },
                "Key": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Key ID"
                        },
                        "algorithm": {
                            "type": "string",
                            "description": "Key algorithm"
                        },
                        "type": {
                            "type": "string",
                            "description": "Key type (symmetric, public, private)"
                        },
                        "created_at": {
                            "type": "string",
                            "format": "date-time",
                            "description": "Creation timestamp"
                        }
                    }
                },
                "EncryptionResult": {
                    "type": "object",
                    "properties": {
                        "algorithm": {
                            "type": "string",
                            "description": "Encryption algorithm used"
                        },
                        "ciphertext": {
                            "type": "string",
                            "format": "byte",
                            "description": "Base64-encoded encrypted data"
                        },
                        "nonce": {
                            "type": "string",
                            "format": "byte",
                            "description": "Base64-encoded nonce or initialization vector"
                        },
                        "tag": {
                            "type": "string",
                            "format": "byte",
                            "description": "Base64-encoded authentication tag (for AEAD algorithms)"
                        }
                    },
                    "required": ["algorithm", "ciphertext"]
                },
                "SignatureResult": {
                    "type": "object",
                    "properties": {
                        "algorithm": {
                            "type": "string",
                            "description": "Signature algorithm used"
                        },
                        "signature": {
                            "type": "string",
                            "format": "byte",
                            "description": "Base64-encoded signature"
                        }
                    },
                    "required": ["algorithm", "signature"]
                },
                "HSMSlot": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "integer",
                            "description": "Slot ID"
                        },
                        "description": {
                            "type": "string",
                            "description": "Slot description"
                        },
                        "manufacturer": {
                            "type": "string",
                            "description": "Slot manufacturer"
                        },
                        "has_token": {
                            "type": "boolean",
                            "description": "Whether the slot has a token"
                        },
                        "token_label": {
                            "type": "string",
                            "description": "Token label (if present)"
                        },
                        "token_model": {
                            "type": "string",
                            "description": "Token model (if present)"
                        }
                    },
                    "required": ["id", "has_token"]
                },
                "Plugin": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Plugin ID"
                        },
                        "name": {
                            "type": "string",
                            "description": "Plugin name"
                        },
                        "description": {
                            "type": "string",
                            "description": "Plugin description"
                        },
                        "version": {
                            "type": "string",
                            "description": "Plugin version"
                        },
                        "system_type": {
                            "type": "string",
                            "description": "Type of document management system"
                        },
                        "capabilities": {
                            "type": "array",
                            "description": "Plugin capabilities",
                            "items": {
                                "type": "string",
                                "enum": ["read", "write", "encrypt", "decrypt", "sign", "verify"]
                            }
                        },
                        "configured": {
                            "type": "boolean",
                            "description": "Whether the plugin is configured"
                        }
                    },
                    "required": ["id", "name", "system_type", "capabilities"]
                },
                "Document": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Document ID or path"
                        },
                        "name": {
                            "type": "string",
                            "description": "Document name"
                        },
                        "type": {
                            "type": "string",
                            "description": "Document type (file or folder)",
                            "enum": ["file", "folder"]
                        },
                        "size": {
                            "type": "integer",
                            "description": "Document size in bytes (for files)"
                        },
                        "modified": {
                            "type": "string",
                            "description": "Last modified timestamp"
                        },
                        "url": {
                            "type": "string",
                            "description": "URL to access the document (if available)"
                        }
                    },
                    "required": ["id", "name", "type"]
                }
            },
            "parameters": {
                "KeyId": {
                    "name": "key_id",
                    "in": "path",
                    "description": "ID of the key",
                    "required": true,
                    "schema": {
                        "type": "string"
                    }
                },
                "PluginId": {
                    "name": "plugin_id",
                    "in": "path",
                    "description": "ID of the plugin",
                    "required": true,
                    "schema": {
                        "type": "string"
                    }
                },
                "DocumentId": {
                    "name": "document_id",
                    "in": "path",
                    "description": "ID or path of the document",
                    "required": true,
                    "schema": {
                        "type": "string"
                    }
                }
            },
            "examples": {
                "EncryptionRequest": {
                    "value": {
                        "data": "SGVsbG8gV29ybGQh",
                        "key_id": "my_key",
                        "algorithm": "AES-GCM"
                    }
                },
                "SignatureRequest": {
                    "value": {
                        "data": "SGVsbG8gV29ybGQh",
                        "key_id": "my_key.private",
                        "algorithm": "RSA-SHA256"
                    }
                },
                "HSMKeyGeneration": {
                    "value": {
                        "key_type": "RSA",
                        "key_size": 2048,
                        "key_label": "my_hsm_key",
                        "extractable": false
                    }
                },
                "PluginConfiguration": {
                    "value": {
                        "site_url": "https://example.sharepoint.com/sites/mysite",
                        "auth_type": "username_password",
                        "username": "user@example.com",
                        "password": "password"
                    }
                }
            }
        },
        "security": [
            {
                "Bearer": []
            }
        ],
        "tags": [
            {
                "name": "Authentication",
                "description": "Authentication operations"
            },
            {
                "name": "Encryption",
                "description": "Encryption and decryption operations"
            },
            {
                "name": "Signatures",
                "description": "Digital signature operations"
            },
            {
                "name": "Keys",
                "description": "Key management operations"
            },
            {
                "name": "JWT",
                "description": "JWT, JWS, and JWE operations"
            },
            {
                "name": "HSM",
                "description": "Hardware Security Module operations"
            },
            {
                "name": "Plugins",
                "description": "Document management system plugins"
            }
        ]
    }

    Swagger(app, config=swagger_config, template=swagger_template)
