"""
Configuration for the RESTful API.
"""

import os
import secrets


class DefaultConfig:
    """Default configuration for the API."""

    # API settings
    DEBUG = False
    HOST = '0.0.0.0'
    PORT = 5000

    # Security settings
    JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRATION = 3600  # 1 hour

    # Admin credentials (for demo purposes only)
    # In production, use a proper user database
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'password')

    # File paths
    KEYS_FILE = os.environ.get('KEYS_FILE', 'keys.json')
    AUDIT_LOG_FILE = os.environ.get('AUDIT_LOG_FILE', 'audit.log')

    # HSM settings
    HSM_LIBRARY_PATH = os.environ.get('HSM_LIBRARY_PATH')
    HSM_TOKEN_LABEL = os.environ.get('HSM_TOKEN_LABEL')
    HSM_PIN = os.environ.get('HSM_PIN')


class DevelopmentConfig(DefaultConfig):
    """Development configuration."""

    DEBUG = True


class TestingConfig(DefaultConfig):
    """Testing configuration."""

    DEBUG = True
    TESTING = True

    # Use in-memory storage for testing
    KEYS_FILE = ':memory:'
    AUDIT_LOG_FILE = ':memory:'


class ProductionConfig(DefaultConfig):
    """Production configuration."""

    # In production, all sensitive values should come from environment variables
    JWT_SECRET = os.environ.get('JWT_SECRET')
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')

    # File paths should be absolute in production
    KEYS_FILE = os.environ.get('KEYS_FILE', '/var/lib/crypto/keys.json')
    AUDIT_LOG_FILE = os.environ.get('AUDIT_LOG_FILE', '/var/log/crypto/audit.log')

    # HSM settings must be provided in production
    HSM_LIBRARY_PATH = os.environ.get('HSM_LIBRARY_PATH')
    HSM_TOKEN_LABEL = os.environ.get('HSM_TOKEN_LABEL')
    HSM_PIN = os.environ.get('HSM_PIN')
