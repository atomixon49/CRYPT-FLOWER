"""
JWT tab for the cryptographic system GUI.

This tab provides functionality for working with JSON Web Tokens (JWT),
including JSON Web Encryption (JWE) and JSON Web Signature (JWS).
"""

import os
import json
import base64
from typing import Optional, Dict, Any, List, Union

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QRadioButton, QButtonGroup, QFileDialog, QLineEdit, QProgressBar,
    QTextEdit, QGroupBox, QFormLayout, QCheckBox, QMessageBox,
    QSizePolicy, QFrame, QSpacerItem, QTabWidget
)
from PyQt6.QtCore import Qt, QMimeData, QUrl
from PyQt6.QtGui import QDragEnterEvent, QDropEvent

from ....core.key_management import KeyManager
from ....core.jwt_interface import JWTInterface, JWTError


class JWTTab(QWidget):
    """
    Tab for JWT operations.
    
    This tab provides a user interface for:
    - Creating JWS tokens
    - Verifying JWS tokens
    - Creating JWE tokens
    - Decrypting JWE tokens
    - Exporting keys as JWK
    """
    
    def __init__(self, key_manager: KeyManager, parent=None):
        """
        Initialize the JWT tab.
        
        Args:
            key_manager: Key manager to use for key operations
            parent: Parent widget
        """
        super().__init__(parent)
        self.key_manager = key_manager
        
        # Initialize JWT interface
        try:
            self.jwt_interface = JWTInterface(key_manager=self.key_manager)
            self.jwt_support = True
        except JWTError:
            self.jwt_support = False
        
        # Set up the UI
        self.setup_ui()
        
        # Connect signals and slots
        self.connect_signals()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Check if JWT support is available
        if not self.jwt_support:
            # Show error message
            error_label = QLabel("JWT support is not available. Please install pyjwt and jwcrypto.")
            error_label.setStyleSheet("color: red; font-weight: bold;")
            main_layout.addWidget(error_label)
            return
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.create_jws_tab()
        self.create_verify_jws_tab()
        self.create_jwe_tab()
        self.create_decrypt_jwe_tab()
        self.create_jwk_tab()
    
    def create_jws_tab(self):
        """Create the JWS creation tab."""
        # Create tab widget
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create form layout
        form_layout = QFormLayout()
        layout.addLayout(form_layout)
        
        # Key selection
        self.jws_key_combo = QComboBox()
        self.populate_private_keys(self.jws_key_combo)
        form_layout.addRow("Private Key:", self.jws_key_combo)
        
        # Algorithm selection
        self.jws_algorithm_combo = QComboBox()
        self.populate_signing_algorithms(self.jws_algorithm_combo)
        form_layout.addRow("Algorithm:", self.jws_algorithm_combo)
        
        # Payload input
        self.jws_payload_edit = QTextEdit()
        self.jws_payload_edit.setPlaceholderText("Enter payload (JSON or text)")
        form_layout.addRow("Payload:", self.jws_payload_edit)
        
        # Headers input
        self.jws_headers_edit = QTextEdit()
        self.jws_headers_edit.setPlaceholderText("Enter headers (JSON, optional)")
        form_layout.addRow("Headers:", self.jws_headers_edit)
        
        # Create button
        self.create_jws_button = QPushButton("Create JWS")
        layout.addWidget(self.create_jws_button)
        
        # Output
        self.jws_output_edit = QTextEdit()
        self.jws_output_edit.setReadOnly(True)
        self.jws_output_edit.setPlaceholderText("JWS token will appear here")
        layout.addWidget(QLabel("Output:"))
        layout.addWidget(self.jws_output_edit)
        
        # Add tab to tab widget
        self.tab_widget.addTab(tab, "Create JWS")
    
    def create_verify_jws_tab(self):
        """Create the JWS verification tab."""
        # Create tab widget
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create form layout
        form_layout = QFormLayout()
        layout.addLayout(form_layout)
        
        # Key selection
        self.verify_jws_key_combo = QComboBox()
        self.populate_public_keys(self.verify_jws_key_combo)
        form_layout.addRow("Public Key:", self.verify_jws_key_combo)
        
        # Token input
        self.verify_jws_token_edit = QTextEdit()
        self.verify_jws_token_edit.setPlaceholderText("Enter JWS token")
        form_layout.addRow("JWS Token:", self.verify_jws_token_edit)
        
        # Verify button
        self.verify_jws_button = QPushButton("Verify JWS")
        layout.addWidget(self.verify_jws_button)
        
        # Output
        self.verify_jws_output_edit = QTextEdit()
        self.verify_jws_output_edit.setReadOnly(True)
        self.verify_jws_output_edit.setPlaceholderText("Verification result will appear here")
        layout.addWidget(QLabel("Result:"))
        layout.addWidget(self.verify_jws_output_edit)
        
        # Add tab to tab widget
        self.tab_widget.addTab(tab, "Verify JWS")
    
    def create_jwe_tab(self):
        """Create the JWE creation tab."""
        # Create tab widget
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create form layout
        form_layout = QFormLayout()
        layout.addLayout(form_layout)
        
        # Key selection
        self.jwe_key_combo = QComboBox()
        self.populate_public_keys(self.jwe_key_combo)
        form_layout.addRow("Public Key:", self.jwe_key_combo)
        
        # Algorithm selection
        self.jwe_algorithm_combo = QComboBox()
        self.populate_key_encryption_algorithms(self.jwe_algorithm_combo)
        form_layout.addRow("Key Encryption:", self.jwe_algorithm_combo)
        
        # Encryption selection
        self.jwe_encryption_combo = QComboBox()
        self.populate_content_encryption_algorithms(self.jwe_encryption_combo)
        form_layout.addRow("Content Encryption:", self.jwe_encryption_combo)
        
        # Payload input
        self.jwe_payload_edit = QTextEdit()
        self.jwe_payload_edit.setPlaceholderText("Enter payload (JSON or text)")
        form_layout.addRow("Payload:", self.jwe_payload_edit)
        
        # Headers input
        self.jwe_headers_edit = QTextEdit()
        self.jwe_headers_edit.setPlaceholderText("Enter headers (JSON, optional)")
        form_layout.addRow("Headers:", self.jwe_headers_edit)
        
        # Create button
        self.create_jwe_button = QPushButton("Create JWE")
        layout.addWidget(self.create_jwe_button)
        
        # Output
        self.jwe_output_edit = QTextEdit()
        self.jwe_output_edit.setReadOnly(True)
        self.jwe_output_edit.setPlaceholderText("JWE token will appear here")
        layout.addWidget(QLabel("Output:"))
        layout.addWidget(self.jwe_output_edit)
        
        # Add tab to tab widget
        self.tab_widget.addTab(tab, "Create JWE")
    
    def create_decrypt_jwe_tab(self):
        """Create the JWE decryption tab."""
        # Create tab widget
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create form layout
        form_layout = QFormLayout()
        layout.addLayout(form_layout)
        
        # Key selection
        self.decrypt_jwe_key_combo = QComboBox()
        self.populate_private_keys(self.decrypt_jwe_key_combo)
        form_layout.addRow("Private Key:", self.decrypt_jwe_key_combo)
        
        # Token input
        self.decrypt_jwe_token_edit = QTextEdit()
        self.decrypt_jwe_token_edit.setPlaceholderText("Enter JWE token")
        form_layout.addRow("JWE Token:", self.decrypt_jwe_token_edit)
        
        # Decrypt button
        self.decrypt_jwe_button = QPushButton("Decrypt JWE")
        layout.addWidget(self.decrypt_jwe_button)
        
        # Output
        self.decrypt_jwe_output_edit = QTextEdit()
        self.decrypt_jwe_output_edit.setReadOnly(True)
        self.decrypt_jwe_output_edit.setPlaceholderText("Decryption result will appear here")
        layout.addWidget(QLabel("Result:"))
        layout.addWidget(self.decrypt_jwe_output_edit)
        
        # Add tab to tab widget
        self.tab_widget.addTab(tab, "Decrypt JWE")
    
    def create_jwk_tab(self):
        """Create the JWK export tab."""
        # Create tab widget
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create form layout
        form_layout = QFormLayout()
        layout.addLayout(form_layout)
        
        # Key selection
        self.jwk_key_combo = QComboBox()
        self.populate_all_keys(self.jwk_key_combo)
        form_layout.addRow("Key:", self.jwk_key_combo)
        
        # Export button
        self.export_jwk_button = QPushButton("Export JWK")
        layout.addWidget(self.export_jwk_button)
        
        # Output
        self.jwk_output_edit = QTextEdit()
        self.jwk_output_edit.setReadOnly(True)
        self.jwk_output_edit.setPlaceholderText("JWK will appear here")
        layout.addWidget(QLabel("JWK:"))
        layout.addWidget(self.jwk_output_edit)
        
        # Add tab to tab widget
        self.tab_widget.addTab(tab, "Export JWK")
    
    def connect_signals(self):
        """Connect signals and slots."""
        if not self.jwt_support:
            return
        
        # JWS creation
        self.create_jws_button.clicked.connect(self.on_create_jws)
        
        # JWS verification
        self.verify_jws_button.clicked.connect(self.on_verify_jws)
        
        # JWE creation
        self.create_jwe_button.clicked.connect(self.on_create_jwe)
        
        # JWE decryption
        self.decrypt_jwe_button.clicked.connect(self.on_decrypt_jwe)
        
        # JWK export
        self.export_jwk_button.clicked.connect(self.on_export_jwk)
    
    def populate_private_keys(self, combo_box: QComboBox):
        """
        Populate a combo box with private keys.
        
        Args:
            combo_box: Combo box to populate
        """
        combo_box.clear()
        
        # Add private keys
        for key_id, key_info in self.key_manager.active_keys.items():
            if key_id.endswith('.private'):
                combo_box.addItem(key_id)
    
    def populate_public_keys(self, combo_box: QComboBox):
        """
        Populate a combo box with public keys.
        
        Args:
            combo_box: Combo box to populate
        """
        combo_box.clear()
        
        # Add public keys
        for key_id, key_info in self.key_manager.active_keys.items():
            if key_id.endswith('.public'):
                combo_box.addItem(key_id)
    
    def populate_all_keys(self, combo_box: QComboBox):
        """
        Populate a combo box with all keys.
        
        Args:
            combo_box: Combo box to populate
        """
        combo_box.clear()
        
        # Add all keys
        for key_id in self.key_manager.active_keys.keys():
            combo_box.addItem(key_id)
    
    def populate_signing_algorithms(self, combo_box: QComboBox):
        """
        Populate a combo box with signing algorithms.
        
        Args:
            combo_box: Combo box to populate
        """
        combo_box.clear()
        
        # Add signing algorithms
        for algorithm in self.jwt_interface.SUPPORTED_SIGNING_ALGORITHMS:
            combo_box.addItem(algorithm)
    
    def populate_key_encryption_algorithms(self, combo_box: QComboBox):
        """
        Populate a combo box with key encryption algorithms.
        
        Args:
            combo_box: Combo box to populate
        """
        combo_box.clear()
        
        # Add key encryption algorithms
        for algorithm in self.jwt_interface.SUPPORTED_KEY_ENCRYPTION_ALGORITHMS:
            combo_box.addItem(algorithm)
    
    def populate_content_encryption_algorithms(self, combo_box: QComboBox):
        """
        Populate a combo box with content encryption algorithms.
        
        Args:
            combo_box: Combo box to populate
        """
        combo_box.clear()
        
        # Add content encryption algorithms
        for algorithm in self.jwt_interface.SUPPORTED_CONTENT_ENCRYPTION_ALGORITHMS:
            combo_box.addItem(algorithm)
    
    def on_create_jws(self):
        """Handle JWS creation button click."""
        try:
            # Get parameters
            key_id = self.jws_key_combo.currentText()
            algorithm = self.jws_algorithm_combo.currentText()
            payload_text = self.jws_payload_edit.toPlainText()
            headers_text = self.jws_headers_edit.toPlainText()
            
            # Parse payload
            try:
                payload = json.loads(payload_text)
            except json.JSONDecodeError:
                payload = payload_text
            
            # Parse headers
            headers = None
            if headers_text:
                try:
                    headers = json.loads(headers_text)
                except json.JSONDecodeError:
                    QMessageBox.warning(self, "Invalid Headers", "Headers must be valid JSON")
                    return
            
            # Create JWS
            jws_token = self.jwt_interface.create_jws_with_key_id(
                payload=payload,
                key_id=key_id,
                algorithm=algorithm,
                headers=headers
            )
            
            # Show result
            self.jws_output_edit.setText(jws_token)
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create JWS: {str(e)}")
    
    def on_verify_jws(self):
        """Handle JWS verification button click."""
        try:
            # Get parameters
            key_id = self.verify_jws_key_combo.currentText()
            token = self.verify_jws_token_edit.toPlainText()
            
            # Verify JWS
            result = self.jwt_interface.verify_jws_with_key_id(
                token=token,
                key_id=key_id
            )
            
            # Format result
            if result['valid']:
                # Convert payload to string if it's bytes
                payload = result['payload']
                if isinstance(payload, bytes):
                    try:
                        payload = json.loads(payload.decode('utf-8'))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        payload = base64.b64encode(payload).decode('utf-8')
                
                # Format output
                output = f"Verification: VALID\n\nHeaders:\n{json.dumps(result['headers'], indent=2)}\n\nPayload:\n"
                if isinstance(payload, dict):
                    output += json.dumps(payload, indent=2)
                else:
                    output += str(payload)
            else:
                output = "Verification: INVALID"
            
            # Show result
            self.verify_jws_output_edit.setText(output)
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to verify JWS: {str(e)}")
    
    def on_create_jwe(self):
        """Handle JWE creation button click."""
        try:
            # Get parameters
            key_id = self.jwe_key_combo.currentText()
            algorithm = self.jwe_algorithm_combo.currentText()
            encryption = self.jwe_encryption_combo.currentText()
            payload_text = self.jwe_payload_edit.toPlainText()
            headers_text = self.jwe_headers_edit.toPlainText()
            
            # Parse payload
            try:
                payload = json.loads(payload_text)
            except json.JSONDecodeError:
                payload = payload_text
            
            # Parse headers
            headers = None
            if headers_text:
                try:
                    headers = json.loads(headers_text)
                except json.JSONDecodeError:
                    QMessageBox.warning(self, "Invalid Headers", "Headers must be valid JSON")
                    return
            
            # Create JWE
            jwe_token = self.jwt_interface.create_jwe_with_key_id(
                payload=payload,
                key_id=key_id,
                algorithm=algorithm,
                encryption=encryption,
                headers=headers
            )
            
            # Show result
            self.jwe_output_edit.setText(jwe_token)
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create JWE: {str(e)}")
    
    def on_decrypt_jwe(self):
        """Handle JWE decryption button click."""
        try:
            # Get parameters
            key_id = self.decrypt_jwe_key_combo.currentText()
            token = self.decrypt_jwe_token_edit.toPlainText()
            
            # Decrypt JWE
            result = self.jwt_interface.decrypt_jwe_with_key_id(
                token=token,
                key_id=key_id
            )
            
            # Format result
            # Convert payload to string if it's bytes
            payload = result['payload']
            if isinstance(payload, bytes):
                try:
                    payload = json.loads(payload.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    payload = base64.b64encode(payload).decode('utf-8')
            
            # Format output
            output = f"Headers:\n{json.dumps(result['headers'], indent=2)}\n\nPayload:\n"
            if isinstance(payload, dict):
                output += json.dumps(payload, indent=2)
            else:
                output += str(payload)
            
            # Show result
            self.decrypt_jwe_output_edit.setText(output)
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to decrypt JWE: {str(e)}")
    
    def on_export_jwk(self):
        """Handle JWK export button click."""
        try:
            # Get parameters
            key_id = self.jwk_key_combo.currentText()
            
            # Get the key
            key = self.key_manager.get_key(key_id)
            
            # Create JWK
            jwk_data = self.jwt_interface.create_jwk(key, kid=key_id)
            
            # Show result
            self.jwk_output_edit.setText(json.dumps(jwk_data, indent=2))
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export JWK: {str(e)}")
