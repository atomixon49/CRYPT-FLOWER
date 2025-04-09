"""
Multi-Recipient Encryption Tab

This module provides a GUI tab for encrypting files for multiple recipients.
"""

import os
import json
import base64
from typing import List, Dict, Any, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFileDialog, QMessageBox, QListWidget, QListWidgetItem, QCheckBox,
    QComboBox, QGroupBox, QFormLayout, QSplitter, QTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal

from ....core.multi_recipient_encryption import MultiRecipientEncryption
from ....core.key_management import KeyManager

class MultiRecipientTab(QWidget):
    """Tab for multi-recipient encryption operations."""
    
    def __init__(self, parent=None):
        """Initialize the multi-recipient tab."""
        super().__init__(parent)
        
        # Initialize components
        self.key_manager = KeyManager()
        self.multi_encryption = MultiRecipientEncryption(self.key_manager)
        
        # Set up the UI
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        # Main layout
        main_layout = QVBoxLayout()
        
        # File selection section
        file_group = QGroupBox("File Selection")
        file_layout = QFormLayout()
        
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_file)
        
        file_path_layout = QHBoxLayout()
        file_path_layout.addWidget(self.file_path_edit)
        file_path_layout.addWidget(browse_button)
        
        file_layout.addRow("File to encrypt:", file_path_layout)
        
        self.output_path_edit = QLineEdit()
        self.output_path_edit.setReadOnly(True)
        
        output_browse_button = QPushButton("Browse...")
        output_browse_button.clicked.connect(self.browse_output)
        
        output_path_layout = QHBoxLayout()
        output_path_layout.addWidget(self.output_path_edit)
        output_path_layout.addWidget(output_browse_button)
        
        file_layout.addRow("Output file:", output_path_layout)
        
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)
        
        # Recipients section
        recipients_group = QGroupBox("Recipients")
        recipients_layout = QVBoxLayout()
        
        # Available keys list
        keys_layout = QHBoxLayout()
        
        available_keys_layout = QVBoxLayout()
        available_keys_label = QLabel("Available Keys:")
        self.available_keys_list = QListWidget()
        self.available_keys_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        
        available_keys_layout.addWidget(available_keys_label)
        available_keys_layout.addWidget(self.available_keys_list)
        
        # Buttons for adding/removing recipients
        buttons_layout = QVBoxLayout()
        self.add_recipient_button = QPushButton("Add >")
        self.add_recipient_button.clicked.connect(self.add_recipient)
        
        self.remove_recipient_button = QPushButton("< Remove")
        self.remove_recipient_button.clicked.connect(self.remove_recipient)
        
        buttons_layout.addStretch()
        buttons_layout.addWidget(self.add_recipient_button)
        buttons_layout.addWidget(self.remove_recipient_button)
        buttons_layout.addStretch()
        
        # Selected recipients list
        selected_recipients_layout = QVBoxLayout()
        selected_recipients_label = QLabel("Selected Recipients:")
        self.selected_recipients_list = QListWidget()
        self.selected_recipients_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        
        selected_recipients_layout.addWidget(selected_recipients_label)
        selected_recipients_layout.addWidget(self.selected_recipients_list)
        
        keys_layout.addLayout(available_keys_layout)
        keys_layout.addLayout(buttons_layout)
        keys_layout.addLayout(selected_recipients_layout)
        
        recipients_layout.addLayout(keys_layout)
        
        # Refresh keys button
        refresh_keys_button = QPushButton("Refresh Keys")
        refresh_keys_button.clicked.connect(self.load_keys)
        recipients_layout.addWidget(refresh_keys_button)
        
        recipients_group.setLayout(recipients_layout)
        main_layout.addWidget(recipients_group)
        
        # Encryption options
        options_group = QGroupBox("Encryption Options")
        options_layout = QFormLayout()
        
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(["AES-GCM", "ChaCha20-Poly1305"])
        
        options_layout.addRow("Algorithm:", self.algorithm_combo)
        
        options_group.setLayout(options_layout)
        main_layout.addWidget(options_group)
        
        # Action buttons
        actions_layout = QHBoxLayout()
        
        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        
        self.decrypt_button = QPushButton("Decrypt")
        self.decrypt_button.clicked.connect(self.decrypt_file)
        
        actions_layout.addWidget(self.encrypt_button)
        actions_layout.addWidget(self.decrypt_button)
        
        main_layout.addLayout(actions_layout)
        
        # Set the main layout
        self.setLayout(main_layout)
        
        # Load keys
        self.load_keys()
    
    def load_keys(self):
        """Load available keys from the key manager."""
        try:
            # Clear the lists
            self.available_keys_list.clear()
            
            # Get all keys
            keys = self.key_manager.active_keys
            
            # Add public keys to the available keys list
            for key_id, key_data in keys.items():
                # Only show public keys
                if key_id.endswith('.public') or key_data.get('key_type') == 'public':
                    # Create a list item with the key ID
                    item = QListWidgetItem(key_id)
                    
                    # Add key info as tooltip
                    key_info = self.key_manager.get_key_info(key_id)
                    tooltip = f"ID: {key_id}\n"
                    tooltip += f"Algorithm: {key_info.get('algorithm', 'Unknown')}\n"
                    tooltip += f"Created: {key_info.get('created_str', 'Unknown')}"
                    
                    item.setToolTip(tooltip)
                    
                    # Add to the list
                    self.available_keys_list.addItem(item)
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load keys: {str(e)}")
    
    def browse_file(self):
        """Browse for a file to encrypt."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Encrypt", "", "All Files (*)"
        )
        
        if file_path:
            self.file_path_edit.setText(file_path)
            
            # Set default output path
            output_path = file_path + ".encrypted"
            self.output_path_edit.setText(output_path)
    
    def browse_output(self):
        """Browse for an output file location."""
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Select Output File", "", "Encrypted Files (*.encrypted);;All Files (*)"
        )
        
        if output_path:
            self.output_path_edit.setText(output_path)
    
    def add_recipient(self):
        """Add selected keys to the recipients list."""
        # Get selected items
        selected_items = self.available_keys_list.selectedItems()
        
        for item in selected_items:
            # Check if the key is already in the recipients list
            existing_items = self.selected_recipients_list.findItems(
                item.text(), Qt.MatchFlag.MatchExactly
            )
            
            if not existing_items:
                # Add to recipients list
                self.selected_recipients_list.addItem(item.text())
    
    def remove_recipient(self):
        """Remove selected keys from the recipients list."""
        # Get selected items
        selected_items = self.selected_recipients_list.selectedItems()
        
        for item in selected_items:
            # Remove from the list
            row = self.selected_recipients_list.row(item)
            self.selected_recipients_list.takeItem(row)
    
    def encrypt_file(self):
        """Encrypt a file for multiple recipients."""
        try:
            # Get the file path
            file_path = self.file_path_edit.text()
            if not file_path:
                QMessageBox.warning(self, "Warning", "Please select a file to encrypt.")
                return
            
            # Get the output path
            output_path = self.output_path_edit.text()
            if not output_path:
                QMessageBox.warning(self, "Warning", "Please select an output file.")
                return
            
            # Get the recipients
            recipient_key_ids = []
            for i in range(self.selected_recipients_list.count()):
                recipient_key_ids.append(self.selected_recipients_list.item(i).text())
            
            if not recipient_key_ids:
                QMessageBox.warning(self, "Warning", "Please select at least one recipient.")
                return
            
            # Get the algorithm
            algorithm = self.algorithm_combo.currentText()
            
            # Read the file
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            # Prepare metadata
            metadata = {
                "filename": os.path.basename(file_path),
                "original_size": len(file_data)
            }
            
            # Encrypt the file
            encrypted_data = self.multi_encryption.encrypt(
                data=file_data,
                recipient_key_ids=recipient_key_ids,
                symmetric_algorithm=algorithm,
                metadata=metadata
            )
            
            # Write the encrypted data to the output file
            with open(output_path, "w") as f:
                json.dump(encrypted_data, f, indent=2)
            
            QMessageBox.information(
                self,
                "Success",
                f"File encrypted successfully for {len(recipient_key_ids)} recipients.\n\n"
                f"Output saved to: {output_path}"
            )
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to encrypt file: {str(e)}")
    
    def decrypt_file(self):
        """Decrypt a file as one of the recipients."""
        try:
            # Get the file path
            file_path = self.file_path_edit.text()
            if not file_path:
                QMessageBox.warning(self, "Warning", "Please select a file to decrypt.")
                return
            
            # Get the output path
            output_path = self.output_path_edit.text()
            if not output_path:
                QMessageBox.warning(self, "Warning", "Please select an output file.")
                return
            
            # Read the encrypted file
            with open(file_path, "r") as f:
                encrypted_data = json.load(f)
            
            # Check if it's a multi-recipient encrypted file
            if encrypted_data.get("type") != "multi_recipient_encrypted":
                QMessageBox.warning(
                    self,
                    "Warning",
                    "The selected file is not a multi-recipient encrypted file."
                )
                return
            
            # Get the list of recipients
            recipients = encrypted_data.get("recipients", {})
            
            # Create a dialog to select the recipient key
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QComboBox, QDialogButtonBox
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Select Recipient Key")
            
            dialog_layout = QVBoxLayout()
            
            dialog_layout.addWidget(QLabel("Select your key to decrypt the file:"))
            
            key_combo = QComboBox()
            for key_id in recipients.keys():
                key_combo.addItem(key_id)
            
            dialog_layout.addWidget(key_combo)
            
            button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            button_box.accepted.connect(dialog.accept)
            button_box.rejected.connect(dialog.reject)
            
            dialog_layout.addWidget(button_box)
            
            dialog.setLayout(dialog_layout)
            
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            
            # Get the selected key
            recipient_key_id = key_combo.currentText()
            
            # Decrypt the file
            decrypted_data = self.multi_encryption.decrypt(
                encrypted_data=encrypted_data,
                recipient_key_id=recipient_key_id
            )
            
            # Write the decrypted data to the output file
            with open(output_path, "wb") as f:
                f.write(decrypted_data)
            
            # Get original filename from metadata if available
            original_filename = encrypted_data.get("metadata", {}).get("filename", "unknown")
            
            QMessageBox.information(
                self,
                "Success",
                f"File decrypted successfully.\n\n"
                f"Original filename: {original_filename}\n"
                f"Output saved to: {output_path}"
            )
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to decrypt file: {str(e)}")
