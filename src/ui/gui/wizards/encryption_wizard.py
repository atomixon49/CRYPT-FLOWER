"""
Encryption wizard for guided encryption operations.

This module provides a wizard for guiding users through the encryption process.
"""

import os
from PyQt6.QtWidgets import (
    QWizardPage, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QFileDialog, QComboBox, QCheckBox, QGroupBox,
    QRadioButton, QListWidget, QListWidgetItem, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal

from .base_wizard import BaseWizard, BaseWizardPage
from ....core.encryption import EncryptionEngine
from ....core.key_management import KeyManager
from ....core.multi_recipient_encryption import MultiRecipientEncryption

class FileSelectionPage(BaseWizardPage):
    """Page for selecting the file to encrypt."""
    
    def __init__(self, parent=None):
        """Initialize the page."""
        super().__init__(
            "Select File",
            "Select the file you want to encrypt.",
            parent
        )
        
        # Register fields
        self.registerField("file_path*", self.file_path_edit)
        self.registerField("output_path*", self.output_path_edit)
    
    def setup_ui(self):
        """Set up the user interface."""
        # File selection
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()
        
        # Input file
        input_layout = QHBoxLayout()
        input_label = QLabel("File to encrypt:")
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_file)
        
        input_layout.addWidget(input_label)
        input_layout.addWidget(self.file_path_edit)
        input_layout.addWidget(browse_button)
        
        # Output file
        output_layout = QHBoxLayout()
        output_label = QLabel("Output file:")
        self.output_path_edit = QLineEdit()
        self.output_path_edit.setReadOnly(True)
        output_browse_button = QPushButton("Browse...")
        output_browse_button.clicked.connect(self.browse_output)
        
        output_layout.addWidget(output_label)
        output_layout.addWidget(self.output_path_edit)
        output_layout.addWidget(output_browse_button)
        
        # Add to group layout
        file_layout.addLayout(input_layout)
        file_layout.addLayout(output_layout)
        file_group.setLayout(file_layout)
        
        # Add to page layout
        self.layout.addWidget(file_group)
        self.layout.addStretch()
    
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

class EncryptionMethodPage(BaseWizardPage):
    """Page for selecting the encryption method."""
    
    def __init__(self, parent=None):
        """Initialize the page."""
        super().__init__(
            "Select Encryption Method",
            "Choose how you want to encrypt the file.",
            parent
        )
        
        # Register fields
        self.registerField("use_key", self.key_radio)
        self.registerField("use_password", self.password_radio)
        self.registerField("use_multi_recipient", self.multi_recipient_radio)
        self.registerField("password", self.password_edit)
        self.registerField("confirm_password", self.confirm_password_edit)
    
    def setup_ui(self):
        """Set up the user interface."""
        # Method selection
        method_group = QGroupBox("Encryption Method")
        method_layout = QVBoxLayout()
        
        # Radio buttons for method selection
        self.key_radio = QRadioButton("Use a key")
        self.password_radio = QRadioButton("Use a password")
        self.multi_recipient_radio = QRadioButton("Multiple recipients (encrypt for multiple people)")
        
        self.key_radio.setChecked(True)
        
        method_layout.addWidget(self.key_radio)
        method_layout.addWidget(self.password_radio)
        method_layout.addWidget(self.multi_recipient_radio)
        
        # Connect signals
        self.key_radio.toggled.connect(self.update_page)
        self.password_radio.toggled.connect(self.update_page)
        self.multi_recipient_radio.toggled.connect(self.update_page)
        
        method_group.setLayout(method_layout)
        
        # Password input
        password_group = QGroupBox("Password")
        password_layout = QVBoxLayout()
        
        password_label = QLabel("Enter password:")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        
        confirm_label = QLabel("Confirm password:")
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_edit)
        password_layout.addWidget(confirm_label)
        password_layout.addWidget(self.confirm_password_edit)
        
        password_group.setLayout(password_layout)
        password_group.setVisible(False)
        self.password_group = password_group
        
        # Add to page layout
        self.layout.addWidget(method_group)
        self.layout.addWidget(password_group)
        self.layout.addStretch()
    
    def update_page(self):
        """Update the page based on the selected method."""
        self.password_group.setVisible(self.password_radio.isChecked())
    
    def validatePage(self):
        """Validate the page before proceeding."""
        if self.password_radio.isChecked():
            password = self.password_edit.text()
            confirm_password = self.confirm_password_edit.text()
            
            if not password:
                QMessageBox.warning(self, "Warning", "Please enter a password.")
                return False
            
            if password != confirm_password:
                QMessageBox.warning(self, "Warning", "Passwords do not match.")
                return False
        
        return True

class KeySelectionPage(BaseWizardPage):
    """Page for selecting the encryption key."""
    
    def __init__(self, key_manager, parent=None):
        """Initialize the page."""
        self.key_manager = key_manager
        super().__init__(
            "Select Encryption Key",
            "Choose the key you want to use for encryption.",
            parent
        )
        
        # Register fields
        self.registerField("key_id", self.key_combo, "currentText")
    
    def setup_ui(self):
        """Set up the user interface."""
        # Key selection
        key_group = QGroupBox("Encryption Key")
        key_layout = QVBoxLayout()
        
        key_label = QLabel("Select a key:")
        self.key_combo = QComboBox()
        
        refresh_button = QPushButton("Refresh Keys")
        refresh_button.clicked.connect(self.load_keys)
        
        key_layout.addWidget(key_label)
        key_layout.addWidget(self.key_combo)
        key_layout.addWidget(refresh_button)
        
        key_group.setLayout(key_layout)
        
        # Add to page layout
        self.layout.addWidget(key_group)
        self.layout.addStretch()
        
        # Load keys
        self.load_keys()
    
    def load_keys(self):
        """Load available keys from the key manager."""
        self.key_combo.clear()
        
        # Get all keys
        keys = self.key_manager.active_keys
        
        # Add symmetric keys to the combo box
        for key_id, key_data in keys.items():
            if key_data.get('key_type') == 'symmetric':
                self.key_combo.addItem(key_id)
    
    def initializePage(self):
        """Initialize the page when it is shown."""
        # Check if we should skip this page
        wizard = self.wizard()
        if wizard.field("use_password") or wizard.field("use_multi_recipient"):
            wizard.next()

class RecipientSelectionPage(BaseWizardPage):
    """Page for selecting recipients for multi-recipient encryption."""
    
    def __init__(self, key_manager, parent=None):
        """Initialize the page."""
        self.key_manager = key_manager
        super().__init__(
            "Select Recipients",
            "Choose the recipients who will be able to decrypt the file.",
            parent
        )
    
    def setup_ui(self):
        """Set up the user interface."""
        # Recipients selection
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
        
        # Add to page layout
        self.layout.addWidget(recipients_group)
        
        # Load keys
        self.load_keys()
    
    def load_keys(self):
        """Load available keys from the key manager."""
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
    
    def get_selected_recipients(self):
        """Get the list of selected recipients."""
        recipients = []
        for i in range(self.selected_recipients_list.count()):
            recipients.append(self.selected_recipients_list.item(i).text())
        return recipients
    
    def validatePage(self):
        """Validate the page before proceeding."""
        recipients = self.get_selected_recipients()
        
        if not recipients:
            QMessageBox.warning(self, "Warning", "Please select at least one recipient.")
            return False
        
        # Store the recipients in the wizard field
        self.wizard().result_data['recipients'] = recipients
        
        return True
    
    def initializePage(self):
        """Initialize the page when it is shown."""
        # Check if we should skip this page
        wizard = self.wizard()
        if not wizard.field("use_multi_recipient"):
            wizard.next()

class AlgorithmSelectionPage(BaseWizardPage):
    """Page for selecting the encryption algorithm."""
    
    def __init__(self, parent=None):
        """Initialize the page."""
        super().__init__(
            "Select Encryption Algorithm",
            "Choose the algorithm you want to use for encryption.",
            parent
        )
        
        # Register fields
        self.registerField("algorithm", self.algorithm_combo, "currentText")
    
    def setup_ui(self):
        """Set up the user interface."""
        # Algorithm selection
        algorithm_group = QGroupBox("Encryption Algorithm")
        algorithm_layout = QVBoxLayout()
        
        algorithm_label = QLabel("Select an algorithm:")
        self.algorithm_combo = QComboBox()
        
        # Add algorithms
        self.algorithm_combo.addItem("AES-GCM")
        self.algorithm_combo.addItem("ChaCha20-Poly1305")
        
        algorithm_layout.addWidget(algorithm_label)
        algorithm_layout.addWidget(self.algorithm_combo)
        
        algorithm_group.setLayout(algorithm_layout)
        
        # Advanced options
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QVBoxLayout()
        
        self.compress_check = QCheckBox("Compress data before encryption")
        self.compress_check.setChecked(True)
        
        self.metadata_check = QCheckBox("Include file metadata")
        self.metadata_check.setChecked(True)
        
        advanced_layout.addWidget(self.compress_check)
        advanced_layout.addWidget(self.metadata_check)
        
        advanced_group.setLayout(advanced_layout)
        
        # Add to page layout
        self.layout.addWidget(algorithm_group)
        self.layout.addWidget(advanced_group)
        self.layout.addStretch()
        
        # Register additional fields
        self.registerField("compress", self.compress_check)
        self.registerField("include_metadata", self.metadata_check)

class SummaryPage(BaseWizardPage):
    """Page for showing a summary of the encryption settings."""
    
    def __init__(self, parent=None):
        """Initialize the page."""
        super().__init__(
            "Summary",
            "Review your encryption settings before proceeding.",
            parent
        )
    
    def setup_ui(self):
        """Set up the user interface."""
        # Summary group
        summary_group = QGroupBox("Encryption Settings")
        summary_layout = QVBoxLayout()
        
        # File information
        file_label = QLabel("File:")
        self.file_value = QLabel()
        self.file_value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        
        output_label = QLabel("Output:")
        self.output_value = QLabel()
        self.output_value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        
        # Method information
        method_label = QLabel("Method:")
        self.method_value = QLabel()
        
        # Key information
        key_label = QLabel("Key:")
        self.key_value = QLabel()
        self.key_value.setVisible(False)
        
        # Recipients information
        recipients_label = QLabel("Recipients:")
        self.recipients_value = QLabel()
        self.recipients_value.setVisible(False)
        
        # Algorithm information
        algorithm_label = QLabel("Algorithm:")
        self.algorithm_value = QLabel()
        
        # Options information
        options_label = QLabel("Options:")
        self.options_value = QLabel()
        
        # Add to layout
        summary_layout.addWidget(file_label)
        summary_layout.addWidget(self.file_value)
        summary_layout.addWidget(output_label)
        summary_layout.addWidget(self.output_value)
        summary_layout.addWidget(method_label)
        summary_layout.addWidget(self.method_value)
        summary_layout.addWidget(key_label)
        summary_layout.addWidget(self.key_value)
        summary_layout.addWidget(recipients_label)
        summary_layout.addWidget(self.recipients_value)
        summary_layout.addWidget(algorithm_label)
        summary_layout.addWidget(self.algorithm_value)
        summary_layout.addWidget(options_label)
        summary_layout.addWidget(self.options_value)
        
        summary_group.setLayout(summary_layout)
        
        # Add to page layout
        self.layout.addWidget(summary_group)
        self.layout.addStretch()
    
    def initializePage(self):
        """Initialize the page when it is shown."""
        wizard = self.wizard()
        
        # Set file information
        self.file_value.setText(wizard.field("file_path"))
        self.output_value.setText(wizard.field("output_path"))
        
        # Set method information
        if wizard.field("use_key"):
            self.method_value.setText("Using a key")
            self.key_value.setText(wizard.field("key_id"))
            self.key_value.setVisible(True)
            self.recipients_value.setVisible(False)
        elif wizard.field("use_password"):
            self.method_value.setText("Using a password")
            self.key_value.setVisible(False)
            self.recipients_value.setVisible(False)
        elif wizard.field("use_multi_recipient"):
            self.method_value.setText("Multiple recipients")
            self.key_value.setVisible(False)
            
            # Set recipients information
            recipients = wizard.result_data.get('recipients', [])
            self.recipients_value.setText("\n".join(recipients))
            self.recipients_value.setVisible(True)
        
        # Set algorithm information
        self.algorithm_value.setText(wizard.field("algorithm"))
        
        # Set options information
        options = []
        if wizard.field("compress"):
            options.append("Compress data")
        if wizard.field("include_metadata"):
            options.append("Include file metadata")
        
        self.options_value.setText("\n".join(options) if options else "None")

class EncryptionWizard(BaseWizard):
    """Wizard for guiding users through the encryption process."""
    
    def __init__(self, key_manager, encryption_engine, multi_encryption=None, parent=None):
        """Initialize the wizard."""
        self.key_manager = key_manager
        self.encryption_engine = encryption_engine
        self.multi_encryption = multi_encryption or MultiRecipientEncryption(key_manager)
        
        super().__init__(parent)
        
        self.setWindowTitle("Encryption Wizard")
    
    def add_pages(self):
        """Add pages to the wizard."""
        self.addPage(FileSelectionPage(self))
        self.addPage(EncryptionMethodPage(self))
        self.addPage(KeySelectionPage(self.key_manager, self))
        self.addPage(RecipientSelectionPage(self.key_manager, self))
        self.addPage(AlgorithmSelectionPage(self))
        self.addPage(SummaryPage(self))
    
    def collect_data(self):
        """Collect data from all fields."""
        # File information
        self.result_data['file_path'] = self.field("file_path")
        self.result_data['output_path'] = self.field("output_path")
        
        # Method information
        self.result_data['use_key'] = self.field("use_key")
        self.result_data['use_password'] = self.field("use_password")
        self.result_data['use_multi_recipient'] = self.field("use_multi_recipient")
        
        if self.field("use_key"):
            self.result_data['key_id'] = self.field("key_id")
        elif self.field("use_password"):
            self.result_data['password'] = self.field("password")
        # Recipients are already collected in the RecipientSelectionPage
        
        # Algorithm information
        self.result_data['algorithm'] = self.field("algorithm")
        
        # Options information
        self.result_data['compress'] = self.field("compress")
        self.result_data['include_metadata'] = self.field("include_metadata")
    
    def perform_encryption(self):
        """Perform the encryption operation."""
        try:
            # Get file data
            with open(self.result_data['file_path'], 'rb') as f:
                file_data = f.read()
            
            # Prepare metadata
            metadata = None
            if self.result_data['include_metadata']:
                metadata = {
                    'filename': os.path.basename(self.result_data['file_path']),
                    'original_size': len(file_data),
                    'compressed': self.result_data['compress']
                }
            
            # Compress data if requested
            if self.result_data['compress']:
                import zlib
                file_data = zlib.compress(file_data)
            
            # Encrypt the data
            if self.result_data['use_key']:
                # Get the key
                key = self.key_manager.get_key(self.result_data['key_id'])
                
                # Encrypt with key
                encryption_result = self.encryption_engine.encrypt(
                    data=file_data,
                    key=key,
                    algorithm=self.result_data['algorithm'],
                    metadata=metadata
                )
                
                # Save the encrypted data
                with open(self.result_data['output_path'], 'wb') as f:
                    f.write(encryption_result['data'])
                
            elif self.result_data['use_password']:
                # Encrypt with password
                encryption_result = self.encryption_engine.encrypt_with_password(
                    data=file_data,
                    password=self.result_data['password'],
                    algorithm=self.result_data['algorithm'],
                    metadata=metadata
                )
                
                # Save the encrypted data
                with open(self.result_data['output_path'], 'wb') as f:
                    f.write(encryption_result['data'])
                
            elif self.result_data['use_multi_recipient']:
                # Encrypt for multiple recipients
                encrypted_data = self.multi_encryption.encrypt(
                    data=file_data,
                    recipient_key_ids=self.result_data['recipients'],
                    symmetric_algorithm=self.result_data['algorithm'],
                    metadata=metadata
                )
                
                # Save the encrypted data
                import json
                with open(self.result_data['output_path'], 'w') as f:
                    json.dump(encrypted_data, f, indent=2)
            
            return True, "Encryption completed successfully."
            
        except Exception as e:
            return False, f"Error during encryption: {str(e)}"
