"""
Key management wizard for guided key operations.

This module provides a wizard for guiding users through key management operations.
"""

import os
from PyQt6.QtWidgets import (
    QWizardPage, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QFileDialog, QComboBox, QCheckBox, QGroupBox,
    QRadioButton, QSpinBox, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal

from .base_wizard import BaseWizard, BaseWizardPage
from ....core.key_management import KeyManager

class OperationSelectionPage(BaseWizardPage):
    """Page for selecting the key management operation."""
    
    def __init__(self, parent=None):
        """Initialize the page."""
        super().__init__(
            "Select Operation",
            "Choose the key management operation you want to perform.",
            parent
        )
        
        # Register fields
        self.registerField("generate_key", self.generate_radio)
        self.registerField("import_key", self.import_radio)
        self.registerField("export_key", self.export_radio)
    
    def setup_ui(self):
        """Set up the user interface."""
        # Operation selection
        operation_group = QGroupBox("Key Operation")
        operation_layout = QVBoxLayout()
        
        # Radio buttons for operation selection
        self.generate_radio = QRadioButton("Generate a new key")
        self.import_radio = QRadioButton("Import an existing key")
        self.export_radio = QRadioButton("Export a key")
        
        self.generate_radio.setChecked(True)
        
        operation_layout.addWidget(self.generate_radio)
        operation_layout.addWidget(self.import_radio)
        operation_layout.addWidget(self.export_radio)
        
        operation_group.setLayout(operation_layout)
        
        # Add to page layout
        self.layout.addWidget(operation_group)
        self.layout.addStretch()

class KeyGenerationPage(BaseWizardPage):
    """Page for generating a new key."""
    
    def __init__(self, parent=None):
        """Initialize the page."""
        super().__init__(
            "Generate Key",
            "Configure the parameters for the new key.",
            parent
        )
        
        # Register fields
        self.registerField("key_type", self.key_type_combo, "currentText")
        self.registerField("key_algorithm", self.algorithm_combo, "currentText")
        self.registerField("key_size", self.key_size_spin)
        self.registerField("key_label*", self.key_label_edit)
    
    def setup_ui(self):
        """Set up the user interface."""
        # Key type selection
        type_group = QGroupBox("Key Type")
        type_layout = QVBoxLayout()
        
        type_label = QLabel("Select key type:")
        self.key_type_combo = QComboBox()
        
        # Add key types
        self.key_type_combo.addItem("Symmetric")
        self.key_type_combo.addItem("Asymmetric")
        
        type_layout.addWidget(type_label)
        type_layout.addWidget(self.key_type_combo)
        
        type_group.setLayout(type_layout)
        
        # Algorithm selection
        algorithm_group = QGroupBox("Algorithm")
        algorithm_layout = QVBoxLayout()
        
        algorithm_label = QLabel("Select algorithm:")
        self.algorithm_combo = QComboBox()
        
        # Add algorithms
        self.update_algorithms()
        
        algorithm_layout.addWidget(algorithm_label)
        algorithm_layout.addWidget(self.algorithm_combo)
        
        algorithm_group.setLayout(algorithm_layout)
        
        # Key size selection
        size_group = QGroupBox("Key Size")
        size_layout = QVBoxLayout()
        
        size_label = QLabel("Select key size (bits):")
        self.key_size_spin = QSpinBox()
        self.key_size_spin.setRange(128, 8192)
        self.key_size_spin.setSingleStep(64)
        self.key_size_spin.setValue(256)
        
        size_layout.addWidget(size_label)
        size_layout.addWidget(self.key_size_spin)
        
        size_group.setLayout(size_layout)
        
        # Key label
        label_group = QGroupBox("Key Label")
        label_layout = QVBoxLayout()
        
        label_label = QLabel("Enter a label for the key:")
        self.key_label_edit = QLineEdit()
        
        label_layout.addWidget(label_label)
        label_layout.addWidget(self.key_label_edit)
        
        label_group.setLayout(label_layout)
        
        # Connect signals
        self.key_type_combo.currentTextChanged.connect(self.update_algorithms)
        self.algorithm_combo.currentTextChanged.connect(self.update_key_sizes)
        
        # Add to page layout
        self.layout.addWidget(type_group)
        self.layout.addWidget(algorithm_group)
        self.layout.addWidget(size_group)
        self.layout.addWidget(label_group)
    
    def update_algorithms(self):
        """Update the algorithm list based on the selected key type."""
        self.algorithm_combo.clear()
        
        key_type = self.key_type_combo.currentText()
        
        if key_type == "Symmetric":
            self.algorithm_combo.addItem("AES")
            self.algorithm_combo.addItem("ChaCha20")
        elif key_type == "Asymmetric":
            self.algorithm_combo.addItem("RSA")
            self.algorithm_combo.addItem("ECC")
            self.algorithm_combo.addItem("KYBER")  # Post-quantum
            self.algorithm_combo.addItem("DILITHIUM")  # Post-quantum
        
        self.update_key_sizes()
    
    def update_key_sizes(self):
        """Update the key size range based on the selected algorithm."""
        algorithm = self.algorithm_combo.currentText()
        
        if algorithm == "AES":
            self.key_size_spin.setRange(128, 256)
            self.key_size_spin.setSingleStep(64)
            self.key_size_spin.setValue(256)
        elif algorithm == "ChaCha20":
            self.key_size_spin.setRange(256, 256)
            self.key_size_spin.setValue(256)
        elif algorithm == "RSA":
            self.key_size_spin.setRange(2048, 8192)
            self.key_size_spin.setSingleStep(1024)
            self.key_size_spin.setValue(3072)
        elif algorithm == "ECC":
            self.key_size_spin.setRange(256, 521)
            self.key_size_spin.setSingleStep(128)
            self.key_size_spin.setValue(256)
        elif algorithm == "KYBER":
            self.key_size_spin.setRange(512, 1024)
            self.key_size_spin.setSingleStep(256)
            self.key_size_spin.setValue(768)
        elif algorithm == "DILITHIUM":
            self.key_size_spin.setRange(2, 5)
            self.key_size_spin.setSingleStep(1)
            self.key_size_spin.setValue(3)
    
    def initializePage(self):
        """Initialize the page when it is shown."""
        # Check if we should skip this page
        wizard = self.wizard()
        if not wizard.field("generate_key"):
            wizard.next()

class KeyImportPage(BaseWizardPage):
    """Page for importing an existing key."""
    
    def __init__(self, parent=None):
        """Initialize the page."""
        super().__init__(
            "Import Key",
            "Import an existing key from a file.",
            parent
        )
        
        # Register fields
        self.registerField("import_file_path*", self.file_path_edit)
        self.registerField("import_key_label*", self.key_label_edit)
        self.registerField("import_password", self.password_edit)
    
    def setup_ui(self):
        """Set up the user interface."""
        # File selection
        file_group = QGroupBox("Key File")
        file_layout = QVBoxLayout()
        
        file_label = QLabel("Select key file:")
        
        file_path_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_file)
        
        file_path_layout.addWidget(self.file_path_edit)
        file_path_layout.addWidget(browse_button)
        
        file_layout.addWidget(file_label)
        file_layout.addLayout(file_path_layout)
        
        file_group.setLayout(file_layout)
        
        # Key label
        label_group = QGroupBox("Key Label")
        label_layout = QVBoxLayout()
        
        label_label = QLabel("Enter a label for the key:")
        self.key_label_edit = QLineEdit()
        
        label_layout.addWidget(label_label)
        label_layout.addWidget(self.key_label_edit)
        
        label_group.setLayout(label_layout)
        
        # Password
        password_group = QGroupBox("Password (if required)")
        password_layout = QVBoxLayout()
        
        password_label = QLabel("Enter password:")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_edit)
        
        password_group.setLayout(password_layout)
        
        # Add to page layout
        self.layout.addWidget(file_group)
        self.layout.addWidget(label_group)
        self.layout.addWidget(password_group)
        self.layout.addStretch()
    
    def browse_file(self):
        """Browse for a key file to import."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Key File", "", "Key Files (*.key *.pem *.der);;All Files (*)"
        )
        
        if file_path:
            self.file_path_edit.setText(file_path)
            
            # Set default label from filename
            base_name = os.path.basename(file_path)
            name, _ = os.path.splitext(base_name)
            self.key_label_edit.setText(name)
    
    def initializePage(self):
        """Initialize the page when it is shown."""
        # Check if we should skip this page
        wizard = self.wizard()
        if not wizard.field("import_key"):
            wizard.next()

class KeyExportPage(BaseWizardPage):
    """Page for exporting a key."""
    
    def __init__(self, key_manager, parent=None):
        """Initialize the page."""
        self.key_manager = key_manager
        super().__init__(
            "Export Key",
            "Export a key to a file.",
            parent
        )
        
        # Register fields
        self.registerField("export_key_id", self.key_combo, "currentText")
        self.registerField("export_file_path*", self.file_path_edit)
        self.registerField("export_password", self.password_edit)
        self.registerField("export_protect", self.protect_check)
    
    def setup_ui(self):
        """Set up the user interface."""
        # Key selection
        key_group = QGroupBox("Key Selection")
        key_layout = QVBoxLayout()
        
        key_label = QLabel("Select key to export:")
        self.key_combo = QComboBox()
        
        refresh_button = QPushButton("Refresh Keys")
        refresh_button.clicked.connect(self.load_keys)
        
        key_layout.addWidget(key_label)
        key_layout.addWidget(self.key_combo)
        key_layout.addWidget(refresh_button)
        
        key_group.setLayout(key_layout)
        
        # File selection
        file_group = QGroupBox("Export File")
        file_layout = QVBoxLayout()
        
        file_label = QLabel("Select export location:")
        
        file_path_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_file)
        
        file_path_layout.addWidget(self.file_path_edit)
        file_path_layout.addWidget(browse_button)
        
        file_layout.addWidget(file_label)
        file_layout.addLayout(file_path_layout)
        
        file_group.setLayout(file_layout)
        
        # Protection options
        protection_group = QGroupBox("Protection Options")
        protection_layout = QVBoxLayout()
        
        self.protect_check = QCheckBox("Protect with password")
        self.protect_check.toggled.connect(self.update_page)
        
        password_label = QLabel("Enter password:")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setEnabled(False)
        
        protection_layout.addWidget(self.protect_check)
        protection_layout.addWidget(password_label)
        protection_layout.addWidget(self.password_edit)
        
        protection_group.setLayout(protection_layout)
        
        # Add to page layout
        self.layout.addWidget(key_group)
        self.layout.addWidget(file_group)
        self.layout.addWidget(protection_group)
        self.layout.addStretch()
        
        # Load keys
        self.load_keys()
    
    def load_keys(self):
        """Load available keys from the key manager."""
        self.key_combo.clear()
        
        # Get all keys
        keys = self.key_manager.active_keys
        
        # Add keys to the combo box
        for key_id in keys:
            self.key_combo.addItem(key_id)
    
    def browse_file(self):
        """Browse for a file location to export the key."""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Select Export Location", "", "Key Files (*.key *.pem *.der);;All Files (*)"
        )
        
        if file_path:
            self.file_path_edit.setText(file_path)
    
    def update_page(self):
        """Update the page based on the selected options."""
        self.password_edit.setEnabled(self.protect_check.isChecked())
    
    def validatePage(self):
        """Validate the page before proceeding."""
        if self.protect_check.isChecked() and not self.password_edit.text():
            QMessageBox.warning(self, "Warning", "Please enter a password for key protection.")
            return False
        
        return True
    
    def initializePage(self):
        """Initialize the page when it is shown."""
        # Check if we should skip this page
        wizard = self.wizard()
        if not wizard.field("export_key"):
            wizard.next()

class SummaryPage(BaseWizardPage):
    """Page for showing a summary of the key management operation."""
    
    def __init__(self, parent=None):
        """Initialize the page."""
        super().__init__(
            "Summary",
            "Review your key management settings before proceeding.",
            parent
        )
    
    def setup_ui(self):
        """Set up the user interface."""
        # Summary group
        summary_group = QGroupBox("Operation Summary")
        summary_layout = QVBoxLayout()
        
        # Operation information
        operation_label = QLabel("Operation:")
        self.operation_value = QLabel()
        
        # Key information
        key_label = QLabel("Key:")
        self.key_value = QLabel()
        
        # Details information
        details_label = QLabel("Details:")
        self.details_value = QLabel()
        self.details_value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        
        # Add to layout
        summary_layout.addWidget(operation_label)
        summary_layout.addWidget(self.operation_value)
        summary_layout.addWidget(key_label)
        summary_layout.addWidget(self.key_value)
        summary_layout.addWidget(details_label)
        summary_layout.addWidget(self.details_value)
        
        summary_group.setLayout(summary_layout)
        
        # Add to page layout
        self.layout.addWidget(summary_group)
        self.layout.addStretch()
    
    def initializePage(self):
        """Initialize the page when it is shown."""
        wizard = self.wizard()
        
        # Set operation information
        if wizard.field("generate_key"):
            self.operation_value.setText("Generate a new key")
            
            # Set key information
            key_type = wizard.field("key_type")
            algorithm = wizard.field("key_algorithm")
            key_size = wizard.field("key_size")
            key_label = wizard.field("key_label")
            
            self.key_value.setText(f"{key_type} key: {algorithm}-{key_size}")
            
            # Set details information
            details = f"Label: {key_label}\n"
            details += f"Type: {key_type}\n"
            details += f"Algorithm: {algorithm}\n"
            details += f"Size: {key_size} bits"
            
            self.details_value.setText(details)
            
        elif wizard.field("import_key"):
            self.operation_value.setText("Import an existing key")
            
            # Set key information
            file_path = wizard.field("import_file_path")
            key_label = wizard.field("import_key_label")
            
            self.key_value.setText(f"Import from: {os.path.basename(file_path)}")
            
            # Set details information
            details = f"Label: {key_label}\n"
            details += f"File: {file_path}\n"
            
            if wizard.field("import_password"):
                details += "Password protected: Yes"
            else:
                details += "Password protected: No"
            
            self.details_value.setText(details)
            
        elif wizard.field("export_key"):
            self.operation_value.setText("Export a key")
            
            # Set key information
            key_id = wizard.field("export_key_id")
            file_path = wizard.field("export_file_path")
            
            self.key_value.setText(f"Export key: {key_id}")
            
            # Set details information
            details = f"Key ID: {key_id}\n"
            details += f"Export to: {file_path}\n"
            
            if wizard.field("export_protect"):
                details += "Password protection: Yes"
            else:
                details += "Password protection: No"
            
            self.details_value.setText(details)

class KeyManagementWizard(BaseWizard):
    """Wizard for guiding users through key management operations."""
    
    def __init__(self, key_manager, parent=None):
        """Initialize the wizard."""
        self.key_manager = key_manager
        
        super().__init__(parent)
        
        self.setWindowTitle("Key Management Wizard")
    
    def add_pages(self):
        """Add pages to the wizard."""
        self.addPage(OperationSelectionPage(self))
        self.addPage(KeyGenerationPage(self))
        self.addPage(KeyImportPage(self))
        self.addPage(KeyExportPage(self.key_manager, self))
        self.addPage(SummaryPage(self))
    
    def collect_data(self):
        """Collect data from all fields."""
        # Operation information
        self.result_data['generate_key'] = self.field("generate_key")
        self.result_data['import_key'] = self.field("import_key")
        self.result_data['export_key'] = self.field("export_key")
        
        if self.field("generate_key"):
            # Key generation information
            self.result_data['key_type'] = self.field("key_type")
            self.result_data['key_algorithm'] = self.field("key_algorithm")
            self.result_data['key_size'] = self.field("key_size")
            self.result_data['key_label'] = self.field("key_label")
            
        elif self.field("import_key"):
            # Key import information
            self.result_data['import_file_path'] = self.field("import_file_path")
            self.result_data['import_key_label'] = self.field("import_key_label")
            self.result_data['import_password'] = self.field("import_password")
            
        elif self.field("export_key"):
            # Key export information
            self.result_data['export_key_id'] = self.field("export_key_id")
            self.result_data['export_file_path'] = self.field("export_file_path")
            self.result_data['export_password'] = self.field("export_password")
            self.result_data['export_protect'] = self.field("export_protect")
    
    def perform_operation(self):
        """Perform the key management operation."""
        try:
            if self.result_data['generate_key']:
                # Generate a new key
                key_type = self.result_data['key_type']
                algorithm = self.result_data['key_algorithm']
                key_size = self.result_data['key_size']
                key_label = self.result_data['key_label']
                
                if key_type == "Symmetric":
                    # Generate symmetric key
                    key = self.key_manager.generate_symmetric_key(
                        algorithm=algorithm,
                        key_size=key_size,
                        label=key_label
                    )
                    
                    return True, f"Symmetric key generated successfully. Key ID: {key}"
                    
                elif key_type == "Asymmetric":
                    # Generate asymmetric key pair
                    public_key, private_key = self.key_manager.generate_asymmetric_keypair(
                        algorithm=algorithm,
                        key_size=key_size,
                        label=key_label
                    )
                    
                    return True, f"Asymmetric key pair generated successfully.\nPublic Key ID: {public_key}\nPrivate Key ID: {private_key}"
                
            elif self.result_data['import_key']:
                # Import an existing key
                file_path = self.result_data['import_file_path']
                key_label = self.result_data['import_key_label']
                password = self.result_data['import_password'] or None
                
                # Read the key file
                with open(file_path, 'rb') as f:
                    key_data = f.read()
                
                # Import the key
                key_id = self.key_manager.import_key(
                    key_data=key_data,
                    label=key_label,
                    password=password
                )
                
                return True, f"Key imported successfully. Key ID: {key_id}"
                
            elif self.result_data['export_key']:
                # Export a key
                key_id = self.result_data['export_key_id']
                file_path = self.result_data['export_file_path']
                password = self.result_data['export_password'] if self.result_data['export_protect'] else None
                
                # Export the key
                self.key_manager.export_key(
                    key_id=key_id,
                    output_file=file_path,
                    password=password
                )
                
                return True, f"Key exported successfully to: {file_path}"
            
            return False, "No operation selected."
            
        except Exception as e:
            return False, f"Error during operation: {str(e)}"
