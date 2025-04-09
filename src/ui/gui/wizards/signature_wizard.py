"""
Signature wizard for guided digital signature operations.
"""

import os
from PyQt6.QtWidgets import (
    QWizardPage, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QFileDialog, QComboBox, QCheckBox, QGroupBox,
    QRadioButton, QListWidget, QListWidgetItem, QMessageBox
)
from PyQt6.QtCore import Qt

from .base_wizard import BaseWizard, BaseWizardPage
from ....core.signatures import SignatureEngine
from ....core.key_management import KeyManager
from ....core.cosign import CoSignatureManager
from ....core.timestamp import TimestampManager

class OperationSelectionPage(BaseWizardPage):
    """Page for selecting the signature operation."""
    
    def __init__(self, parent=None):
        super().__init__("Select Operation", "Choose the signature operation you want to perform.", parent)
        self.registerField("sign", self.sign_radio)
        self.registerField("verify", self.verify_radio)
        self.registerField("cosign", self.cosign_radio)
    
    def setup_ui(self):
        operation_group = QGroupBox("Signature Operation")
        operation_layout = QVBoxLayout()
        
        self.sign_radio = QRadioButton("Sign a document")
        self.verify_radio = QRadioButton("Verify a signature")
        self.cosign_radio = QRadioButton("Co-sign a document")
        
        self.sign_radio.setChecked(True)
        
        operation_layout.addWidget(self.sign_radio)
        operation_layout.addWidget(self.verify_radio)
        operation_layout.addWidget(self.cosign_radio)
        
        operation_group.setLayout(operation_layout)
        self.layout.addWidget(operation_group)
        self.layout.addStretch()

class FileSelectionPage(BaseWizardPage):
    """Page for selecting the file to sign or verify."""
    
    def __init__(self, parent=None):
        super().__init__("Select File", "Select the file you want to sign or verify.", parent)
        self.registerField("file_path*", self.file_path_edit)
        self.registerField("signature_path", self.signature_path_edit)
    
    def setup_ui(self):
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()
        
        # Input file
        input_layout = QHBoxLayout()
        input_label = QLabel("File:")
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_file)
        
        input_layout.addWidget(input_label)
        input_layout.addWidget(self.file_path_edit)
        input_layout.addWidget(browse_button)
        
        # Signature file (for verification)
        signature_layout = QHBoxLayout()
        self.signature_label = QLabel("Signature file:")
        self.signature_path_edit = QLineEdit()
        self.signature_path_edit.setReadOnly(True)
        signature_browse_button = QPushButton("Browse...")
        signature_browse_button.clicked.connect(self.browse_signature)
        
        signature_layout.addWidget(self.signature_label)
        signature_layout.addWidget(self.signature_path_edit)
        signature_layout.addWidget(signature_browse_button)
        
        file_layout.addLayout(input_layout)
        file_layout.addLayout(signature_layout)
        file_group.setLayout(file_layout)
        
        self.layout.addWidget(file_group)
        self.layout.addStretch()
    
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if file_path:
            self.file_path_edit.setText(file_path)
            
            # Set default signature path for signing
            if self.wizard().field("sign") or self.wizard().field("cosign"):
                signature_path = file_path + ".sig"
                self.signature_path_edit.setText(signature_path)
    
    def browse_signature(self):
        signature_path, _ = QFileDialog.getOpenFileName(
            self, "Select Signature File", "", "Signature Files (*.sig *.cosig);;All Files (*)"
        )
        if signature_path:
            self.signature_path_edit.setText(signature_path)
    
    def initializePage(self):
        # Update UI based on operation
        is_verify = self.wizard().field("verify")
        self.signature_label.setVisible(is_verify)
        self.signature_path_edit.setVisible(is_verify)
        self.signature_path_edit.setEnabled(is_verify)
        
        # Make signature path required for verification
        if is_verify:
            self.registerField("signature_path*", self.signature_path_edit)

class KeySelectionPage(BaseWizardPage):
    """Page for selecting the signing or verification key."""
    
    def __init__(self, key_manager, parent=None):
        self.key_manager = key_manager
        super().__init__("Select Key", "Choose the key you want to use.", parent)
        self.registerField("key_id", self.key_combo, "currentText")
    
    def setup_ui(self):
        key_group = QGroupBox("Key Selection")
        key_layout = QVBoxLayout()
        
        self.key_label = QLabel("Select a key:")
        self.key_combo = QComboBox()
        
        refresh_button = QPushButton("Refresh Keys")
        refresh_button.clicked.connect(self.load_keys)
        
        key_layout.addWidget(self.key_label)
        key_layout.addWidget(self.key_combo)
        key_layout.addWidget(refresh_button)
        
        key_group.setLayout(key_layout)
        self.layout.addWidget(key_group)
        
        # Algorithm selection
        algorithm_group = QGroupBox("Signature Algorithm")
        algorithm_layout = QVBoxLayout()
        
        algorithm_label = QLabel("Select algorithm:")
        self.algorithm_combo = QComboBox()
        
        # Add algorithms
        self.algorithm_combo.addItem("RSA-PSS")
        self.algorithm_combo.addItem("RSA-PKCS1v15")
        self.algorithm_combo.addItem("ECDSA")
        self.algorithm_combo.addItem("Ed25519")
        self.algorithm_combo.addItem("DILITHIUM")  # Post-quantum
        
        algorithm_layout.addWidget(algorithm_label)
        algorithm_layout.addWidget(self.algorithm_combo)
        
        algorithm_group.setLayout(algorithm_layout)
        self.layout.addWidget(algorithm_group)
        self.layout.addStretch()
        
        # Register algorithm field
        self.registerField("algorithm", self.algorithm_combo, "currentText")
        
        # Load keys
        self.load_keys()
    
    def load_keys(self):
        self.key_combo.clear()
        
        # Get all keys
        keys = self.key_manager.active_keys
        
        # Add appropriate keys based on operation
        is_verify = self.wizard().field("verify")
        
        for key_id, key_data in keys.items():
            if is_verify:
                # For verification, show public keys
                if key_id.endswith('.public') or key_data.get('key_type') == 'public':
                    self.key_combo.addItem(key_id)
            else:
                # For signing, show private keys
                if key_id.endswith('.private') or key_data.get('key_type') == 'private':
                    self.key_combo.addItem(key_id)
    
    def initializePage(self):
        # Update UI based on operation
        is_verify = self.wizard().field("verify")
        
        if is_verify:
            self.key_label.setText("Select verification key:")
            self.setTitle("Select Verification Key")
            self.setSubTitle("Choose the key you want to use for verification.")
        else:
            self.key_label.setText("Select signing key:")
            self.setTitle("Select Signing Key")
            self.setSubTitle("Choose the key you want to use for signing.")
        
        # Reload keys
        self.load_keys()

class CoSignOptionsPage(BaseWizardPage):
    """Page for configuring co-signature options."""
    
    def __init__(self, key_manager, parent=None):
        self.key_manager = key_manager
        super().__init__("Co-Signature Options", "Configure options for co-signing.", parent)
    
    def setup_ui(self):
        # Co-sign type
        type_group = QGroupBox("Co-Signature Type")
        type_layout = QVBoxLayout()
        
        self.create_radio = QRadioButton("Create a new co-signature chain")
        self.add_radio = QRadioButton("Add to an existing co-signature chain")
        
        self.create_radio.setChecked(True)
        
        type_layout.addWidget(self.create_radio)
        type_layout.addWidget(self.add_radio)
        
        type_group.setLayout(type_layout)
        
        # Required signers
        signers_group = QGroupBox("Required Signers")
        signers_layout = QVBoxLayout()
        
        # Available keys list
        keys_layout = QHBoxLayout()
        
        available_keys_layout = QVBoxLayout()
        available_keys_label = QLabel("Available Keys:")
        self.available_keys_list = QListWidget()
        self.available_keys_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        
        available_keys_layout.addWidget(available_keys_label)
        available_keys_layout.addWidget(self.available_keys_list)
        
        # Buttons for adding/removing signers
        buttons_layout = QVBoxLayout()
        self.add_signer_button = QPushButton("Add >")
        self.add_signer_button.clicked.connect(self.add_signer)
        
        self.remove_signer_button = QPushButton("< Remove")
        self.remove_signer_button.clicked.connect(self.remove_signer)
        
        buttons_layout.addStretch()
        buttons_layout.addWidget(self.add_signer_button)
        buttons_layout.addWidget(self.remove_signer_button)
        buttons_layout.addStretch()
        
        # Selected signers list
        selected_signers_layout = QVBoxLayout()
        selected_signers_label = QLabel("Required Signers:")
        self.selected_signers_list = QListWidget()
        self.selected_signers_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        
        selected_signers_layout.addWidget(selected_signers_label)
        selected_signers_layout.addWidget(self.selected_signers_list)
        
        keys_layout.addLayout(available_keys_layout)
        keys_layout.addLayout(buttons_layout)
        keys_layout.addLayout(selected_signers_layout)
        
        signers_layout.addLayout(keys_layout)
        
        # Refresh keys button
        refresh_keys_button = QPushButton("Refresh Keys")
        refresh_keys_button.clicked.connect(self.load_keys)
        signers_layout.addWidget(refresh_keys_button)
        
        signers_group.setLayout(signers_layout)
        
        # Add to page layout
        self.layout.addWidget(type_group)
        self.layout.addWidget(signers_group)
        
        # Register fields
        self.registerField("create_cosign", self.create_radio)
        self.registerField("add_cosign", self.add_radio)
        
        # Load keys
        self.load_keys()
    
    def load_keys(self):
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
    
    def add_signer(self):
        # Get selected items
        selected_items = self.available_keys_list.selectedItems()
        
        for item in selected_items:
            # Check if the key is already in the signers list
            existing_items = self.selected_signers_list.findItems(
                item.text(), Qt.MatchFlag.MatchExactly
            )
            
            if not existing_items:
                # Add to signers list
                self.selected_signers_list.addItem(item.text())
    
    def remove_signer(self):
        # Get selected items
        selected_items = self.selected_signers_list.selectedItems()
        
        for item in selected_items:
            # Remove from the list
            row = self.selected_signers_list.row(item)
            self.selected_signers_list.takeItem(row)
    
    def get_selected_signers(self):
        signers = []
        for i in range(self.selected_signers_list.count()):
            signers.append(self.selected_signers_list.item(i).text())
        return signers
    
    def validatePage(self):
        if self.create_radio.isChecked():
            # Store the signers in the wizard field
            self.wizard().result_data['required_signers'] = self.get_selected_signers()
        
        return True
    
    def initializePage(self):
        # Check if we should skip this page
        if not self.wizard().field("cosign"):
            self.wizard().next()

class TimestampOptionsPage(BaseWizardPage):
    """Page for configuring timestamp options."""
    
    def __init__(self, parent=None):
        super().__init__("Timestamp Options", "Configure options for timestamping.", parent)
    
    def setup_ui(self):
        # Timestamp options
        timestamp_group = QGroupBox("Timestamp Options")
        timestamp_layout = QVBoxLayout()
        
        self.timestamp_check = QCheckBox("Add timestamp to signature")
        self.timestamp_check.setChecked(True)
        self.timestamp_check.toggled.connect(self.update_page)
        
        # TSA options
        tsa_group = QGroupBox("Time Stamping Authority (TSA)")
        tsa_layout = QVBoxLayout()
        
        self.use_tsa_check = QCheckBox("Use external TSA server")
        self.use_tsa_check.toggled.connect(self.update_page)
        
        tsa_url_label = QLabel("TSA URL:")
        self.tsa_url_edit = QLineEdit("https://freetsa.org/tsr")
        
        tsa_layout.addWidget(self.use_tsa_check)
        tsa_layout.addWidget(tsa_url_label)
        tsa_layout.addWidget(self.tsa_url_edit)
        
        tsa_group.setLayout(tsa_layout)
        
        timestamp_layout.addWidget(self.timestamp_check)
        timestamp_layout.addWidget(tsa_group)
        
        timestamp_group.setLayout(timestamp_layout)
        
        # Add to page layout
        self.layout.addWidget(timestamp_group)
        self.layout.addStretch()
        
        # Register fields
        self.registerField("add_timestamp", self.timestamp_check)
        self.registerField("use_tsa", self.use_tsa_check)
        self.registerField("tsa_url", self.tsa_url_edit)
        
        # Initial update
        self.update_page()
    
    def update_page(self):
        # Enable/disable TSA options based on timestamp checkbox
        tsa_enabled = self.timestamp_check.isChecked()
        self.use_tsa_check.setEnabled(tsa_enabled)
        
        # Enable/disable TSA URL based on TSA checkbox
        url_enabled = tsa_enabled and self.use_tsa_check.isChecked()
        self.tsa_url_edit.setEnabled(url_enabled)
    
    def initializePage(self):
        # Check if we should skip this page
        if self.wizard().field("verify"):
            self.wizard().next()

class SummaryPage(BaseWizardPage):
    """Page for showing a summary of the signature operation."""
    
    def __init__(self, parent=None):
        super().__init__("Summary", "Review your signature settings before proceeding.", parent)
    
    def setup_ui(self):
        # Summary group
        summary_group = QGroupBox("Operation Summary")
        summary_layout = QVBoxLayout()
        
        # Operation information
        operation_label = QLabel("Operation:")
        self.operation_value = QLabel()
        
        # File information
        file_label = QLabel("File:")
        self.file_value = QLabel()
        self.file_value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        
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
        summary_layout.addWidget(file_label)
        summary_layout.addWidget(self.file_value)
        summary_layout.addWidget(key_label)
        summary_layout.addWidget(self.key_value)
        summary_layout.addWidget(details_label)
        summary_layout.addWidget(self.details_value)
        
        summary_group.setLayout(summary_layout)
        
        # Add to page layout
        self.layout.addWidget(summary_group)
        self.layout.addStretch()
    
    def initializePage(self):
        wizard = self.wizard()
        
        # Set operation information
        if wizard.field("sign"):
            self.operation_value.setText("Sign a document")
        elif wizard.field("verify"):
            self.operation_value.setText("Verify a signature")
        elif wizard.field("cosign"):
            if wizard.field("create_cosign"):
                self.operation_value.setText("Create a new co-signature chain")
            else:
                self.operation_value.setText("Add to an existing co-signature chain")
        
        # Set file information
        self.file_value.setText(wizard.field("file_path"))
        
        # Set key information
        self.key_value.setText(wizard.field("key_id"))
        
        # Set details information
        details = []
        
        if wizard.field("sign") or wizard.field("cosign"):
            details.append(f"Algorithm: {wizard.field('algorithm')}")
            
            if wizard.field("add_timestamp"):
                details.append("Add timestamp: Yes")
                if wizard.field("use_tsa"):
                    details.append(f"TSA URL: {wizard.field('tsa_url')}")
                else:
                    details.append("TSA: Local timestamp")
            else:
                details.append("Add timestamp: No")
            
            if wizard.field("cosign") and wizard.field("create_cosign"):
                required_signers = wizard.result_data.get('required_signers', [])
                if required_signers:
                    details.append(f"Required signers: {len(required_signers)}")
                    for signer in required_signers:
                        details.append(f"  - {signer}")
        
        elif wizard.field("verify"):
            details.append(f"Signature file: {wizard.field('signature_path')}")
        
        self.details_value.setText("\n".join(details))

class SignatureWizard(BaseWizard):
    """Wizard for guiding users through digital signature operations."""
    
    def __init__(self, key_manager, signature_engine, cosign_manager=None, timestamp_manager=None, parent=None):
        self.key_manager = key_manager
        self.signature_engine = signature_engine
        self.cosign_manager = cosign_manager or CoSignatureManager(key_manager)
        self.timestamp_manager = timestamp_manager or TimestampManager()
        
        super().__init__(parent)
        
        self.setWindowTitle("Digital Signature Wizard")
    
    def add_pages(self):
        self.addPage(OperationSelectionPage(self))
        self.addPage(FileSelectionPage(self))
        self.addPage(KeySelectionPage(self.key_manager, self))
        self.addPage(CoSignOptionsPage(self.key_manager, self))
        self.addPage(TimestampOptionsPage(self))
        self.addPage(SummaryPage(self))
    
    def collect_data(self):
        # Operation information
        self.result_data['sign'] = self.field("sign")
        self.result_data['verify'] = self.field("verify")
        self.result_data['cosign'] = self.field("cosign")
        
        # File information
        self.result_data['file_path'] = self.field("file_path")
        
        if self.field("verify") or (self.field("cosign") and self.field("add_cosign")):
            self.result_data['signature_path'] = self.field("signature_path")
        
        # Key information
        self.result_data['key_id'] = self.field("key_id")
        
        if self.field("sign") or self.field("cosign"):
            # Algorithm information
            self.result_data['algorithm'] = self.field("algorithm")
            
            # Timestamp information
            self.result_data['add_timestamp'] = self.field("add_timestamp")
            self.result_data['use_tsa'] = self.field("use_tsa")
            self.result_data['tsa_url'] = self.field("tsa_url")
            
            if self.field("cosign"):
                # Co-sign information
                self.result_data['create_cosign'] = self.field("create_cosign")
                self.result_data['add_cosign'] = self.field("add_cosign")
                # Required signers are collected in the CoSignOptionsPage
    
    def perform_operation(self):
        try:
            # Read the file
            with open(self.result_data['file_path'], 'rb') as f:
                file_data = f.read()
            
            if self.result_data['sign']:
                # Get the key
                key = self.key_manager.get_key(self.result_data['key_id'])
                
                # Sign the file
                signature_result = self.signature_engine.sign(
                    data=file_data,
                    private_key=key,
                    algorithm=self.result_data['algorithm']
                )
                
                # Add timestamp if requested
                if self.result_data['add_timestamp']:
                    signature_result = self.timestamp_manager.timestamp_signature(
                        signature_data=signature_result,
                        use_tsa=self.result_data['use_tsa'],
                        tsa_url=self.result_data['tsa_url'] if self.result_data['use_tsa'] else None
                    )
                
                # Save the signature
                output_path = self.result_data['file_path'] + ".sig"
                self.signature_engine.save_signature(signature_result, output_path)
                
                return True, f"File signed successfully. Signature saved to: {output_path}"
                
            elif self.result_data['verify']:
                # Get the key
                key = self.key_manager.get_key(self.result_data['key_id'])
                
                # Load the signature
                signature_result = self.signature_engine.load_signature(self.result_data['signature_path'])
                
                # Verify the signature
                is_valid = self.signature_engine.verify(
                    data=file_data,
                    signature_result=signature_result,
                    public_key=key
                )
                
                # Check timestamp if present
                timestamp_valid = None
                if 'timestamp' in signature_result:
                    timestamp_result = self.timestamp_manager.verify_signature_timestamp(signature_result)
                    timestamp_valid = timestamp_result.get('valid')
                
                if is_valid:
                    message = "Signature is valid."
                    if timestamp_valid is not None:
                        message += f"\nTimestamp is {'valid' if timestamp_valid else 'invalid'}."
                    return True, message
                else:
                    return False, "Signature is invalid."
                
            elif self.result_data['cosign']:
                # Get the key
                key = self.key_manager.get_key(self.result_data['key_id'])
                
                if self.result_data['create_cosign']:
                    # Create a new co-signature chain
                    required_signers = self.result_data.get('required_signers', [])
                    
                    # Prepare metadata
                    metadata = {
                        "filename": os.path.basename(self.result_data['file_path']),
                        "created_by": self.result_data['key_id']
                    }
                    
                    # Create the signature chain
                    signature_chain = self.cosign_manager.create_signature_chain(
                        data=file_data,
                        signer_key_id=self.result_data['key_id'],
                        algorithm=self.result_data['algorithm'],
                        metadata=metadata,
                        required_signers=required_signers
                    )
                    
                    # Save the signature chain
                    output_path = self.result_data['file_path'] + ".cosig"
                    import json
                    with open(output_path, "w") as f:
                        json.dump(signature_chain, f, indent=2)
                    
                    return True, f"Co-signature chain created successfully. Saved to: {output_path}"
                    
                else:
                    # Add to an existing co-signature chain
                    # Load the signature chain
                    import json
                    with open(self.result_data['signature_path'], "r") as f:
                        signature_chain = json.load(f)
                    
                    # Add the signature
                    updated_chain = self.cosign_manager.add_signature(
                        data=file_data,
                        signature_chain=signature_chain,
                        signer_key_id=self.result_data['key_id'],
                        algorithm=self.result_data['algorithm']
                    )
                    
                    # Save the updated signature chain
                    with open(self.result_data['signature_path'], "w") as f:
                        json.dump(updated_chain, f, indent=2)
                    
                    return True, f"Signature added successfully to the co-signature chain."
            
            return False, "No operation selected."
            
        except Exception as e:
            return False, f"Error during operation: {str(e)}"
