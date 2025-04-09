"""
Key Rotation Tab for the GUI.
"""

import os
from datetime import datetime
from typing import Optional, Dict, Any

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QRadioButton, QFileDialog, QLineEdit, QProgressBar, QTextEdit,
    QGroupBox, QFormLayout, QCheckBox, QMessageBox, QListWidget,
    QListWidgetItem, QDialog, QDialogButtonBox, QSpinBox
)
from PyQt6.QtCore import Qt

from ....core.key_management import KeyManager
from ....core.key_rotation import KeyRotationManager, KeyRotationPolicy


class KeyRotationTab(QWidget):
    """Tab for managing key rotation policies."""
    
    def __init__(self, key_manager: KeyManager, rotation_manager: KeyRotationManager):
        """Initialize the key rotation tab."""
        super().__init__()
        
        self.key_manager = key_manager
        self.rotation_manager = rotation_manager
        
        # Set up the UI
        self.setup_ui()
        
        # Refresh the policy list
        self.refresh_policy_list()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Create a horizontal layout for the list and details
        list_details_layout = QHBoxLayout()
        main_layout.addLayout(list_details_layout)
        
        # Create the policy list section
        policy_list_group = QGroupBox("Rotation Policies")
        policy_list_layout = QVBoxLayout(policy_list_group)
        
        # Policy list
        self.policy_list = QListWidget()
        self.policy_list.setMinimumWidth(250)
        self.policy_list.currentItemChanged.connect(self.policy_selected)
        policy_list_layout.addWidget(self.policy_list)
        
        # Policy list buttons
        policy_list_buttons = QHBoxLayout()
        
        self.add_policy_button = QPushButton("Add Policy")
        self.add_policy_button.clicked.connect(self.add_policy)
        policy_list_buttons.addWidget(self.add_policy_button)
        
        self.remove_policy_button = QPushButton("Remove Policy")
        self.remove_policy_button.clicked.connect(self.remove_policy)
        policy_list_buttons.addWidget(self.remove_policy_button)
        
        policy_list_layout.addLayout(policy_list_buttons)
        
        # Add the policy list to the main layout
        list_details_layout.addWidget(policy_list_group)
        
        # Create the policy details section
        policy_details_group = QGroupBox("Policy Details")
        policy_details_layout = QVBoxLayout(policy_details_group)
        
        # Policy details form
        details_form = QFormLayout()
        
        # Key ID
        self.key_id_label = QLabel("No policy selected")
        details_form.addRow("Key ID:", self.key_id_label)
        
        # Key type
        self.key_type_label = QLabel("")
        details_form.addRow("Key Type:", self.key_type_label)
        
        # Rotation interval
        self.rotation_interval_label = QLabel("")
        details_form.addRow("Rotation Interval:", self.rotation_interval_label)
        
        # Usage limits
        self.usage_limits_label = QLabel("")
        details_form.addRow("Usage Limits:", self.usage_limits_label)
        
        # Auto-rotate
        self.auto_rotate_label = QLabel("")
        details_form.addRow("Auto-Rotate:", self.auto_rotate_label)
        
        # Last rotation
        self.last_rotation_label = QLabel("")
        details_form.addRow("Last Rotation:", self.last_rotation_label)
        
        # Current usage
        self.current_usage_label = QLabel("")
        details_form.addRow("Current Usage:", self.current_usage_label)
        
        policy_details_layout.addLayout(details_form)
        
        # Rotation button
        self.rotate_button = QPushButton("Rotate Key Now")
        self.rotate_button.clicked.connect(self.rotate_key)
        policy_details_layout.addWidget(self.rotate_button)
        
        # Add the policy details to the main layout
        list_details_layout.addWidget(policy_details_group)
        
        # Create the results section
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        results_layout.addWidget(self.results_text)
        
        # Add the results to the main layout
        main_layout.addWidget(results_group)
    
    def refresh_policy_list(self):
        """Refresh the list of rotation policies."""
        # Clear the current list
        self.policy_list.clear()
        
        # Add policies from the rotation manager
        policies = self.rotation_manager.list_policies()
        
        for policy_data in policies:
            key_id = policy_data["key_id"]
            
            # Get key info
            key_info = self.key_manager.get_key_metadata(key_id)
            if key_info:
                # Create a list item
                item = QListWidgetItem(key_id)
                item.setData(Qt.ItemDataRole.UserRole, policy_data)
                self.policy_list.addItem(item)
    
    def policy_selected(self, current, previous):
        """Handle policy selection."""
        if current is None:
            # Clear the details
            self.key_id_label.setText("No policy selected")
            self.key_type_label.setText("")
            self.rotation_interval_label.setText("")
            self.usage_limits_label.setText("")
            self.auto_rotate_label.setText("")
            self.last_rotation_label.setText("")
            self.current_usage_label.setText("")
            self.rotate_button.setEnabled(False)
            return
        
        # Get the policy data
        policy_data = current.data(Qt.ItemDataRole.UserRole)
        
        # Update the details
        self.key_id_label.setText(policy_data["key_id"])
        
        # Get key info
        key_info = self.key_manager.get_key_metadata(policy_data["key_id"])
        if key_info:
            if key_info.get("type") == "hybrid":
                self.key_type_label.setText("Hybrid")
            elif key_info.get("post_quantum"):
                self.key_type_label.setText("Post-Quantum")
            elif key_info.get("type") == "symmetric":
                self.key_type_label.setText("Symmetric")
            elif key_info.get("type") == "asymmetric":
                self.key_type_label.setText("Asymmetric")
            else:
                self.key_type_label.setText("Unknown")
        else:
            self.key_type_label.setText("Unknown")
        
        # Rotation interval
        self.rotation_interval_label.setText(f"{policy_data['rotation_interval_days']} days")
        
        # Usage limits
        usage_limits = []
        if policy_data["max_bytes_encrypted"]:
            bytes_limit = policy_data["max_bytes_encrypted"]
            if bytes_limit >= 1024 * 1024 * 1024:
                bytes_limit_str = f"{bytes_limit / (1024 * 1024 * 1024):.2f} GB"
            elif bytes_limit >= 1024 * 1024:
                bytes_limit_str = f"{bytes_limit / (1024 * 1024):.2f} MB"
            elif bytes_limit >= 1024:
                bytes_limit_str = f"{bytes_limit / 1024:.2f} KB"
            else:
                bytes_limit_str = f"{bytes_limit} bytes"
            usage_limits.append(f"Max Bytes: {bytes_limit_str}")
        
        if policy_data["max_operations"]:
            usage_limits.append(f"Max Operations: {policy_data['max_operations']}")
        
        if usage_limits:
            self.usage_limits_label.setText(", ".join(usage_limits))
        else:
            self.usage_limits_label.setText("None")
        
        # Auto-rotate
        self.auto_rotate_label.setText("Yes" if policy_data["auto_rotate"] else "No")
        
        # Last rotation
        last_rotation_time = datetime.fromtimestamp(policy_data["last_rotation_time"])
        self.last_rotation_label.setText(last_rotation_time.strftime("%Y-%m-%d %H:%M:%S"))
        
        # Current usage
        current_usage = []
        if policy_data["bytes_encrypted"] > 0:
            bytes_used = policy_data["bytes_encrypted"]
            if bytes_used >= 1024 * 1024 * 1024:
                bytes_used_str = f"{bytes_used / (1024 * 1024 * 1024):.2f} GB"
            elif bytes_used >= 1024 * 1024:
                bytes_used_str = f"{bytes_used / (1024 * 1024):.2f} MB"
            elif bytes_used >= 1024:
                bytes_used_str = f"{bytes_used / 1024:.2f} KB"
            else:
                bytes_used_str = f"{bytes_used} bytes"
            current_usage.append(f"Bytes Encrypted: {bytes_used_str}")
        
        if policy_data["operation_count"] > 0:
            current_usage.append(f"Operations: {policy_data['operation_count']}")
        
        if current_usage:
            self.current_usage_label.setText(", ".join(current_usage))
        else:
            self.current_usage_label.setText("None")
        
        # Enable the rotate button
        self.rotate_button.setEnabled(True)
    
    def add_policy(self):
        """Add a new rotation policy."""
        # Create a dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Rotation Policy")
        
        # Create the dialog layout
        layout = QVBoxLayout(dialog)
        
        # Create a form layout for the inputs
        form_layout = QFormLayout()
        
        # Key selection
        key_combo = QComboBox()
        
        # Add keys from key manager
        for key_id in self.key_manager.active_keys:
            # Skip keys that already have policies
            if self.rotation_manager.get_policy(key_id):
                continue
            
            key_combo.addItem(key_id)
        
        form_layout.addRow("Key:", key_combo)
        
        # Rotation interval
        interval_spin = QSpinBox()
        interval_spin.setMinimum(1)
        interval_spin.setMaximum(365)
        interval_spin.setValue(90)
        form_layout.addRow("Rotation Interval (days):", interval_spin)
        
        # Max bytes encrypted
        bytes_spin = QSpinBox()
        bytes_spin.setMinimum(0)
        bytes_spin.setMaximum(1000000)
        bytes_spin.setValue(0)
        bytes_spin.setSpecialValueText("No limit")
        form_layout.addRow("Max Bytes Encrypted (MB):", bytes_spin)
        
        # Max operations
        operations_spin = QSpinBox()
        operations_spin.setMinimum(0)
        operations_spin.setMaximum(1000000)
        operations_spin.setValue(0)
        operations_spin.setSpecialValueText("No limit")
        form_layout.addRow("Max Operations:", operations_spin)
        
        # Auto-rotate
        auto_rotate_check = QCheckBox()
        form_layout.addRow("Auto-Rotate:", auto_rotate_check)
        
        layout.addLayout(form_layout)
        
        # Add buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        # Show the dialog
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Get the values
            key_id = key_combo.currentText()
            rotation_interval_days = interval_spin.value()
            max_bytes_encrypted = bytes_spin.value() * 1024 * 1024 if bytes_spin.value() > 0 else None
            max_operations = operations_spin.value() if operations_spin.value() > 0 else None
            auto_rotate = auto_rotate_check.isChecked()
            
            # Create the policy
            policy = KeyRotationPolicy(
                key_id=key_id,
                rotation_interval_days=rotation_interval_days,
                max_bytes_encrypted=max_bytes_encrypted,
                max_operations=max_operations,
                auto_rotate=auto_rotate
            )
            
            # Add the policy
            self.rotation_manager.add_policy(policy)
            
            # Refresh the policy list
            self.refresh_policy_list()
            
            # Show result
            self.results_text.append(f"Added rotation policy for key {key_id}.")
            self.results_text.append(f"Rotation interval: {rotation_interval_days} days")
            if max_bytes_encrypted:
                self.results_text.append(f"Max bytes encrypted: {max_bytes_encrypted / (1024 * 1024):.2f} MB")
            if max_operations:
                self.results_text.append(f"Max operations: {max_operations}")
            self.results_text.append(f"Auto-rotate: {'Yes' if auto_rotate else 'No'}")
    
    def remove_policy(self):
        """Remove the selected rotation policy."""
        # Get the selected policy
        current_item = self.policy_list.currentItem()
        if current_item is None:
            QMessageBox.warning(self, "No Policy Selected", "Please select a policy to remove.")
            return
        
        # Get the policy data
        policy_data = current_item.data(Qt.ItemDataRole.UserRole)
        key_id = policy_data["key_id"]
        
        # Confirm removal
        confirm = QMessageBox.question(
            self,
            "Confirm Removal",
            f"Are you sure you want to remove the rotation policy for key {key_id}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            # Remove the policy
            self.rotation_manager.remove_policy(key_id)
            
            # Refresh the policy list
            self.refresh_policy_list()
            
            # Show result
            self.results_text.append(f"Removed rotation policy for key {key_id}.")
    
    def rotate_key(self):
        """Rotate the selected key."""
        # Get the selected policy
        current_item = self.policy_list.currentItem()
        if current_item is None:
            QMessageBox.warning(self, "No Policy Selected", "Please select a policy to rotate the key.")
            return
        
        # Get the policy data
        policy_data = current_item.data(Qt.ItemDataRole.UserRole)
        key_id = policy_data["key_id"]
        
        # Confirm rotation
        confirm = QMessageBox.question(
            self,
            "Confirm Rotation",
            f"Are you sure you want to rotate the key {key_id}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            # Rotate the key
            new_key_id = self.rotation_manager.rotate_key(key_id)
            
            if new_key_id:
                # Refresh the policy list
                self.refresh_policy_list()
                
                # Show result
                self.results_text.append(f"Rotated key {key_id} to {new_key_id}.")
                
                # Select the new policy
                for i in range(self.policy_list.count()):
                    item = self.policy_list.item(i)
                    if item.text() == new_key_id:
                        self.policy_list.setCurrentItem(item)
                        break
            else:
                # Show error
                QMessageBox.critical(self, "Rotation Failed", f"Failed to rotate key {key_id}.")
                self.results_text.append(f"Failed to rotate key {key_id}.")
