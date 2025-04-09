"""
Audit Tab for the GUI.
"""

import os
import time
import datetime
from typing import Optional, Dict, Any, List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QRadioButton, QFileDialog, QLineEdit, QProgressBar, QTextEdit,
    QGroupBox, QFormLayout, QCheckBox, QMessageBox, QListWidget,
    QListWidgetItem, QDialog, QDialogButtonBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QTabWidget, QDateTimeEdit, QSplitter
)
from PyQt6.QtCore import Qt, QDateTime
from PyQt6.QtGui import QColor

from ....core.crypto_audit import (
    AuditEventType,
    AuditSeverity,
    AuditEvent,
    AlertRule,
    FileAuditLogDestination,
    CryptoAuditLogger,
    create_failed_authentication_rule,
    create_sensitive_operation_rule,
    create_error_rate_rule
)


class AuditTab(QWidget):
    """Tab for viewing and analyzing audit logs."""
    
    def __init__(self, audit_logger: CryptoAuditLogger):
        """Initialize the audit tab."""
        super().__init__()
        
        self.audit_logger = audit_logger
        
        # Set up the UI
        self.setup_ui()
        
        # Refresh the event list
        self.refresh_events()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Create a splitter for resizable sections
        splitter = QSplitter(Qt.Orientation.Vertical)
        main_layout.addWidget(splitter)
        
        # Create the filter section
        filter_group = QGroupBox("Filters")
        filter_layout = QVBoxLayout(filter_group)
        
        # Filter form
        filter_form = QFormLayout()
        
        # Event type filter
        self.event_type_combo = QComboBox()
        self.event_type_combo.addItem("All Types", None)
        for event_type in AuditEventType:
            self.event_type_combo.addItem(event_type.value, event_type)
        filter_form.addRow("Event Type:", self.event_type_combo)
        
        # Severity filter
        self.severity_combo = QComboBox()
        self.severity_combo.addItem("All Severities", None)
        for severity in AuditSeverity:
            self.severity_combo.addItem(severity.value, severity)
        filter_form.addRow("Severity:", self.severity_combo)
        
        # User ID filter
        self.user_id_edit = QLineEdit()
        filter_form.addRow("User ID:", self.user_id_edit)
        
        # Time range filter
        time_range_layout = QHBoxLayout()
        
        self.start_time_edit = QDateTimeEdit()
        self.start_time_edit.setDateTime(QDateTime.currentDateTime().addDays(-7))
        self.start_time_edit.setCalendarPopup(True)
        time_range_layout.addWidget(QLabel("From:"))
        time_range_layout.addWidget(self.start_time_edit)
        
        self.end_time_edit = QDateTimeEdit()
        self.end_time_edit.setDateTime(QDateTime.currentDateTime())
        self.end_time_edit.setCalendarPopup(True)
        time_range_layout.addWidget(QLabel("To:"))
        time_range_layout.addWidget(self.end_time_edit)
        
        filter_form.addRow("Time Range:", time_range_layout)
        
        # Add the filter form to the layout
        filter_layout.addLayout(filter_form)
        
        # Filter buttons
        filter_buttons = QHBoxLayout()
        
        self.apply_filter_button = QPushButton("Apply Filters")
        self.apply_filter_button.clicked.connect(self.apply_filters)
        filter_buttons.addWidget(self.apply_filter_button)
        
        self.clear_filter_button = QPushButton("Clear Filters")
        self.clear_filter_button.clicked.connect(self.clear_filters)
        filter_buttons.addWidget(self.clear_filter_button)
        
        filter_layout.addLayout(filter_buttons)
        
        # Add the filter group to the splitter
        splitter.addWidget(filter_group)
        
        # Create the events section
        events_group = QGroupBox("Audit Events")
        events_layout = QVBoxLayout(events_group)
        
        # Events table
        self.events_table = QTableWidget()
        self.events_table.setColumnCount(6)
        self.events_table.setHorizontalHeaderLabels(["Time", "Type", "Severity", "User", "Description", "Event ID"])
        self.events_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.events_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.events_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.events_table.currentItemChanged.connect(self.event_selected)
        events_layout.addWidget(self.events_table)
        
        # Add the events group to the splitter
        splitter.addWidget(events_group)
        
        # Create the details section
        details_group = QGroupBox("Event Details")
        details_layout = QVBoxLayout(details_group)
        
        # Details text
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        
        # Add the details group to the splitter
        splitter.addWidget(details_group)
        
        # Set the initial splitter sizes
        splitter.setSizes([100, 300, 200])
        
        # Add buttons at the bottom
        buttons_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_events)
        buttons_layout.addWidget(self.refresh_button)
        
        self.export_button = QPushButton("Export Report")
        self.export_button.clicked.connect(self.export_report)
        buttons_layout.addWidget(self.export_button)
        
        self.alerts_button = QPushButton("View Alerts")
        self.alerts_button.clicked.connect(self.view_alerts)
        buttons_layout.addWidget(self.alerts_button)
        
        main_layout.addLayout(buttons_layout)
    
    def apply_filters(self):
        """Apply filters and refresh the event list."""
        self.refresh_events()
    
    def clear_filters(self):
        """Clear all filters and refresh the event list."""
        self.event_type_combo.setCurrentIndex(0)
        self.severity_combo.setCurrentIndex(0)
        self.user_id_edit.clear()
        self.start_time_edit.setDateTime(QDateTime.currentDateTime().addDays(-7))
        self.end_time_edit.setDateTime(QDateTime.currentDateTime())
        
        self.refresh_events()
    
    def refresh_events(self):
        """Refresh the list of audit events."""
        # Get the filter values
        event_type = self.event_type_combo.currentData()
        severity = self.severity_combo.currentData()
        user_id = self.user_id_edit.text().strip() or None
        
        start_time = self.start_time_edit.dateTime().toSecsSinceEpoch()
        end_time = self.end_time_edit.dateTime().toSecsSinceEpoch()
        
        # Build the filters
        filters = {}
        if event_type:
            filters["event_type"] = event_type.value
        if severity:
            filters["severity"] = severity.value
        if user_id:
            filters["user_id"] = user_id
        
        # Get the events
        events = self.audit_logger.get_events(
            filters=filters,
            start_time=start_time,
            end_time=end_time
        )
        
        # Update the table
        self.events_table.setRowCount(0)
        self.events_table.setRowCount(len(events))
        
        for i, event in enumerate(events):
            # Time
            timestamp = datetime.datetime.fromtimestamp(event.timestamp)
            time_item = QTableWidgetItem(timestamp.strftime("%Y-%m-%d %H:%M:%S"))
            self.events_table.setItem(i, 0, time_item)
            
            # Type
            type_item = QTableWidgetItem(event.event_type.value)
            self.events_table.setItem(i, 1, type_item)
            
            # Severity
            severity_item = QTableWidgetItem(event.severity.value)
            if event.severity == AuditSeverity.ERROR or event.severity == AuditSeverity.CRITICAL:
                severity_item.setBackground(QColor(255, 200, 200))
            elif event.severity == AuditSeverity.WARNING:
                severity_item.setBackground(QColor(255, 255, 200))
            self.events_table.setItem(i, 2, severity_item)
            
            # User
            user_item = QTableWidgetItem(event.user_id)
            self.events_table.setItem(i, 3, user_item)
            
            # Description
            desc_item = QTableWidgetItem(event.description)
            self.events_table.setItem(i, 4, desc_item)
            
            # Event ID
            id_item = QTableWidgetItem(event.event_id)
            self.events_table.setItem(i, 5, id_item)
            
            # Store the event in the first item
            time_item.setData(Qt.ItemDataRole.UserRole, event)
        
        # Resize columns to content
        self.events_table.resizeColumnsToContents()
        
        # Clear the details
        self.details_text.clear()
    
    def event_selected(self, current, previous):
        """Handle event selection."""
        if current is None:
            self.details_text.clear()
            return
        
        # Get the event
        event = current.data(Qt.ItemDataRole.UserRole)
        if not event:
            row = current.row()
            event = self.events_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        
        if not event:
            self.details_text.clear()
            return
        
        # Format the event details
        details = f"<h2>Event Details</h2>"
        details += f"<p><b>Event ID:</b> {event.event_id}</p>"
        details += f"<p><b>Timestamp:</b> {datetime.datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')}</p>"
        details += f"<p><b>Type:</b> {event.event_type.value}</p>"
        details += f"<p><b>Severity:</b> {event.severity.value}</p>"
        details += f"<p><b>User ID:</b> {event.user_id}</p>"
        details += f"<p><b>Description:</b> {event.description}</p>"
        
        # System info
        details += f"<h3>System Information</h3>"
        details += f"<p><b>Hostname:</b> {event.system_info.get('hostname', 'Unknown')}</p>"
        details += f"<p><b>Process ID:</b> {event.system_info.get('process_id', 'Unknown')}</p>"
        details += f"<p><b>Thread ID:</b> {event.system_info.get('thread_id', 'Unknown')}</p>"
        
        # Metadata
        if event.metadata:
            details += f"<h3>Metadata</h3>"
            for key, value in event.metadata.items():
                details += f"<p><b>{key}:</b> {value}</p>"
        
        # Set the details text
        self.details_text.setHtml(details)
    
    def export_report(self):
        """Export an audit report."""
        # Ask for the file path
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Audit Report",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        # Get the filter values
        event_type = self.event_type_combo.currentData()
        severity = self.severity_combo.currentData()
        user_id = self.user_id_edit.text().strip() or None
        
        start_time = self.start_time_edit.dateTime().toSecsSinceEpoch()
        end_time = self.end_time_edit.dateTime().toSecsSinceEpoch()
        
        # Build the filters
        filters = {}
        if event_type:
            filters["event_type"] = event_type.value
        if severity:
            filters["severity"] = severity.value
        if user_id:
            filters["user_id"] = user_id
        
        # Generate the report
        report = self.audit_logger.generate_report(
            title="Cryptographic Audit Report",
            filters=filters
        )
        
        # Add time range to the report
        report["start_time"] = start_time
        report["end_time"] = end_time
        report["start_time_str"] = datetime.datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S")
        report["end_time_str"] = datetime.datetime.fromtimestamp(end_time).strftime("%Y-%m-%d %H:%M:%S")
        
        # Save the report
        try:
            with open(file_path, 'w') as f:
                import json
                json.dump(report, f, indent=2)
            
            QMessageBox.information(
                self,
                "Export Successful",
                f"Audit report exported to {file_path}"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Failed to export audit report: {str(e)}"
            )
    
    def view_alerts(self):
        """View security alerts."""
        # Filter for alert events
        self.event_type_combo.setCurrentText("alert")
        self.apply_filters()


class AlertRuleDialog(QDialog):
    """Dialog for managing alert rules."""
    
    def __init__(self, audit_logger: CryptoAuditLogger, parent=None):
        """Initialize the alert rule dialog."""
        super().__init__(parent)
        
        self.audit_logger = audit_logger
        
        self.setWindowTitle("Manage Alert Rules")
        self.setMinimumWidth(500)
        
        # Set up the UI
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        layout = QVBoxLayout(self)
        
        # Create tabs
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Current rules tab
        current_rules_tab = QWidget()
        current_rules_layout = QVBoxLayout(current_rules_tab)
        
        # Rules list
        self.rules_list = QListWidget()
        current_rules_layout.addWidget(self.rules_list)
        
        # Add predefined rules
        for rule in self.audit_logger.alert_rules:
            item = QListWidgetItem(f"{rule.name}: {rule.description}")
            item.setData(Qt.ItemDataRole.UserRole, rule)
            self.rules_list.addItem(item)
        
        # Buttons
        rules_buttons = QHBoxLayout()
        
        self.remove_rule_button = QPushButton("Remove Rule")
        self.remove_rule_button.clicked.connect(self.remove_rule)
        rules_buttons.addWidget(self.remove_rule_button)
        
        current_rules_layout.addLayout(rules_buttons)
        
        # Add the tab
        tabs.addTab(current_rules_tab, "Current Rules")
        
        # Add predefined rules tab
        predefined_rules_tab = QWidget()
        predefined_rules_layout = QVBoxLayout(predefined_rules_tab)
        
        # Predefined rules list
        self.predefined_rules_list = QListWidget()
        predefined_rules_layout.addWidget(self.predefined_rules_list)
        
        # Add predefined rules
        predefined_rules = [
            ("Failed Authentication", "Alerts on multiple failed authentication attempts", create_failed_authentication_rule),
            ("Sensitive Operations", "Alerts on sensitive cryptographic operations", create_sensitive_operation_rule),
            ("High Error Rate", "Alerts on high error rates", create_error_rate_rule)
        ]
        
        for name, desc, func in predefined_rules:
            item = QListWidgetItem(f"{name}: {desc}")
            item.setData(Qt.ItemDataRole.UserRole, func)
            self.predefined_rules_list.addItem(item)
        
        # Buttons
        predefined_buttons = QHBoxLayout()
        
        self.add_predefined_button = QPushButton("Add Selected Rule")
        self.add_predefined_button.clicked.connect(self.add_predefined_rule)
        predefined_buttons.addWidget(self.add_predefined_button)
        
        predefined_rules_layout.addLayout(predefined_buttons)
        
        # Add the tab
        tabs.addTab(predefined_rules_tab, "Predefined Rules")
        
        # Dialog buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
    
    def remove_rule(self):
        """Remove the selected rule."""
        # Get the selected rule
        current_item = self.rules_list.currentItem()
        if current_item is None:
            QMessageBox.warning(self, "No Rule Selected", "Please select a rule to remove.")
            return
        
        # Get the rule
        rule = current_item.data(Qt.ItemDataRole.UserRole)
        
        # Remove the rule
        if rule in self.audit_logger.alert_rules:
            self.audit_logger.alert_rules.remove(rule)
        
        # Remove the item from the list
        self.rules_list.takeItem(self.rules_list.row(current_item))
    
    def add_predefined_rule(self):
        """Add the selected predefined rule."""
        # Get the selected rule
        current_item = self.predefined_rules_list.currentItem()
        if current_item is None:
            QMessageBox.warning(self, "No Rule Selected", "Please select a rule to add.")
            return
        
        # Get the rule function
        rule_func = current_item.data(Qt.ItemDataRole.UserRole)
        
        # Create the rule
        rule = rule_func()
        
        # Add the rule to the logger
        self.audit_logger.add_alert_rule(rule)
        
        # Add the rule to the list
        item = QListWidgetItem(f"{rule.name}: {rule.description}")
        item.setData(Qt.ItemDataRole.UserRole, rule)
        self.rules_list.addItem(item)
        
        QMessageBox.information(self, "Rule Added", f"Added rule: {rule.name}")
