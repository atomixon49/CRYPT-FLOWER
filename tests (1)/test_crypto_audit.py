"""
Tests for the cryptographic audit and logging module.
"""

import unittest
import os
import tempfile
import shutil
import time
import json
from pathlib import Path

from src.core.crypto_audit import (
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


class TestAuditEvent(unittest.TestCase):
    """Test cases for the AuditEvent class."""
    
    def test_create_event(self):
        """Test creating an audit event."""
        event = AuditEvent(
            event_type=AuditEventType.ENCRYPTION,
            user_id="test_user",
            description="Test encryption event",
            severity=AuditSeverity.INFO,
            metadata={"file": "test.txt", "algorithm": "AES"}
        )
        
        # Verify the event
        self.assertEqual(event.event_type, AuditEventType.ENCRYPTION)
        self.assertEqual(event.user_id, "test_user")
        self.assertEqual(event.description, "Test encryption event")
        self.assertEqual(event.severity, AuditSeverity.INFO)
        self.assertEqual(event.metadata["file"], "test.txt")
        self.assertEqual(event.metadata["algorithm"], "AES")
        
        # Verify system info
        self.assertIn("hostname", event.system_info)
        self.assertIn("process_id", event.system_info)
        self.assertIn("thread_id", event.system_info)
    
    def test_event_serialization(self):
        """Test serializing and deserializing an audit event."""
        # Create an event
        original_event = AuditEvent(
            event_type=AuditEventType.DECRYPTION,
            user_id="test_user",
            description="Test decryption event",
            severity=AuditSeverity.WARNING,
            metadata={"file": "secret.txt", "algorithm": "RSA"}
        )
        
        # Serialize to dictionary
        event_dict = original_event.to_dict()
        
        # Deserialize from dictionary
        restored_event = AuditEvent.from_dict(event_dict)
        
        # Verify the restored event
        self.assertEqual(restored_event.event_id, original_event.event_id)
        self.assertEqual(restored_event.timestamp, original_event.timestamp)
        self.assertEqual(restored_event.event_type, original_event.event_type)
        self.assertEqual(restored_event.user_id, original_event.user_id)
        self.assertEqual(restored_event.description, original_event.description)
        self.assertEqual(restored_event.severity, original_event.severity)
        self.assertEqual(restored_event.metadata, original_event.metadata)
        self.assertEqual(restored_event.system_info, original_event.system_info)
    
    def test_event_string_representation(self):
        """Test the string representation of an audit event."""
        event = AuditEvent(
            event_type=AuditEventType.SIGNATURE,
            user_id="test_user",
            description="Test signature event",
            severity=AuditSeverity.ERROR
        )
        
        # Get the string representation
        event_str = str(event)
        
        # Verify the string
        self.assertIn("ERROR", event_str)
        self.assertIn("signature", event_str)
        self.assertIn("Test signature event", event_str)


class TestAlertRule(unittest.TestCase):
    """Test cases for the AlertRule class."""
    
    def test_alert_rule_condition(self):
        """Test alert rule condition evaluation."""
        # Create a simple rule that alerts on critical events
        def check_critical(event):
            return event.severity == AuditSeverity.CRITICAL
        
        rule = AlertRule(
            name="Critical Event",
            description="Alert on critical events",
            severity=AuditSeverity.ERROR,
            condition=check_critical
        )
        
        # Create events with different severities
        critical_event = AuditEvent(
            event_type=AuditEventType.ERROR,
            user_id="test_user",
            description="Critical error",
            severity=AuditSeverity.CRITICAL
        )
        
        info_event = AuditEvent(
            event_type=AuditEventType.ENCRYPTION,
            user_id="test_user",
            description="Normal encryption",
            severity=AuditSeverity.INFO
        )
        
        # Check the rule
        self.assertTrue(rule.check_event(critical_event))
        self.assertFalse(rule.check_event(info_event))
    
    def test_alert_rule_actions(self):
        """Test alert rule actions."""
        # Create a test action that records the event
        triggered_events = []
        
        def test_action(event):
            triggered_events.append(event)
        
        # Create a rule with the test action
        rule = AlertRule(
            name="Test Rule",
            description="Rule for testing actions",
            severity=AuditSeverity.WARNING,
            condition=lambda e: True,  # Always trigger
            actions=[test_action]
        )
        
        # Create a test event
        event = AuditEvent(
            event_type=AuditEventType.AUTHENTICATION,
            user_id="test_user",
            description="Test authentication",
            severity=AuditSeverity.INFO
        )
        
        # Trigger the rule's actions
        rule.trigger_actions(event)
        
        # Verify the action was called
        self.assertEqual(len(triggered_events), 1)
        self.assertEqual(triggered_events[0], event)


class TestFileAuditLogDestination(unittest.TestCase):
    """Test cases for the FileAuditLogDestination class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, "audit.log")
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        shutil.rmtree(self.test_dir)
    
    def test_write_and_read_events(self):
        """Test writing events to a file and reading them back."""
        # Create a file destination
        destination = FileAuditLogDestination(self.log_file)
        
        # Create some test events
        event1 = AuditEvent(
            event_type=AuditEventType.ENCRYPTION,
            user_id="user1",
            description="Encryption event 1",
            metadata={"file": "file1.txt"}
        )
        
        event2 = AuditEvent(
            event_type=AuditEventType.DECRYPTION,
            user_id="user2",
            description="Decryption event 2",
            severity=AuditSeverity.WARNING,
            metadata={"file": "file2.txt"}
        )
        
        # Write the events
        destination.write_event(event1)
        destination.write_event(event2)
        
        # Read the events back
        events = destination.read_events()
        
        # Verify the events
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_id, event1.event_id)
        self.assertEqual(events[0].event_type, event1.event_type)
        self.assertEqual(events[0].user_id, event1.user_id)
        self.assertEqual(events[0].description, event1.description)
        self.assertEqual(events[0].metadata, event1.metadata)
        
        self.assertEqual(events[1].event_id, event2.event_id)
        self.assertEqual(events[1].event_type, event2.event_type)
        self.assertEqual(events[1].user_id, event2.user_id)
        self.assertEqual(events[1].description, event2.description)
        self.assertEqual(events[1].severity, event2.severity)
        self.assertEqual(events[1].metadata, event2.metadata)
        
        # Close the destination
        destination.close()
    
    def test_filtering_events(self):
        """Test filtering events when reading from a file."""
        # Create a file destination
        destination = FileAuditLogDestination(self.log_file)
        
        # Create events with different types and users
        for i in range(10):
            event_type = AuditEventType.ENCRYPTION if i % 2 == 0 else AuditEventType.DECRYPTION
            user_id = "user1" if i % 3 == 0 else "user2"
            
            event = AuditEvent(
                event_type=event_type,
                user_id=user_id,
                description=f"Event {i}",
                metadata={"index": i}
            )
            
            destination.write_event(event)
        
        # Read with type filter
        encryption_events = destination.read_events(
            filters={"event_type": "encryption"}
        )
        self.assertEqual(len(encryption_events), 5)
        for event in encryption_events:
            self.assertEqual(event.event_type, AuditEventType.ENCRYPTION)
        
        # Read with user filter
        user1_events = destination.read_events(
            filters={"user_id": "user1"}
        )
        self.assertEqual(len(user1_events), 4)
        for event in user1_events:
            self.assertEqual(event.user_id, "user1")
        
        # Read with combined filters
        combined_events = destination.read_events(
            filters={"event_type": "encryption", "user_id": "user1"}
        )
        self.assertEqual(len(combined_events), 2)
        for event in combined_events:
            self.assertEqual(event.event_type, AuditEventType.ENCRYPTION)
            self.assertEqual(event.user_id, "user1")
        
        # Read with limit
        limited_events = destination.read_events(limit=3)
        self.assertEqual(len(limited_events), 3)
        
        # Close the destination
        destination.close()


class TestCryptoAuditLogger(unittest.TestCase):
    """Test cases for the CryptoAuditLogger class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, "audit.log")
        
        # Create a file destination
        self.destination = FileAuditLogDestination(self.log_file)
        
        # Create a logger with the test destination
        self.logger = CryptoAuditLogger(
            destinations=[self.destination],
            user_id="test_system"
        )
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Close the logger
        self.logger.close()
        
        # Remove the temporary directory and its contents
        shutil.rmtree(self.test_dir)
    
    def test_log_event(self):
        """Test logging an event."""
        # Log an event
        event = self.logger.log_event(
            event_type=AuditEventType.ENCRYPTION,
            description="Test encryption",
            metadata={"file": "test.txt"}
        )
        
        # Verify the event
        self.assertEqual(event.event_type, AuditEventType.ENCRYPTION)
        self.assertEqual(event.user_id, "test_system")
        self.assertEqual(event.description, "Test encryption")
        self.assertEqual(event.metadata["file"], "test.txt")
        
        # Read the event from the log
        events = self.logger.get_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_id, event.event_id)
    
    def test_alert_rules(self):
        """Test alert rules in the logger."""
        # Create a test rule that alerts on decryption events
        triggered_alerts = []
        
        def test_action(event):
            triggered_alerts.append(event)
        
        rule = AlertRule(
            name="Decryption Alert",
            description="Alert on decryption events",
            severity=AuditSeverity.WARNING,
            condition=lambda e: e.event_type == AuditEventType.DECRYPTION,
            actions=[test_action]
        )
        
        # Add the rule to the logger
        self.logger.add_alert_rule(rule)
        
        # Log events of different types
        self.logger.log_event(
            event_type=AuditEventType.ENCRYPTION,
            description="Test encryption"
        )
        
        self.logger.log_event(
            event_type=AuditEventType.DECRYPTION,
            description="Test decryption"
        )
        
        # Verify that only the decryption event triggered the alert
        self.assertEqual(len(triggered_alerts), 1)
        
        # Verify that an alert event was logged
        events = self.logger.get_events(
            filters={"event_type": "alert"}
        )
        self.assertEqual(len(events), 1)
        self.assertIn("Decryption Alert", events[0].description)
    
    def test_generate_report(self):
        """Test generating an audit report."""
        # Log various events
        for i in range(10):
            event_type = AuditEventType.ENCRYPTION if i % 2 == 0 else AuditEventType.DECRYPTION
            user_id = "user1" if i % 3 == 0 else "user2"
            severity = AuditSeverity.INFO if i % 4 != 0 else AuditSeverity.WARNING
            
            self.logger.log_event(
                event_type=event_type,
                description=f"Event {i}",
                user_id=user_id,
                severity=severity
            )
        
        # Generate a report
        report = self.logger.generate_report()
        
        # Verify the report
        self.assertEqual(report["total_events"], 10)
        self.assertEqual(report["event_types"]["encryption"], 5)
        self.assertEqual(report["event_types"]["decryption"], 5)
        self.assertEqual(report["severity_counts"]["info"], 7)
        self.assertEqual(report["severity_counts"]["warning"], 3)
        self.assertEqual(report["user_activity"]["user1"], 4)
        self.assertEqual(report["user_activity"]["user2"], 6)


class TestAlertRules(unittest.TestCase):
    """Test cases for the predefined alert rules."""
    
    def test_failed_authentication_rule(self):
        """Test the failed authentication alert rule."""
        # Create the rule with a threshold of 3 attempts
        rule = create_failed_authentication_rule(threshold=3, time_window=10)
        
        # Create failed authentication events
        events = []
        base_time = time.time()
        
        for i in range(4):
            event = AuditEvent(
                event_type=AuditEventType.AUTHENTICATION,
                user_id="attacker",
                description=f"Failed login attempt {i}",
                severity=AuditSeverity.WARNING,
                metadata={"success": False, "target_user_id": "victim"}
            )
            # Override the timestamp for testing
            event.timestamp = base_time + i
            events.append(event)
        
        # First two attempts should not trigger the alert
        self.assertFalse(rule.check_event(events[0]))
        self.assertFalse(rule.check_event(events[1]))
        
        # Third attempt should trigger the alert
        self.assertTrue(rule.check_event(events[2]))
        
        # Fourth attempt should also trigger the alert
        self.assertTrue(rule.check_event(events[3]))
    
    def test_sensitive_operation_rule(self):
        """Test the sensitive operation alert rule."""
        # Create the rule
        rule = create_sensitive_operation_rule()
        
        # Create events of different types
        key_deletion_event = AuditEvent(
            event_type=AuditEventType.KEY_DELETION,
            user_id="admin",
            description="Deleted master key",
            severity=AuditSeverity.WARNING
        )
        
        policy_change_event = AuditEvent(
            event_type=AuditEventType.POLICY_CHANGE,
            user_id="admin",
            description="Changed security policy",
            severity=AuditSeverity.WARNING
        )
        
        encryption_event = AuditEvent(
            event_type=AuditEventType.ENCRYPTION,
            user_id="user",
            description="Encrypted file",
            severity=AuditSeverity.INFO
        )
        
        # Check the rule
        self.assertTrue(rule.check_event(key_deletion_event))
        self.assertTrue(rule.check_event(policy_change_event))
        self.assertFalse(rule.check_event(encryption_event))
    
    def test_error_rate_rule(self):
        """Test the error rate alert rule."""
        # Create the rule with a threshold of 3 errors in 10 seconds
        rule = create_error_rate_rule(threshold=3, time_window=10)
        
        # Create error events
        events = []
        base_time = time.time()
        
        for i in range(4):
            event = AuditEvent(
                event_type=AuditEventType.ERROR,
                user_id="system",
                description=f"Error {i}",
                severity=AuditSeverity.ERROR
            )
            # Override the timestamp for testing
            event.timestamp = base_time + i
            events.append(event)
        
        # First two errors should not trigger the alert
        self.assertFalse(rule.check_event(events[0]))
        self.assertFalse(rule.check_event(events[1]))
        
        # Third error should trigger the alert
        self.assertTrue(rule.check_event(events[2]))
        
        # Fourth error should also trigger the alert
        self.assertTrue(rule.check_event(events[3]))


if __name__ == "__main__":
    unittest.main()
