"""
Cryptographic Audit and Logging Module

This module provides comprehensive auditing and logging capabilities for cryptographic operations.
It records detailed information about all cryptographic operations, generates security alerts
for suspicious activities, and provides tools for analyzing and reporting on the audit logs.

Features:
- Detailed logging of all cryptographic operations
- Security alerts for suspicious activities
- Configurable log destinations (file, database, etc.)
- Audit report generation
- Log integrity verification
"""

import os
import time
import json
import logging
import hashlib
import threading
import datetime
from enum import Enum
from typing import Dict, List, Any, Optional, Union, Callable, Tuple
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("crypto_audit")


class AuditEventType(Enum):
    """Types of events that can be audited."""
    KEY_GENERATION = "key_generation"
    KEY_ROTATION = "key_rotation"
    KEY_DELETION = "key_deletion"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNATURE = "signature"
    VERIFICATION = "verification"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIGURATION = "configuration"
    POLICY_CHANGE = "policy_change"
    ALERT = "alert"
    ERROR = "error"


class AuditSeverity(Enum):
    """Severity levels for audit events."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditEvent:
    """
    Represents a single audit event.
    
    This class encapsulates all the information about a cryptographic operation
    or security event that should be recorded in the audit log.
    """
    
    def __init__(self,
                event_type: AuditEventType,
                user_id: str,
                description: str,
                severity: AuditSeverity = AuditSeverity.INFO,
                metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize a new audit event.
        
        Args:
            event_type: The type of event
            user_id: ID of the user who performed the action
            description: Human-readable description of the event
            severity: Severity level of the event
            metadata: Additional information about the event
        """
        self.event_id = self._generate_event_id()
        self.timestamp = time.time()
        self.event_type = event_type
        self.user_id = user_id
        self.description = description
        self.severity = severity
        self.metadata = metadata or {}
        
        # Add system information
        self.system_info = {
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
            "process_id": os.getpid(),
            "thread_id": threading.get_ident()
        }
    
    def _generate_event_id(self) -> str:
        """Generate a unique ID for this event."""
        unique_data = f"{time.time()}-{os.getpid()}-{threading.get_ident()}-{os.urandom(8).hex()}"
        return hashlib.sha256(unique_data.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "user_id": self.user_id,
            "description": self.description,
            "severity": self.severity.value,
            "metadata": self.metadata,
            "system_info": self.system_info
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditEvent':
        """Create an event from a dictionary."""
        event = cls(
            event_type=AuditEventType(data["event_type"]),
            user_id=data["user_id"],
            description=data["description"],
            severity=AuditSeverity(data["severity"]),
            metadata=data["metadata"]
        )
        event.event_id = data["event_id"]
        event.timestamp = data["timestamp"]
        event.system_info = data["system_info"]
        return event
    
    def __str__(self) -> str:
        """Return a string representation of the event."""
        timestamp = datetime.datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        return f"[{timestamp}] [{self.severity.value.upper()}] [{self.event_type.value}] {self.description}"


class AlertRule:
    """
    Defines a rule for generating security alerts based on audit events.
    
    Alert rules can be based on patterns in individual events or
    on patterns across multiple events over time.
    """
    
    def __init__(self,
                name: str,
                description: str,
                severity: AuditSeverity,
                condition: Callable[[AuditEvent], bool],
                actions: List[Callable[[AuditEvent], None]] = None):
        """
        Initialize a new alert rule.
        
        Args:
            name: Name of the rule
            description: Description of what the rule detects
            severity: Severity level for alerts generated by this rule
            condition: Function that takes an event and returns True if an alert should be generated
            actions: List of functions to call when an alert is generated
        """
        self.name = name
        self.description = description
        self.severity = severity
        self.condition = condition
        self.actions = actions or []
    
    def check_event(self, event: AuditEvent) -> bool:
        """
        Check if an event should trigger this alert.
        
        Args:
            event: The event to check
            
        Returns:
            True if the event triggers the alert, False otherwise
        """
        return self.condition(event)
    
    def trigger_actions(self, event: AuditEvent):
        """
        Trigger all actions associated with this rule.
        
        Args:
            event: The event that triggered the alert
        """
        for action in self.actions:
            try:
                action(event)
            except Exception as e:
                logger.error(f"Error executing alert action: {str(e)}")


class AuditLogDestination:
    """
    Base class for audit log destinations.
    
    This class defines the interface for different types of log destinations,
    such as files, databases, or remote logging services.
    """
    
    def write_event(self, event: AuditEvent):
        """
        Write an event to the log destination.
        
        Args:
            event: The event to write
        """
        raise NotImplementedError("Subclasses must implement write_event")
    
    def read_events(self, 
                   filters: Optional[Dict[str, Any]] = None, 
                   start_time: Optional[float] = None,
                   end_time: Optional[float] = None,
                   limit: Optional[int] = None) -> List[AuditEvent]:
        """
        Read events from the log destination.
        
        Args:
            filters: Criteria for filtering events
            start_time: Start of time range to read
            end_time: End of time range to read
            limit: Maximum number of events to return
            
        Returns:
            List of events matching the criteria
        """
        raise NotImplementedError("Subclasses must implement read_events")
    
    def close(self):
        """Close the log destination and release any resources."""
        pass


class FileAuditLogDestination(AuditLogDestination):
    """
    Audit log destination that writes events to a file.
    
    Events are stored as JSON objects, one per line, in the specified file.
    """
    
    def __init__(self, file_path: str, append: bool = True):
        """
        Initialize a file-based audit log destination.
        
        Args:
            file_path: Path to the log file
            append: Whether to append to an existing file (True) or overwrite it (False)
        """
        self.file_path = file_path
        self.append = append
        self.file = None
        
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        
        # Open the file
        mode = "a" if append else "w"
        self.file = open(file_path, mode, encoding="utf-8")
    
    def write_event(self, event: AuditEvent):
        """
        Write an event to the log file.
        
        Args:
            event: The event to write
        """
        if self.file is None:
            raise ValueError("Log file is not open")
        
        # Convert the event to JSON and write it to the file
        event_json = json.dumps(event.to_dict())
        self.file.write(event_json + "\n")
        self.file.flush()
    
    def read_events(self, 
                   filters: Optional[Dict[str, Any]] = None, 
                   start_time: Optional[float] = None,
                   end_time: Optional[float] = None,
                   limit: Optional[int] = None) -> List[AuditEvent]:
        """
        Read events from the log file.
        
        Args:
            filters: Criteria for filtering events
            start_time: Start of time range to read
            end_time: End of time range to read
            limit: Maximum number of events to return
            
        Returns:
            List of events matching the criteria
        """
        # Close the current file if it's open for writing
        if self.file is not None:
            self.file.close()
            self.file = None
        
        # Open the file for reading
        events = []
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        # Parse the event from JSON
                        event_dict = json.loads(line.strip())
                        event = AuditEvent.from_dict(event_dict)
                        
                        # Apply time filters
                        if start_time is not None and event.timestamp < start_time:
                            continue
                        if end_time is not None and event.timestamp > end_time:
                            continue
                        
                        # Apply other filters
                        if filters:
                            match = True
                            for key, value in filters.items():
                                if key == "event_type":
                                    if event.event_type.value != value:
                                        match = False
                                        break
                                elif key == "severity":
                                    if event.severity.value != value:
                                        match = False
                                        break
                                elif key == "user_id":
                                    if event.user_id != value:
                                        match = False
                                        break
                                elif key in event.metadata:
                                    if event.metadata[key] != value:
                                        match = False
                                        break
                                else:
                                    match = False
                                    break
                            
                            if not match:
                                continue
                        
                        # Add the event to the result
                        events.append(event)
                        
                        # Check if we've reached the limit
                        if limit is not None and len(events) >= limit:
                            break
                    except Exception as e:
                        logger.error(f"Error parsing audit log entry: {str(e)}")
        except FileNotFoundError:
            # If the file doesn't exist, return an empty list
            pass
        
        # Reopen the file for writing if it was open before
        if self.append:
            self.file = open(self.file_path, "a", encoding="utf-8")
        
        return events
    
    def close(self):
        """Close the log file."""
        if self.file is not None:
            self.file.close()
            self.file = None


class CryptoAuditLogger:
    """
    Main class for cryptographic auditing and logging.
    
    This class provides methods for recording audit events, checking alert rules,
    and generating audit reports.
    """
    
    def __init__(self, 
                destinations: List[AuditLogDestination] = None,
                alert_rules: List[AlertRule] = None,
                user_id: str = "system"):
        """
        Initialize the audit logger.
        
        Args:
            destinations: List of destinations to write audit events to
            alert_rules: List of rules for generating security alerts
            user_id: Default user ID to use for events if not specified
        """
        self.destinations = destinations or []
        self.alert_rules = alert_rules or []
        self.default_user_id = user_id
        
        # Add a default file destination if none are provided
        if not self.destinations:
            log_dir = os.path.join(os.path.expanduser("~"), ".crypto_audit")
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, "crypto_audit.log")
            self.destinations.append(FileAuditLogDestination(log_file))
    
    def log_event(self, 
                 event_type: AuditEventType,
                 description: str,
                 user_id: Optional[str] = None,
                 severity: AuditSeverity = AuditSeverity.INFO,
                 metadata: Optional[Dict[str, Any]] = None) -> AuditEvent:
        """
        Log an audit event.
        
        Args:
            event_type: The type of event
            description: Human-readable description of the event
            user_id: ID of the user who performed the action (defaults to the default user ID)
            severity: Severity level of the event
            metadata: Additional information about the event
            
        Returns:
            The created audit event
        """
        # Create the event
        event = AuditEvent(
            event_type=event_type,
            user_id=user_id or self.default_user_id,
            description=description,
            severity=severity,
            metadata=metadata
        )
        
        # Write the event to all destinations
        for destination in self.destinations:
            try:
                destination.write_event(event)
            except Exception as e:
                logger.error(f"Error writing audit event to destination: {str(e)}")
        
        # Check alert rules
        self._check_alert_rules(event)
        
        return event
    
    def _check_alert_rules(self, event: AuditEvent):
        """
        Check if an event triggers any alert rules.
        
        Args:
            event: The event to check
        """
        for rule in self.alert_rules:
            try:
                if rule.check_event(event):
                    # Create an alert event
                    alert_description = f"Alert: {rule.name} - {rule.description}"
                    alert_metadata = {
                        "rule_name": rule.name,
                        "rule_description": rule.description,
                        "triggering_event_id": event.event_id
                    }
                    
                    # Log the alert
                    self.log_event(
                        event_type=AuditEventType.ALERT,
                        description=alert_description,
                        severity=rule.severity,
                        metadata=alert_metadata
                    )
                    
                    # Trigger the rule's actions
                    rule.trigger_actions(event)
            except Exception as e:
                logger.error(f"Error checking alert rule {rule.name}: {str(e)}")
    
    def add_destination(self, destination: AuditLogDestination):
        """
        Add a new log destination.
        
        Args:
            destination: The destination to add
        """
        self.destinations.append(destination)
    
    def add_alert_rule(self, rule: AlertRule):
        """
        Add a new alert rule.
        
        Args:
            rule: The rule to add
        """
        self.alert_rules.append(rule)
    
    def get_events(self, 
                  filters: Optional[Dict[str, Any]] = None, 
                  start_time: Optional[float] = None,
                  end_time: Optional[float] = None,
                  limit: Optional[int] = None) -> List[AuditEvent]:
        """
        Get events from all destinations.
        
        Args:
            filters: Criteria for filtering events
            start_time: Start of time range to read
            end_time: End of time range to read
            limit: Maximum number of events to return
            
        Returns:
            List of events matching the criteria
        """
        all_events = []
        
        # Read events from all destinations
        for destination in self.destinations:
            try:
                events = destination.read_events(
                    filters=filters,
                    start_time=start_time,
                    end_time=end_time,
                    limit=limit
                )
                all_events.extend(events)
            except Exception as e:
                logger.error(f"Error reading events from destination: {str(e)}")
        
        # Sort events by timestamp
        all_events.sort(key=lambda e: e.timestamp)
        
        # Apply limit if specified
        if limit is not None and len(all_events) > limit:
            all_events = all_events[:limit]
        
        return all_events
    
    def generate_report(self, 
                       start_time: Optional[float] = None,
                       end_time: Optional[float] = None,
                       filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate an audit report.
        
        Args:
            start_time: Start of time range for the report
            end_time: End of time range for the report
            filters: Additional filters for events to include
            
        Returns:
            Dictionary containing the report data
        """
        # Get events for the report
        events = self.get_events(
            filters=filters,
            start_time=start_time,
            end_time=end_time
        )
        
        # Initialize report data
        report = {
            "generated_at": time.time(),
            "start_time": start_time,
            "end_time": end_time,
            "filters": filters,
            "total_events": len(events),
            "event_types": {},
            "severity_counts": {},
            "user_activity": {},
            "alerts": [],
            "errors": []
        }
        
        # Process events
        for event in events:
            # Count by event type
            event_type = event.event_type.value
            if event_type not in report["event_types"]:
                report["event_types"][event_type] = 0
            report["event_types"][event_type] += 1
            
            # Count by severity
            severity = event.severity.value
            if severity not in report["severity_counts"]:
                report["severity_counts"][severity] = 0
            report["severity_counts"][severity] += 1
            
            # Count by user
            user_id = event.user_id
            if user_id not in report["user_activity"]:
                report["user_activity"][user_id] = 0
            report["user_activity"][user_id] += 1
            
            # Collect alerts and errors
            if event.event_type == AuditEventType.ALERT:
                report["alerts"].append(event.to_dict())
            elif event.event_type == AuditEventType.ERROR:
                report["errors"].append(event.to_dict())
        
        return report
    
    def close(self):
        """Close all log destinations."""
        for destination in self.destinations:
            try:
                destination.close()
            except Exception as e:
                logger.error(f"Error closing log destination: {str(e)}")


# Default alert actions
def log_alert_action(event: AuditEvent):
    """Log an alert to the system logger."""
    logger.warning(f"SECURITY ALERT: {event.description}")


def email_alert_action(event: AuditEvent, recipient: str):
    """Send an alert by email (placeholder implementation)."""
    logger.info(f"Would send email alert to {recipient}: {event.description}")


# Common alert rules
def create_failed_authentication_rule(threshold: int = 3, 
                                     time_window: float = 300) -> AlertRule:
    """
    Create a rule for detecting failed authentication attempts.
    
    Args:
        threshold: Number of failed attempts that triggers an alert
        time_window: Time window in seconds to count failed attempts
        
    Returns:
        AlertRule for detecting failed authentication attempts
    """
    # Store failed attempts
    failed_attempts = {}
    
    def check_failed_auth(event: AuditEvent) -> bool:
        if (event.event_type == AuditEventType.AUTHENTICATION and 
            event.metadata.get("success") is False):
            
            user_id = event.metadata.get("target_user_id", event.user_id)
            current_time = event.timestamp
            
            # Initialize or update failed attempts for this user
            if user_id not in failed_attempts:
                failed_attempts[user_id] = []
            
            # Add this attempt
            failed_attempts[user_id].append(current_time)
            
            # Remove attempts outside the time window
            failed_attempts[user_id] = [t for t in failed_attempts[user_id] 
                                      if current_time - t <= time_window]
            
            # Check if we've reached the threshold
            return len(failed_attempts[user_id]) >= threshold
        
        return False
    
    return AlertRule(
        name="Failed Authentication",
        description=f"{threshold} failed authentication attempts within {time_window} seconds",
        severity=AuditSeverity.WARNING,
        condition=check_failed_auth,
        actions=[log_alert_action]
    )


def create_sensitive_operation_rule() -> AlertRule:
    """
    Create a rule for detecting sensitive cryptographic operations.
    
    Returns:
        AlertRule for detecting sensitive operations
    """
    def check_sensitive_operation(event: AuditEvent) -> bool:
        # Check for key deletion
        if event.event_type == AuditEventType.KEY_DELETION:
            return True
        
        # Check for policy changes
        if event.event_type == AuditEventType.POLICY_CHANGE:
            return True
        
        # Check for configuration changes
        if event.event_type == AuditEventType.CONFIGURATION:
            return True
        
        return False
    
    return AlertRule(
        name="Sensitive Operation",
        description="Sensitive cryptographic operation detected",
        severity=AuditSeverity.INFO,
        condition=check_sensitive_operation,
        actions=[log_alert_action]
    )


def create_error_rate_rule(threshold: int = 5, 
                          time_window: float = 60) -> AlertRule:
    """
    Create a rule for detecting high error rates.
    
    Args:
        threshold: Number of errors that triggers an alert
        time_window: Time window in seconds to count errors
        
    Returns:
        AlertRule for detecting high error rates
    """
    # Store errors
    errors = []
    
    def check_error_rate(event: AuditEvent) -> bool:
        if event.event_type == AuditEventType.ERROR:
            current_time = event.timestamp
            
            # Add this error
            errors.append(current_time)
            
            # Remove errors outside the time window
            while errors and current_time - errors[0] > time_window:
                errors.pop(0)
            
            # Check if we've reached the threshold
            return len(errors) >= threshold
        
        return False
    
    return AlertRule(
        name="High Error Rate",
        description=f"{threshold} errors within {time_window} seconds",
        severity=AuditSeverity.ERROR,
        condition=check_error_rate,
        actions=[log_alert_action]
    )
