"""
Notification Manager

This module provides a manager for handling notifications in the GUI.
"""

import time
import enum
import uuid
from typing import Dict, List, Any, Optional, Callable
from PyQt6.QtCore import QObject, pyqtSignal

class NotificationType(enum.Enum):
    """Types of notifications."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    SECURITY = "security"
    SUCCESS = "success"

class Notification:
    """Represents a notification."""
    
    def __init__(self, 
                notification_type: NotificationType, 
                title: str, 
                message: str, 
                timeout: int = 5000,
                actions: Optional[List[Dict[str, Any]]] = None):
        """
        Initialize a notification.
        
        Args:
            notification_type: Type of notification
            title: Notification title
            message: Notification message
            timeout: Time in milliseconds before the notification disappears (0 for no timeout)
            actions: List of actions for the notification
        """
        self.id = str(uuid.uuid4())
        self.type = notification_type
        self.title = title
        self.message = message
        self.timeout = timeout
        self.actions = actions or []
        self.created_at = time.time()
        self.read = False
    
    def mark_as_read(self):
        """Mark the notification as read."""
        self.read = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the notification to a dictionary."""
        return {
            'id': self.id,
            'type': self.type.value,
            'title': self.title,
            'message': self.message,
            'timeout': self.timeout,
            'actions': self.actions,
            'created_at': self.created_at,
            'read': self.read
        }

class NotificationManager(QObject):
    """Manager for handling notifications."""
    
    # Signal emitted when a notification is added
    notification_added = pyqtSignal(Notification)
    
    # Signal emitted when a notification is removed
    notification_removed = pyqtSignal(str)  # notification_id
    
    # Signal emitted when all notifications are cleared
    notifications_cleared = pyqtSignal()
    
    def __init__(self):
        """Initialize the notification manager."""
        super().__init__()
        self.notifications = {}  # id -> Notification
    
    def add_notification(self, 
                        notification_type: NotificationType, 
                        title: str, 
                        message: str, 
                        timeout: int = 5000,
                        actions: Optional[List[Dict[str, Any]]] = None) -> str:
        """
        Add a new notification.
        
        Args:
            notification_type: Type of notification
            title: Notification title
            message: Notification message
            timeout: Time in milliseconds before the notification disappears (0 for no timeout)
            actions: List of actions for the notification
        
        Returns:
            Notification ID
        """
        notification = Notification(notification_type, title, message, timeout, actions)
        self.notifications[notification.id] = notification
        self.notification_added.emit(notification)
        return notification.id
    
    def remove_notification(self, notification_id: str) -> bool:
        """
        Remove a notification.
        
        Args:
            notification_id: ID of the notification to remove
        
        Returns:
            True if the notification was removed, False otherwise
        """
        if notification_id in self.notifications:
            del self.notifications[notification_id]
            self.notification_removed.emit(notification_id)
            return True
        return False
    
    def clear_notifications(self):
        """Clear all notifications."""
        self.notifications.clear()
        self.notifications_cleared.emit()
    
    def get_notification(self, notification_id: str) -> Optional[Notification]:
        """
        Get a notification by ID.
        
        Args:
            notification_id: ID of the notification to get
        
        Returns:
            The notification, or None if not found
        """
        return self.notifications.get(notification_id)
    
    def get_all_notifications(self) -> List[Notification]:
        """
        Get all notifications.
        
        Returns:
            List of all notifications
        """
        return list(self.notifications.values())
    
    def get_unread_notifications(self) -> List[Notification]:
        """
        Get all unread notifications.
        
        Returns:
            List of unread notifications
        """
        return [n for n in self.notifications.values() if not n.read]
    
    def mark_as_read(self, notification_id: str) -> bool:
        """
        Mark a notification as read.
        
        Args:
            notification_id: ID of the notification to mark as read
        
        Returns:
            True if the notification was marked as read, False otherwise
        """
        notification = self.get_notification(notification_id)
        if notification:
            notification.mark_as_read()
            return True
        return False
    
    def mark_all_as_read(self):
        """Mark all notifications as read."""
        for notification in self.notifications.values():
            notification.mark_as_read()
    
    # Convenience methods for adding different types of notifications
    
    def info(self, title: str, message: str, timeout: int = 5000) -> str:
        """Add an info notification."""
        return self.add_notification(NotificationType.INFO, title, message, timeout)
    
    def warning(self, title: str, message: str, timeout: int = 5000) -> str:
        """Add a warning notification."""
        return self.add_notification(NotificationType.WARNING, title, message, timeout)
    
    def error(self, title: str, message: str, timeout: int = 0) -> str:
        """Add an error notification."""
        return self.add_notification(NotificationType.ERROR, title, message, timeout)
    
    def security(self, title: str, message: str, timeout: int = 0) -> str:
        """Add a security notification."""
        return self.add_notification(NotificationType.SECURITY, title, message, timeout)
    
    def success(self, title: str, message: str, timeout: int = 5000) -> str:
        """Add a success notification."""
        return self.add_notification(NotificationType.SUCCESS, title, message, timeout)
