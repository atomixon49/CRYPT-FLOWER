"""
Security Rules Module

This module provides classes for defining security rules for static analysis.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from .report import VulnerabilitySeverity

class SecurityRule(ABC):
    """Base class for security rules."""
    
    def __init__(self, name: str, description: str, severity: VulnerabilitySeverity):
        """
        Initialize a security rule.
        
        Args:
            name: Rule name
            description: Rule description
            severity: Rule severity
        """
        self.name = name
        self.description = description
        self.severity = severity
    
    @abstractmethod
    def check(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Check if the rule is violated in the given content.
        
        Args:
            content: Content to check
            file_path: Path of the file being checked
        
        Returns:
            List of violations found
        """
        pass

class CryptographicRule(SecurityRule):
    """Rule for detecting cryptographic vulnerabilities."""
    
    def __init__(self, name: str, description: str, pattern: str, severity: VulnerabilitySeverity):
        """
        Initialize a cryptographic rule.
        
        Args:
            name: Rule name
            description: Rule description
            pattern: Regex pattern to match
            severity: Rule severity
        """
        super().__init__(name, description, severity)
        self.pattern = pattern
    
    def check(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Check if the rule is violated in the given content.
        
        Args:
            content: Content to check
            file_path: Path of the file being checked
        
        Returns:
            List of violations found
        """
        import re
        
        violations = []
        
        # Find all matches
        matches = re.finditer(self.pattern, content)
        
        for match in matches:
            # Get line number
            line_number = content[:match.start()].count("\n") + 1
            
            # Create violation
            violation = {
                "name": self.name,
                "description": self.description,
                "severity": self.severity,
                "file_path": file_path,
                "line_number": line_number,
                "code_snippet": match.group(0)
            }
            
            violations.append(violation)
        
        return violations

class CodeQualityRule(SecurityRule):
    """Rule for detecting code quality issues."""
    
    def __init__(self, name: str, description: str, pattern: str, severity: VulnerabilitySeverity):
        """
        Initialize a code quality rule.
        
        Args:
            name: Rule name
            description: Rule description
            pattern: Regex pattern to match
            severity: Rule severity
        """
        super().__init__(name, description, severity)
        self.pattern = pattern
    
    def check(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Check if the rule is violated in the given content.
        
        Args:
            content: Content to check
            file_path: Path of the file being checked
        
        Returns:
            List of violations found
        """
        import re
        
        violations = []
        
        # Find all matches
        matches = re.finditer(self.pattern, content)
        
        for match in matches:
            # Get line number
            line_number = content[:match.start()].count("\n") + 1
            
            # Create violation
            violation = {
                "name": self.name,
                "description": self.description,
                "severity": self.severity,
                "file_path": file_path,
                "line_number": line_number,
                "code_snippet": match.group(0)
            }
            
            violations.append(violation)
        
        return violations
