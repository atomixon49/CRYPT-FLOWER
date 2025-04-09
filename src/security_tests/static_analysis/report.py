"""
Security Report Module

This module provides classes for generating security reports.
"""

import enum
import json
import datetime
from typing import List, Dict, Any, Optional

class VulnerabilitySeverity(enum.Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class Vulnerability:
    """Represents a security vulnerability."""
    
    def __init__(self, 
                name: str, 
                description: str, 
                severity: VulnerabilitySeverity,
                file_path: str,
                line_number: int,
                code_snippet: str):
        """
        Initialize a vulnerability.
        
        Args:
            name: Vulnerability name
            description: Vulnerability description
            severity: Vulnerability severity
            file_path: Path of the file containing the vulnerability
            line_number: Line number where the vulnerability was found
            code_snippet: Code snippet containing the vulnerability
        """
        self.name = name
        self.description = description
        self.severity = severity
        self.file_path = file_path
        self.line_number = line_number
        self.code_snippet = code_snippet
        self.timestamp = datetime.datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the vulnerability to a dictionary.
        
        Returns:
            Dictionary representation of the vulnerability
        """
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "timestamp": self.timestamp.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Vulnerability':
        """
        Create a vulnerability from a dictionary.
        
        Args:
            data: Dictionary representation of the vulnerability
        
        Returns:
            Vulnerability object
        """
        severity = VulnerabilitySeverity(data["severity"])
        
        vulnerability = cls(
            name=data["name"],
            description=data["description"],
            severity=severity,
            file_path=data["file_path"],
            line_number=data["line_number"],
            code_snippet=data["code_snippet"]
        )
        
        if "timestamp" in data:
            vulnerability.timestamp = datetime.datetime.fromisoformat(data["timestamp"])
        
        return vulnerability

class SecurityReport:
    """Represents a security report."""
    
    def __init__(self):
        """Initialize a security report."""
        self.vulnerabilities = []
        self.timestamp = datetime.datetime.now()
    
    def add_vulnerability(self, vulnerability: Vulnerability):
        """
        Add a vulnerability to the report.
        
        Args:
            vulnerability: Vulnerability to add
        """
        self.vulnerabilities.append(vulnerability)
    
    def add_vulnerabilities(self, vulnerabilities: List[Vulnerability]):
        """
        Add multiple vulnerabilities to the report.
        
        Args:
            vulnerabilities: Vulnerabilities to add
        """
        self.vulnerabilities.extend(vulnerabilities)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the report to a dictionary.
        
        Returns:
            Dictionary representation of the report
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]
        }
    
    def to_json(self, indent: int = 2) -> str:
        """
        Convert the report to JSON.
        
        Args:
            indent: Indentation level for JSON formatting
        
        Returns:
            JSON representation of the report
        """
        return json.dumps(self.to_dict(), indent=indent)
    
    def save(self, file_path: str, indent: int = 2):
        """
        Save the report to a file.
        
        Args:
            file_path: Path to save the report to
            indent: Indentation level for JSON formatting
        """
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(self.to_json(indent))
    
    @classmethod
    def load(cls, file_path: str) -> 'SecurityReport':
        """
        Load a report from a file.
        
        Args:
            file_path: Path to load the report from
        
        Returns:
            Security report
        """
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        report = cls()
        report.timestamp = datetime.datetime.fromisoformat(data["timestamp"])
        
        for vuln_data in data["vulnerabilities"]:
            vulnerability = Vulnerability.from_dict(vuln_data)
            report.add_vulnerability(vulnerability)
        
        return report
    
    def get_vulnerabilities_by_severity(self, severity: VulnerabilitySeverity) -> List[Vulnerability]:
        """
        Get vulnerabilities with the specified severity.
        
        Args:
            severity: Severity to filter by
        
        Returns:
            List of vulnerabilities with the specified severity
        """
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_summary(self) -> Dict[str, int]:
        """
        Get a summary of the vulnerabilities by severity.
        
        Returns:
            Dictionary with counts for each severity level
        """
        summary = {
            "total": len(self.vulnerabilities),
            "critical": len(self.get_vulnerabilities_by_severity(VulnerabilitySeverity.CRITICAL)),
            "high": len(self.get_vulnerabilities_by_severity(VulnerabilitySeverity.HIGH)),
            "medium": len(self.get_vulnerabilities_by_severity(VulnerabilitySeverity.MEDIUM)),
            "low": len(self.get_vulnerabilities_by_severity(VulnerabilitySeverity.LOW))
        }
        
        return summary
