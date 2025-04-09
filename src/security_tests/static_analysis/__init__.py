"""
Static Analysis Package

This package provides tools for static analysis of the cryptographic system.
"""

from .analyzer import StaticAnalyzer
from .rules import SecurityRule, CryptographicRule, CodeQualityRule
from .report import SecurityReport, Vulnerability, VulnerabilitySeverity
