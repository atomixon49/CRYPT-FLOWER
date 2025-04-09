"""
Static Analyzer Module

This module provides a static analyzer for detecting security vulnerabilities in the code.
"""

import os
import re
import ast
import json
import logging
import subprocess
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path

from .rules import SecurityRule, CryptographicRule, CodeQualityRule
from .report import SecurityReport, Vulnerability, VulnerabilitySeverity

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("static_analyzer")

class StaticAnalyzer:
    """
    Static analyzer for detecting security vulnerabilities in the code.
    
    This class provides methods for:
    - Running static analysis tools
    - Checking for common security vulnerabilities
    - Generating security reports
    """
    
    def __init__(self, project_root: str = None):
        """
        Initialize the static analyzer.
        
        Args:
            project_root: Root directory of the project to analyze
        """
        self.project_root = project_root or os.getcwd()
        self.rules = []
        self.load_default_rules()
    
    def load_default_rules(self):
        """Load the default security rules."""
        # Cryptographic rules
        self.rules.extend([
            CryptographicRule(
                name="weak_key_size",
                description="Weak cryptographic key size",
                pattern=r"key_size\s*=\s*(?:512|1024|128)",
                severity=VulnerabilitySeverity.HIGH
            ),
            CryptographicRule(
                name="insecure_random",
                description="Use of insecure random number generator",
                pattern=r"random\.|randint|randrange",
                severity=VulnerabilitySeverity.HIGH
            ),
            CryptographicRule(
                name="weak_hash_algorithm",
                description="Use of weak hash algorithm",
                pattern=r"md5|sha1",
                severity=VulnerabilitySeverity.HIGH
            ),
            CryptographicRule(
                name="hardcoded_secret",
                description="Hardcoded secret or key",
                pattern=r"key\s*=\s*['\"][0-9a-fA-F]{16,}['\"]",
                severity=VulnerabilitySeverity.CRITICAL
            ),
            CryptographicRule(
                name="ecb_mode",
                description="Use of ECB mode for encryption",
                pattern=r"ECB|mode=ECB|mode=['\"]ECB['\"]",
                severity=VulnerabilitySeverity.HIGH
            ),
        ])
        
        # Code quality rules
        self.rules.extend([
            CodeQualityRule(
                name="exception_pass",
                description="Empty except block",
                pattern=r"except.*:\s*pass",
                severity=VulnerabilitySeverity.MEDIUM
            ),
            CodeQualityRule(
                name="broad_except",
                description="Too broad exception clause",
                pattern=r"except\s*:",
                severity=VulnerabilitySeverity.MEDIUM
            ),
            CodeQualityRule(
                name="debug_code",
                description="Debug code in production",
                pattern=r"print\(|debug\(|console\.log\(",
                severity=VulnerabilitySeverity.LOW
            ),
        ])
    
    def add_rule(self, rule: SecurityRule):
        """
        Add a security rule to the analyzer.
        
        Args:
            rule: Security rule to add
        """
        self.rules.append(rule)
    
    def run_analysis(self, target_path: str = None) -> SecurityReport:
        """
        Run static analysis on the target path.
        
        Args:
            target_path: Path to analyze (defaults to project_root)
        
        Returns:
            Security report with findings
        """
        target_path = target_path or self.project_root
        logger.info(f"Running static analysis on {target_path}")
        
        # Create a new security report
        report = SecurityReport()
        
        # Run pattern-based analysis
        pattern_vulnerabilities = self._run_pattern_analysis(target_path)
        report.add_vulnerabilities(pattern_vulnerabilities)
        
        # Run AST-based analysis
        ast_vulnerabilities = self._run_ast_analysis(target_path)
        report.add_vulnerabilities(ast_vulnerabilities)
        
        # Run external tools
        try:
            bandit_vulnerabilities = self._run_bandit(target_path)
            report.add_vulnerabilities(bandit_vulnerabilities)
        except Exception as e:
            logger.warning(f"Failed to run Bandit: {str(e)}")
        
        try:
            safety_vulnerabilities = self._run_safety()
            report.add_vulnerabilities(safety_vulnerabilities)
        except Exception as e:
            logger.warning(f"Failed to run Safety: {str(e)}")
        
        return report
    
    def _run_pattern_analysis(self, target_path: str) -> List[Vulnerability]:
        """
        Run pattern-based analysis on the target path.
        
        Args:
            target_path: Path to analyze
        
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Walk through all Python files in the target path
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    
                    # Read the file content
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        
                        # Check each rule against the file content
                        for rule in self.rules:
                            if isinstance(rule, (CryptographicRule, CodeQualityRule)):
                                matches = re.finditer(rule.pattern, content)
                                
                                for match in matches:
                                    # Get line number
                                    line_number = content[:match.start()].count("\n") + 1
                                    
                                    # Create vulnerability
                                    vulnerability = Vulnerability(
                                        name=rule.name,
                                        description=rule.description,
                                        severity=rule.severity,
                                        file_path=file_path,
                                        line_number=line_number,
                                        code_snippet=match.group(0)
                                    )
                                    
                                    vulnerabilities.append(vulnerability)
                    
                    except Exception as e:
                        logger.warning(f"Failed to analyze {file_path}: {str(e)}")
        
        return vulnerabilities
    
    def _run_ast_analysis(self, target_path: str) -> List[Vulnerability]:
        """
        Run AST-based analysis on the target path.
        
        Args:
            target_path: Path to analyze
        
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Walk through all Python files in the target path
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    
                    # Parse the file into an AST
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        
                        tree = ast.parse(content, filename=file_path)
                        
                        # Check for hardcoded secrets
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Assign):
                                for target in node.targets:
                                    if isinstance(target, ast.Name) and "key" in target.id.lower():
                                        if isinstance(node.value, ast.Str) and len(node.value.s) >= 16:
                                            # Create vulnerability
                                            vulnerability = Vulnerability(
                                                name="hardcoded_secret_ast",
                                                description="Hardcoded secret or key detected by AST analysis",
                                                severity=VulnerabilitySeverity.CRITICAL,
                                                file_path=file_path,
                                                line_number=node.lineno,
                                                code_snippet=f"{target.id} = '{node.value.s}'"
                                            )
                                            
                                            vulnerabilities.append(vulnerability)
                    
                    except Exception as e:
                        logger.warning(f"Failed to analyze AST for {file_path}: {str(e)}")
        
        return vulnerabilities
    
    def _run_bandit(self, target_path: str) -> List[Vulnerability]:
        """
        Run Bandit security linter on the target path.
        
        Args:
            target_path: Path to analyze
        
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Run Bandit
            result = subprocess.run(
                ["bandit", "-r", target_path, "-f", "json"],
                capture_output=True,
                text=True,
                check=False
            )
            
            # Parse the output
            if result.returncode in (0, 1):  # 0 = no issues, 1 = issues found
                output = json.loads(result.stdout)
                
                # Extract vulnerabilities
                for result in output.get("results", []):
                    # Map Bandit severity to our severity
                    severity_map = {
                        "LOW": VulnerabilitySeverity.LOW,
                        "MEDIUM": VulnerabilitySeverity.MEDIUM,
                        "HIGH": VulnerabilitySeverity.HIGH
                    }
                    
                    severity = severity_map.get(result.get("issue_severity", "MEDIUM"), VulnerabilitySeverity.MEDIUM)
                    
                    # Create vulnerability
                    vulnerability = Vulnerability(
                        name=f"bandit_{result.get('test_id', 'unknown')}",
                        description=result.get("issue_text", "Unknown Bandit issue"),
                        severity=severity,
                        file_path=result.get("filename", "unknown"),
                        line_number=result.get("line_number", 0),
                        code_snippet=result.get("code", "")
                    )
                    
                    vulnerabilities.append(vulnerability)
        
        except Exception as e:
            logger.warning(f"Failed to run Bandit: {str(e)}")
        
        return vulnerabilities
    
    def _run_safety(self) -> List[Vulnerability]:
        """
        Run Safety to check for vulnerable dependencies.
        
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Run Safety
            result = subprocess.run(
                ["safety", "check", "--json"],
                capture_output=True,
                text=True,
                check=False
            )
            
            # Parse the output
            if result.returncode in (0, 255):  # 0 = no issues, 255 = issues found
                output = json.loads(result.stdout)
                
                # Extract vulnerabilities
                for vuln in output.get("vulnerabilities", []):
                    # Map Safety severity to our severity
                    severity_map = {
                        "low": VulnerabilitySeverity.LOW,
                        "medium": VulnerabilitySeverity.MEDIUM,
                        "high": VulnerabilitySeverity.HIGH,
                        "critical": VulnerabilitySeverity.CRITICAL
                    }
                    
                    severity = severity_map.get(vuln.get("severity", "medium"), VulnerabilitySeverity.MEDIUM)
                    
                    # Create vulnerability
                    vulnerability = Vulnerability(
                        name=f"safety_{vuln.get('vulnerability_id', 'unknown')}",
                        description=f"Vulnerable dependency: {vuln.get('package_name', 'unknown')} {vuln.get('vulnerable_spec', 'unknown')}",
                        severity=severity,
                        file_path="requirements.txt",
                        line_number=0,
                        code_snippet=f"{vuln.get('package_name', 'unknown')}=={vuln.get('installed_version', 'unknown')}"
                    )
                    
                    vulnerabilities.append(vulnerability)
        
        except Exception as e:
            logger.warning(f"Failed to run Safety: {str(e)}")
        
        return vulnerabilities
    
    def generate_report(self, report: SecurityReport, output_file: str = None) -> str:
        """
        Generate a security report in markdown format.
        
        Args:
            report: Security report to generate
            output_file: Output file path (if None, returns the report as a string)
        
        Returns:
            Report as a string if output_file is None, otherwise None
        """
        # Generate report content
        content = "# Security Analysis Report\n\n"
        
        # Summary
        content += "## Summary\n\n"
        content += f"- **Total vulnerabilities found:** {len(report.vulnerabilities)}\n"
        content += f"- **Critical:** {len([v for v in report.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL])}\n"
        content += f"- **High:** {len([v for v in report.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH])}\n"
        content += f"- **Medium:** {len([v for v in report.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM])}\n"
        content += f"- **Low:** {len([v for v in report.vulnerabilities if v.severity == VulnerabilitySeverity.LOW])}\n\n"
        
        # Vulnerabilities by severity
        for severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH, VulnerabilitySeverity.MEDIUM, VulnerabilitySeverity.LOW]:
            vulns = [v for v in report.vulnerabilities if v.severity == severity]
            
            if vulns:
                content += f"## {severity.name.title()} Severity Vulnerabilities\n\n"
                
                for vuln in vulns:
                    content += f"### {vuln.name}\n\n"
                    content += f"- **Description:** {vuln.description}\n"
                    content += f"- **File:** {vuln.file_path}\n"
                    content += f"- **Line:** {vuln.line_number}\n"
                    content += f"- **Code snippet:**\n\n```python\n{vuln.code_snippet}\n```\n\n"
        
        # Write to file or return as string
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
            
            return None
        else:
            return content
