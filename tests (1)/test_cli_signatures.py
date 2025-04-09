"""
Integration tests for signature functionality in the CLI.
"""

import unittest
import os
import tempfile
import subprocess
import sys

class TestCLISignatures(unittest.TestCase):
    """Integration tests for signature functionality in the CLI."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a test file
        self.test_file_path = os.path.join(self.test_dir, "test_file.txt")
        with open(self.test_file_path, "w") as f:
            f.write("This is a test file for CLI signature tests.")
        
        # Define paths for keys and signatures
        self.pss_key_path = os.path.join(self.test_dir, "pss_key")
        self.pkcs_key_path = os.path.join(self.test_dir, "pkcs_key")
        self.pss_sig_path = os.path.join(self.test_dir, "test_file.pss.sig")
        self.pkcs_sig_path = os.path.join(self.test_dir, "test_file.pkcs.sig")
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        for root, dirs, files in os.walk(self.test_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.test_dir)
    
    def run_cli_command(self, args):
        """Run a CLI command and return the result."""
        command = [sys.executable, "-m", "src.main"] + args
        result = subprocess.run(command, capture_output=True, text=True)
        return result
    
    def test_rsa_pss_signature(self):
        """Test RSA-PSS signature generation and verification."""
        # Generate a key pair
        result = self.run_cli_command([
            "genkey", 
            "--output", self.pss_key_path,
            "--algorithm", "RSA-PSS"
        ])
        self.assertEqual(result.returncode, 0)
        
        # Sign the file
        result = self.run_cli_command([
            "sign",
            "--key", f"{self.pss_key_path}.private",
            "--output", self.pss_sig_path,
            "--algorithm", "RSA-PSS",
            self.test_file_path
        ])
        self.assertEqual(result.returncode, 0)
        
        # Verify the signature
        result = self.run_cli_command([
            "verify",
            "--key", f"{self.pss_key_path}.public",
            "--algorithm", "RSA-PSS",
            self.test_file_path,
            self.pss_sig_path
        ])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Signature is valid", result.stdout)
    
    def test_rsa_pkcs1v15_signature(self):
        """Test RSA-PKCS1v15 signature generation and verification."""
        # Generate a key pair
        result = self.run_cli_command([
            "genkey", 
            "--output", self.pkcs_key_path,
            "--algorithm", "RSA-PKCS1v15"
        ])
        self.assertEqual(result.returncode, 0)
        
        # Sign the file
        result = self.run_cli_command([
            "sign",
            "--key", f"{self.pkcs_key_path}.private",
            "--output", self.pkcs_sig_path,
            "--algorithm", "RSA-PKCS1v15",
            self.test_file_path
        ])
        self.assertEqual(result.returncode, 0)
        
        # Verify the signature
        result = self.run_cli_command([
            "verify",
            "--key", f"{self.pkcs_key_path}.public",
            "--algorithm", "RSA-PKCS1v15",
            self.test_file_path,
            self.pkcs_sig_path
        ])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Signature is valid", result.stdout)
    
    def test_cross_algorithm_verification(self):
        """Test that verification fails when using the wrong algorithm."""
        # Generate key pairs
        self.run_cli_command([
            "genkey", 
            "--output", self.pss_key_path,
            "--algorithm", "RSA-PSS"
        ])
        self.run_cli_command([
            "genkey", 
            "--output", self.pkcs_key_path,
            "--algorithm", "RSA-PKCS1v15"
        ])
        
        # Sign files with different algorithms
        self.run_cli_command([
            "sign",
            "--key", f"{self.pss_key_path}.private",
            "--output", self.pss_sig_path,
            "--algorithm", "RSA-PSS",
            self.test_file_path
        ])
        self.run_cli_command([
            "sign",
            "--key", f"{self.pkcs_key_path}.private",
            "--output", self.pkcs_sig_path,
            "--algorithm", "RSA-PKCS1v15",
            self.test_file_path
        ])
        
        # Verify with wrong algorithm should fail
        result = self.run_cli_command([
            "verify",
            "--key", f"{self.pss_key_path}.public",
            "--algorithm", "RSA-PKCS1v15",  # Wrong algorithm
            self.test_file_path,
            self.pss_sig_path
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Signature is invalid", result.stdout)
        
        result = self.run_cli_command([
            "verify",
            "--key", f"{self.pkcs_key_path}.public",
            "--algorithm", "RSA-PSS",  # Wrong algorithm
            self.test_file_path,
            self.pkcs_sig_path
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Signature is invalid", result.stdout)


if __name__ == "__main__":
    unittest.main()
