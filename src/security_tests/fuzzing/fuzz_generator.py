"""
Fuzz Generator Module

This module provides a generator for fuzzing inputs.
"""

import os
import random
import string
import json
import base64
import struct
from typing import List, Dict, Any, Optional, Union

class FuzzGenerator:
    """
    Generator for fuzzing inputs.
    
    This class provides methods for generating various types of inputs for fuzzing.
    """
    
    def __init__(self, seed: int = None):
        """
        Initialize the fuzz generator.
        
        Args:
            seed: Random seed (if None, uses a random seed)
        """
        if seed is not None:
            random.seed(seed)
    
    def generate(self, input_type: str) -> Any:
        """
        Generate a fuzzing input of the specified type.
        
        Args:
            input_type: Type of input to generate
        
        Returns:
            Generated input
        """
        if input_type == "str":
            return self.generate_string()
        elif input_type == "bytes":
            return self.generate_bytes()
        elif input_type == "int":
            return self.generate_int()
        elif input_type == "float":
            return self.generate_float()
        elif input_type == "bool":
            return self.generate_bool()
        elif input_type == "list":
            return self.generate_list()
        elif input_type == "dict":
            return self.generate_dict()
        elif input_type == "key":
            return self.generate_key()
        elif input_type == "none":
            return None
        else:
            raise ValueError(f"Unknown input type: {input_type}")
    
    def generate_string(self, min_length: int = 0, max_length: int = 100) -> str:
        """
        Generate a random string.
        
        Args:
            min_length: Minimum string length
            max_length: Maximum string length
        
        Returns:
            Random string
        """
        # Choose a string generation strategy
        strategy = random.choice([
            self._generate_ascii_string,
            self._generate_unicode_string,
            self._generate_special_string
        ])
        
        return strategy(min_length, max_length)
    
    def _generate_ascii_string(self, min_length: int, max_length: int) -> str:
        """
        Generate a random ASCII string.
        
        Args:
            min_length: Minimum string length
            max_length: Maximum string length
        
        Returns:
            Random ASCII string
        """
        length = random.randint(min_length, max_length)
        return ''.join(random.choice(string.printable) for _ in range(length))
    
    def _generate_unicode_string(self, min_length: int, max_length: int) -> str:
        """
        Generate a random Unicode string.
        
        Args:
            min_length: Minimum string length
            max_length: Maximum string length
        
        Returns:
            Random Unicode string
        """
        length = random.randint(min_length, max_length)
        return ''.join(chr(random.randint(0, 0x10FFFF)) for _ in range(length))
    
    def _generate_special_string(self, min_length: int, max_length: int) -> str:
        """
        Generate a special string (e.g., empty, very long, format string).
        
        Args:
            min_length: Minimum string length
            max_length: Maximum string length
        
        Returns:
            Special string
        """
        special_strings = [
            "",
            "a" * 1000,
            "a" * 10000,
            "%s%s%s%s%s",
            "%x%x%x%x%x",
            "%n%n%n%n%n",
            "\\x00\\x00\\x00\\x00",
            "\\xff\\xff\\xff\\xff",
            "0" * 1000,
            "1" * 1000,
            "A" * 1000,
            "Z" * 1000,
            "9" * 1000,
            "0xffffffff",
            "0x00000000",
            "NaN",
            "Infinity",
            "-Infinity",
            "undefined",
            "null",
            "true",
            "false",
            "[]",
            "{}",
            "{'a': 1}",
            "[1, 2, 3]",
            "function(){}",
            "<script>alert(1)</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "/dev/null",
            "C:\\Windows\\System32\\cmd.exe",
            "https://example.com",
            "file:///etc/passwd",
            "data:text/html,<script>alert(1)</script>"
        ]
        
        return random.choice(special_strings)
    
    def generate_bytes(self, min_length: int = 0, max_length: int = 100) -> bytes:
        """
        Generate random bytes.
        
        Args:
            min_length: Minimum bytes length
            max_length: Maximum bytes length
        
        Returns:
            Random bytes
        """
        # Choose a bytes generation strategy
        strategy = random.choice([
            self._generate_random_bytes,
            self._generate_special_bytes
        ])
        
        return strategy(min_length, max_length)
    
    def _generate_random_bytes(self, min_length: int, max_length: int) -> bytes:
        """
        Generate random bytes.
        
        Args:
            min_length: Minimum bytes length
            max_length: Maximum bytes length
        
        Returns:
            Random bytes
        """
        length = random.randint(min_length, max_length)
        return bytes(random.randint(0, 255) for _ in range(length))
    
    def _generate_special_bytes(self, min_length: int, max_length: int) -> bytes:
        """
        Generate special bytes (e.g., empty, all zeros, all ones).
        
        Args:
            min_length: Minimum bytes length
            max_length: Maximum bytes length
        
        Returns:
            Special bytes
        """
        special_bytes = [
            b"",
            b"\x00" * 100,
            b"\xff" * 100,
            b"\x00\xff" * 50,
            b"\xff\x00" * 50,
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
            b"\x0a\x0d\x0a\x0d\x0a\x0d\x0a\x0d\x0a\x0d",
            b"A" * 100,
            b"Z" * 100,
            b"0" * 100,
            b"9" * 100,
            b"a" * 100,
            b"z" * 100
        ]
        
        return random.choice(special_bytes)
    
    def generate_int(self, min_value: int = -1000000, max_value: int = 1000000) -> int:
        """
        Generate a random integer.
        
        Args:
            min_value: Minimum value
            max_value: Maximum value
        
        Returns:
            Random integer
        """
        # Choose an integer generation strategy
        strategy = random.choice([
            self._generate_random_int,
            self._generate_special_int
        ])
        
        return strategy(min_value, max_value)
    
    def _generate_random_int(self, min_value: int, max_value: int) -> int:
        """
        Generate a random integer.
        
        Args:
            min_value: Minimum value
            max_value: Maximum value
        
        Returns:
            Random integer
        """
        return random.randint(min_value, max_value)
    
    def _generate_special_int(self, min_value: int, max_value: int) -> int:
        """
        Generate a special integer (e.g., 0, -1, max int, min int).
        
        Args:
            min_value: Minimum value
            max_value: Maximum value
        
        Returns:
            Special integer
        """
        special_ints = [
            0,
            -1,
            1,
            -2,
            2,
            -128,
            127,
            -32768,
            32767,
            -2147483648,
            2147483647,
            -9223372036854775808,
            9223372036854775807
        ]
        
        return random.choice(special_ints)
    
    def generate_float(self, min_value: float = -1000000.0, max_value: float = 1000000.0) -> float:
        """
        Generate a random float.
        
        Args:
            min_value: Minimum value
            max_value: Maximum value
        
        Returns:
            Random float
        """
        # Choose a float generation strategy
        strategy = random.choice([
            self._generate_random_float,
            self._generate_special_float
        ])
        
        return strategy(min_value, max_value)
    
    def _generate_random_float(self, min_value: float, max_value: float) -> float:
        """
        Generate a random float.
        
        Args:
            min_value: Minimum value
            max_value: Maximum value
        
        Returns:
            Random float
        """
        return random.uniform(min_value, max_value)
    
    def _generate_special_float(self, min_value: float, max_value: float) -> float:
        """
        Generate a special float (e.g., 0.0, -0.0, NaN, infinity).
        
        Args:
            min_value: Minimum value
            max_value: Maximum value
        
        Returns:
            Special float
        """
        special_floats = [
            0.0,
            -0.0,
            float('nan'),
            float('inf'),
            float('-inf'),
            1e-10,
            1e10,
            -1e-10,
            -1e10,
            3.14159265358979323846,
            2.71828182845904523536
        ]
        
        return random.choice(special_floats)
    
    def generate_bool(self) -> bool:
        """
        Generate a random boolean.
        
        Returns:
            Random boolean
        """
        return random.choice([True, False])
    
    def generate_list(self, min_length: int = 0, max_length: int = 10) -> List[Any]:
        """
        Generate a random list.
        
        Args:
            min_length: Minimum list length
            max_length: Maximum list length
        
        Returns:
            Random list
        """
        length = random.randint(min_length, max_length)
        
        # Choose list element types
        element_types = random.choices(
            ["str", "bytes", "int", "float", "bool", "none"],
            k=length
        )
        
        return [self.generate(element_type) for element_type in element_types]
    
    def generate_dict(self, min_length: int = 0, max_length: int = 10) -> Dict[str, Any]:
        """
        Generate a random dictionary.
        
        Args:
            min_length: Minimum dictionary length
            max_length: Maximum dictionary length
        
        Returns:
            Random dictionary
        """
        length = random.randint(min_length, max_length)
        
        # Generate keys
        keys = [self.generate_string(1, 10) for _ in range(length)]
        
        # Choose value types
        value_types = random.choices(
            ["str", "bytes", "int", "float", "bool", "none"],
            k=length
        )
        
        # Generate values
        values = [self.generate(value_type) for value_type in value_types]
        
        return dict(zip(keys, values))
    
    def generate_key(self) -> bytes:
        """
        Generate a random cryptographic key.
        
        Returns:
            Random key
        """
        # Choose a key size
        key_size = random.choice([16, 24, 32, 64, 128, 256])
        
        # Generate random bytes for the key
        return os.urandom(key_size)
    
    def generate_encryption_result(self) -> Dict[str, Any]:
        """
        Generate a random encryption result.
        
        Returns:
            Random encryption result
        """
        # Choose an encryption algorithm
        algorithm = random.choice(["AES-GCM", "ChaCha20-Poly1305", "AES-CBC", "AES-CTR"])
        
        # Generate ciphertext
        ciphertext = self.generate_bytes(10, 1000)
        
        # Generate nonce/IV
        nonce_size = 12 if algorithm in ["AES-GCM", "ChaCha20-Poly1305"] else 16
        nonce = os.urandom(nonce_size)
        
        # Generate tag for authenticated encryption
        tag = os.urandom(16) if algorithm in ["AES-GCM", "ChaCha20-Poly1305"] else None
        
        # Create encryption result
        result = {
            "algorithm": algorithm,
            "ciphertext": ciphertext,
            "nonce": nonce
        }
        
        if tag:
            result["tag"] = tag
        
        # Optionally add associated data
        if random.choice([True, False]):
            result["associated_data"] = self.generate_bytes(10, 100)
        
        return result
