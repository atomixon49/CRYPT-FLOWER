"""
Fuzz Result Module

This module provides classes for representing fuzzing results.
"""

import enum
import time
from typing import List, Dict, Any, Optional

class FuzzResultStatus(enum.Enum):
    """Status of a fuzzing result."""
    SUCCESS = "success"
    FAILURE = "failure"

class FuzzResult:
    """Represents a fuzzing result."""
    
    def __init__(self, target_name: str, inputs: List[Any], iteration: int):
        """
        Initialize a fuzzing result.
        
        Args:
            target_name: Name of the fuzzing target
            inputs: Inputs used for fuzzing
            iteration: Iteration number
        """
        self.target_name = target_name
        self.inputs = inputs
        self.iteration = iteration
        self.output = None
        self.exception = None
        self.traceback = None
        self.status = None
        self.duration = None
        self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the fuzzing result to a dictionary.
        
        Returns:
            Dictionary representation of the fuzzing result
        """
        return {
            "target_name": self.target_name,
            "inputs": self._serialize_inputs(),
            "iteration": self.iteration,
            "output": self._serialize_output(),
            "exception": self.exception,
            "traceback": self.traceback,
            "status": self.status.value if self.status else None,
            "duration": self.duration,
            "timestamp": self.timestamp
        }
    
    def _serialize_inputs(self) -> List[str]:
        """
        Serialize inputs to strings.
        
        Returns:
            List of serialized inputs
        """
        serialized = []
        
        for input_value in self.inputs:
            if isinstance(input_value, bytes):
                # Convert bytes to a hex string
                serialized.append(f"bytes({len(input_value)}): {input_value[:20].hex()}...")
            elif isinstance(input_value, (dict, list)):
                # Convert dict/list to a string representation
                serialized.append(f"{type(input_value).__name__}({len(input_value)}): {str(input_value)[:100]}...")
            else:
                # Convert other types to a string representation
                serialized.append(f"{type(input_value).__name__}: {str(input_value)[:100]}...")
        
        return serialized
    
    def _serialize_output(self) -> Optional[str]:
        """
        Serialize output to a string.
        
        Returns:
            Serialized output, or None if output is None
        """
        if self.output is None:
            return None
        
        if isinstance(self.output, bytes):
            # Convert bytes to a hex string
            return f"bytes({len(self.output)}): {self.output[:20].hex()}..."
        elif isinstance(self.output, (dict, list)):
            # Convert dict/list to a string representation
            return f"{type(self.output).__name__}({len(self.output)}): {str(self.output)[:100]}..."
        else:
            # Convert other types to a string representation
            return f"{type(self.output).__name__}: {str(self.output)[:100]}..."
