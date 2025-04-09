"""
Fuzzing Engine Module

This module provides a fuzzing engine for testing the cryptographic system.
"""

import os
import time
import logging
import random
import string
import multiprocessing
import traceback
from typing import List, Dict, Any, Optional, Callable, Tuple, Union

from .fuzz_generator import FuzzGenerator
from .fuzz_result import FuzzResult, FuzzResultStatus

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fuzzing_engine")

class FuzzTarget:
    """Represents a target for fuzzing."""
    
    def __init__(self, name: str, function: Callable, input_types: List[str], iterations: int = 1000):
        """
        Initialize a fuzz target.
        
        Args:
            name: Target name
            function: Function to fuzz
            input_types: Types of inputs to generate
            iterations: Number of fuzzing iterations
        """
        self.name = name
        self.function = function
        self.input_types = input_types
        self.iterations = iterations
        self.results = []
    
    def run(self, generator: FuzzGenerator) -> List[FuzzResult]:
        """
        Run fuzzing on the target.
        
        Args:
            generator: Fuzz generator to use
        
        Returns:
            List of fuzzing results
        """
        logger.info(f"Fuzzing target {self.name} with {self.iterations} iterations")
        
        for i in range(self.iterations):
            # Generate inputs
            inputs = []
            for input_type in self.input_types:
                inputs.append(generator.generate(input_type))
            
            # Run the function with the generated inputs
            start_time = time.time()
            result = FuzzResult(
                target_name=self.name,
                inputs=inputs,
                iteration=i
            )
            
            try:
                output = self.function(*inputs)
                result.output = output
                result.status = FuzzResultStatus.SUCCESS
            except Exception as e:
                result.exception = str(e)
                result.traceback = traceback.format_exc()
                result.status = FuzzResultStatus.FAILURE
            
            result.duration = time.time() - start_time
            self.results.append(result)
            
            # Log progress
            if (i + 1) % 100 == 0:
                logger.info(f"Completed {i + 1}/{self.iterations} iterations for target {self.name}")
        
        return self.results

class FuzzingEngine:
    """
    Fuzzing engine for testing the cryptographic system.
    
    This class provides methods for:
    - Fuzzing various functions with random inputs
    - Detecting crashes and unexpected behavior
    - Generating fuzzing reports
    """
    
    def __init__(self):
        """Initialize the fuzzing engine."""
        self.targets = []
        self.generator = FuzzGenerator()
        self.results = []
    
    def add_target(self, target: FuzzTarget):
        """
        Add a target to the fuzzing engine.
        
        Args:
            target: Target to add
        """
        self.targets.append(target)
    
    def add_function(self, name: str, function: Callable, input_types: List[str], iterations: int = 1000):
        """
        Add a function as a fuzzing target.
        
        Args:
            name: Target name
            function: Function to fuzz
            input_types: Types of inputs to generate
            iterations: Number of fuzzing iterations
        """
        target = FuzzTarget(name, function, input_types, iterations)
        self.add_target(target)
    
    def run(self, parallel: bool = False) -> List[FuzzResult]:
        """
        Run fuzzing on all targets.
        
        Args:
            parallel: Whether to run targets in parallel
        
        Returns:
            List of fuzzing results
        """
        logger.info(f"Running fuzzing on {len(self.targets)} targets")
        
        if parallel:
            self._run_parallel()
        else:
            self._run_sequential()
        
        return self.results
    
    def _run_sequential(self):
        """Run targets sequentially."""
        self.results = []
        
        for target in self.targets:
            target_results = target.run(self.generator)
            self.results.extend(target_results)
    
    def _run_parallel(self):
        """Run targets in parallel."""
        self.results = []
        
        # Create a pool of workers
        with multiprocessing.Pool() as pool:
            # Run each target in a separate process
            target_results = pool.map(self._run_target, self.targets)
            
            # Flatten the results
            for results in target_results:
                self.results.extend(results)
    
    def _run_target(self, target: FuzzTarget) -> List[FuzzResult]:
        """
        Run fuzzing on a target.
        
        Args:
            target: Target to fuzz
        
        Returns:
            List of fuzzing results
        """
        return target.run(self.generator)
    
    def get_failures(self) -> List[FuzzResult]:
        """
        Get all fuzzing failures.
        
        Returns:
            List of fuzzing failures
        """
        return [result for result in self.results if result.status == FuzzResultStatus.FAILURE]
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the fuzzing results.
        
        Returns:
            Dictionary with fuzzing summary
        """
        summary = {
            "total_iterations": len(self.results),
            "successful_iterations": len([r for r in self.results if r.status == FuzzResultStatus.SUCCESS]),
            "failed_iterations": len(self.get_failures()),
            "targets": {}
        }
        
        # Summarize results by target
        for target in self.targets:
            target_results = [r for r in self.results if r.target_name == target.name]
            target_failures = [r for r in target_results if r.status == FuzzResultStatus.FAILURE]
            
            summary["targets"][target.name] = {
                "total_iterations": len(target_results),
                "successful_iterations": len(target_results) - len(target_failures),
                "failed_iterations": len(target_failures)
            }
        
        return summary
    
    def generate_report(self, output_file: str = None, include_failures_only: bool = True) -> str:
        """
        Generate a report of the fuzzing results.
        
        Args:
            output_file: Output file path (if None, returns the report as a string)
            include_failures_only: Whether to include only failures in the report
        
        Returns:
            Report as a string if output_file is None, otherwise None
        """
        summary = self.get_summary()
        
        # Generate report content
        content = "# Fuzzing Report\n\n"
        
        # Summary
        content += "## Summary\n\n"
        content += f"- **Total iterations:** {summary['total_iterations']}\n"
        content += f"- **Successful iterations:** {summary['successful_iterations']}\n"
        content += f"- **Failed iterations:** {summary['failed_iterations']}\n\n"
        
        # Target summaries
        content += "## Target Summaries\n\n"
        
        for target_name, target_summary in summary["targets"].items():
            content += f"### {target_name}\n\n"
            content += f"- **Total iterations:** {target_summary['total_iterations']}\n"
            content += f"- **Successful iterations:** {target_summary['successful_iterations']}\n"
            content += f"- **Failed iterations:** {target_summary['failed_iterations']}\n\n"
        
        # Failures
        failures = self.get_failures()
        
        if failures:
            content += "## Failures\n\n"
            
            for i, failure in enumerate(failures):
                content += f"### Failure {i + 1}\n\n"
                content += f"- **Target:** {failure.target_name}\n"
                content += f"- **Iteration:** {failure.iteration}\n"
                content += f"- **Inputs:** {failure.inputs}\n"
                content += f"- **Exception:** {failure.exception}\n"
                content += f"- **Traceback:**\n\n```\n{failure.traceback}\n```\n\n"
        
        # Write to file or return as string
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
            
            return None
        else:
            return content
    
    def fuzz_encryption(self, encryption_function: Callable, iterations: int = 1000) -> List[FuzzResult]:
        """
        Fuzz an encryption function.
        
        Args:
            encryption_function: Encryption function to fuzz
            iterations: Number of fuzzing iterations
        
        Returns:
            List of fuzzing results
        """
        target = FuzzTarget(
            name="encryption",
            function=encryption_function,
            input_types=["bytes", "key", "str"],
            iterations=iterations
        )
        
        return target.run(self.generator)
    
    def fuzz_decryption(self, decryption_function: Callable, iterations: int = 1000) -> List[FuzzResult]:
        """
        Fuzz a decryption function.
        
        Args:
            decryption_function: Decryption function to fuzz
            iterations: Number of fuzzing iterations
        
        Returns:
            List of fuzzing results
        """
        target = FuzzTarget(
            name="decryption",
            function=decryption_function,
            input_types=["dict", "key"],
            iterations=iterations
        )
        
        return target.run(self.generator)
    
    def fuzz_signature(self, signature_function: Callable, iterations: int = 1000) -> List[FuzzResult]:
        """
        Fuzz a signature function.
        
        Args:
            signature_function: Signature function to fuzz
            iterations: Number of fuzzing iterations
        
        Returns:
            List of fuzzing results
        """
        target = FuzzTarget(
            name="signature",
            function=signature_function,
            input_types=["bytes", "key", "str"],
            iterations=iterations
        )
        
        return target.run(self.generator)
    
    def fuzz_verification(self, verification_function: Callable, iterations: int = 1000) -> List[FuzzResult]:
        """
        Fuzz a verification function.
        
        Args:
            verification_function: Verification function to fuzz
            iterations: Number of fuzzing iterations
        
        Returns:
            List of fuzzing results
        """
        target = FuzzTarget(
            name="verification",
            function=verification_function,
            input_types=["bytes", "dict", "key"],
            iterations=iterations
        )
        
        return target.run(self.generator)
