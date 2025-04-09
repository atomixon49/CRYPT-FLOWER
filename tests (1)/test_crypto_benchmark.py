"""
Tests for the cryptographic benchmarking and optimization module.
"""

import unittest
import os
import tempfile
import shutil
import time
import json
import random
from pathlib import Path

from src.core.crypto_benchmark import (
    BenchmarkType,
    BenchmarkResult,
    CryptoBenchmark,
    ChunkProcessor,
    ParallelProcessor
)


class TestBenchmarkResult(unittest.TestCase):
    """Test cases for the BenchmarkResult class."""
    
    def test_create_result(self):
        """Test creating a benchmark result."""
        # Create a benchmark result
        result = BenchmarkResult(
            benchmark_type=BenchmarkType.ENCRYPTION,
            algorithm="AES-256-GCM",
            data_size=1024 * 1024,  # 1 MB
            iterations=10,
            execution_times=[0.1, 0.11, 0.09, 0.1, 0.12, 0.1, 0.09, 0.11, 0.1, 0.1],
            memory_usage=[1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024],
            metadata={"key_size": 256}
        )
        
        # Verify the result
        self.assertEqual(result.benchmark_type, BenchmarkType.ENCRYPTION)
        self.assertEqual(result.algorithm, "AES-256-GCM")
        self.assertEqual(result.data_size, 1024 * 1024)
        self.assertEqual(result.iterations, 10)
        self.assertEqual(len(result.execution_times), 10)
        self.assertEqual(len(result.memory_usage), 10)
        self.assertEqual(result.metadata["key_size"], 256)
    
    def test_result_statistics(self):
        """Test calculating statistics from benchmark results."""
        # Create a benchmark result with known values
        result = BenchmarkResult(
            benchmark_type=BenchmarkType.ENCRYPTION,
            algorithm="AES-256-GCM",
            data_size=1024 * 1024,  # 1 MB
            iterations=5,
            execution_times=[0.1, 0.2, 0.3, 0.4, 0.5],
            memory_usage=[1000, 2000, 3000, 4000, 5000]
        )
        
        # Verify statistics
        self.assertEqual(result.mean_time, 0.3)
        self.assertEqual(result.median_time, 0.3)
        self.assertEqual(result.min_time, 0.1)
        self.assertEqual(result.max_time, 0.5)
        self.assertAlmostEqual(result.std_dev, 0.1581, places=4)
        self.assertEqual(result.throughput, 1024 * 1024 / 0.3)
        self.assertEqual(result.mean_memory, 3000)
    
    def test_result_serialization(self):
        """Test serializing and deserializing a benchmark result."""
        # Create a benchmark result
        original_result = BenchmarkResult(
            benchmark_type=BenchmarkType.DECRYPTION,
            algorithm="ChaCha20-Poly1305",
            data_size=512 * 1024,  # 512 KB
            iterations=5,
            execution_times=[0.05, 0.06, 0.05, 0.07, 0.05],
            metadata={"key_size": 256}
        )
        
        # Serialize to dictionary
        result_dict = original_result.to_dict()
        
        # Deserialize from dictionary
        restored_result = BenchmarkResult.from_dict(result_dict)
        
        # Verify the restored result
        self.assertEqual(restored_result.benchmark_type, original_result.benchmark_type)
        self.assertEqual(restored_result.algorithm, original_result.algorithm)
        self.assertEqual(restored_result.data_size, original_result.data_size)
        self.assertEqual(restored_result.iterations, original_result.iterations)
        self.assertEqual(restored_result.execution_times, original_result.execution_times)
        self.assertEqual(restored_result.metadata, original_result.metadata)


class TestCryptoBenchmark(unittest.TestCase):
    """Test cases for the CryptoBenchmark class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.results_file = os.path.join(self.test_dir, "benchmark_results.json")
        
        # Create a benchmark instance
        self.benchmark = CryptoBenchmark(
            results_file=self.results_file,
            warm_up_iterations=1
        )
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        shutil.rmtree(self.test_dir)
    
    def test_benchmark_function(self):
        """Test benchmarking a function."""
        # Create a test function that simulates encryption
        def test_encrypt(data_size):
            # Simulate encryption by sleeping
            time.sleep(0.01)
            return b'x' * data_size
        
        # Benchmark the function
        data_size = 1024  # 1 KB
        result = self.benchmark.benchmark_function(
            func=test_encrypt,
            benchmark_type=BenchmarkType.ENCRYPTION,
            algorithm="TEST-AES",
            data_size=data_size,
            iterations=3,
            args=(data_size,)
        )
        
        # Verify the result
        self.assertEqual(result.benchmark_type, BenchmarkType.ENCRYPTION)
        self.assertEqual(result.algorithm, "TEST-AES")
        self.assertEqual(result.data_size, data_size)
        self.assertEqual(result.iterations, 3)
        self.assertEqual(len(result.execution_times), 3)
        
        # Verify that the result was saved
        self.assertEqual(len(self.benchmark.results), 1)
        self.assertTrue(os.path.exists(self.results_file))
    
    def test_compare_algorithms(self):
        """Test comparing different algorithms."""
        # Add some test results
        for algorithm in ["AES", "ChaCha20", "Blowfish"]:
            for _ in range(2):
                self.benchmark.results.append(
                    BenchmarkResult(
                        benchmark_type=BenchmarkType.ENCRYPTION,
                        algorithm=algorithm,
                        data_size=1024,
                        iterations=5,
                        execution_times=[0.1, 0.1, 0.1, 0.1, 0.1]
                    )
                )
        
        # Compare algorithms
        comparison = self.benchmark.compare_algorithms(
            benchmark_type=BenchmarkType.ENCRYPTION,
            algorithms=["AES", "ChaCha20", "Blowfish"],
            data_size=1024
        )
        
        # Verify the comparison
        self.assertEqual(len(comparison), 3)
        self.assertIn("AES", comparison)
        self.assertIn("ChaCha20", comparison)
        self.assertIn("Blowfish", comparison)
    
    def test_get_results(self):
        """Test filtering benchmark results."""
        # Add some test results
        for benchmark_type in [BenchmarkType.ENCRYPTION, BenchmarkType.DECRYPTION]:
            for algorithm in ["AES", "ChaCha20"]:
                for data_size in [1024, 10240]:
                    self.benchmark.results.append(
                        BenchmarkResult(
                            benchmark_type=benchmark_type,
                            algorithm=algorithm,
                            data_size=data_size,
                            iterations=5,
                            execution_times=[0.1, 0.1, 0.1, 0.1, 0.1]
                        )
                    )
        
        # Filter by benchmark type
        encryption_results = self.benchmark.get_results(
            benchmark_type=BenchmarkType.ENCRYPTION
        )
        self.assertEqual(len(encryption_results), 4)
        
        # Filter by algorithm
        aes_results = self.benchmark.get_results(
            algorithm="AES"
        )
        self.assertEqual(len(aes_results), 4)
        
        # Filter by data size
        small_results = self.benchmark.get_results(
            max_data_size=1024
        )
        self.assertEqual(len(small_results), 4)
        
        # Combined filters
        combined_results = self.benchmark.get_results(
            benchmark_type=BenchmarkType.ENCRYPTION,
            algorithm="AES",
            min_data_size=1024,
            max_data_size=1024
        )
        self.assertEqual(len(combined_results), 1)
    
    def test_generate_report(self):
        """Test generating a benchmark report."""
        # Add some test results
        for benchmark_type in [BenchmarkType.ENCRYPTION, BenchmarkType.DECRYPTION]:
            for algorithm in ["AES", "ChaCha20"]:
                for data_size in [1024, 10240, 102400]:
                    self.benchmark.results.append(
                        BenchmarkResult(
                            benchmark_type=benchmark_type,
                            algorithm=algorithm,
                            data_size=data_size,
                            iterations=5,
                            execution_times=[0.1, 0.1, 0.1, 0.1, 0.1]
                        )
                    )
        
        # Generate a report
        report = self.benchmark.generate_report(
            title="Test Report",
            filters={"benchmark_type": BenchmarkType.ENCRYPTION}
        )
        
        # Verify the report
        self.assertEqual(report["title"], "Test Report")
        self.assertEqual(report["total_results"], 6)
        self.assertEqual(report["benchmark_types"]["encryption"], 6)
        self.assertEqual(report["algorithms"]["AES"], 3)
        self.assertEqual(report["algorithms"]["ChaCha20"], 3)
        self.assertEqual(len(report["comparisons"]), 2)


class TestChunkProcessor(unittest.TestCase):
    """Test cases for the ChunkProcessor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a test input file
        self.input_file = os.path.join(self.test_dir, "input.bin")
        with open(self.input_file, 'wb') as f:
            f.write(os.urandom(1024 * 1024))  # 1 MB of random data
        
        # Output file path
        self.output_file = os.path.join(self.test_dir, "output.bin")
        
        # Create a chunk processor
        self.processor = ChunkProcessor(chunk_size=256 * 1024)  # 256 KB chunks
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Remove the temporary directory and its contents
        shutil.rmtree(self.test_dir)
    
    def test_process_file_sequential(self):
        """Test processing a file sequentially."""
        # Define a simple processing function
        def process_chunk(chunk):
            # XOR each byte with 0xFF (bitwise NOT)
            return bytes([b ^ 0xFF for b in chunk])
        
        # Process the file
        bytes_processed = self.processor.process_file(
            input_file=self.input_file,
            output_file=self.output_file,
            process_func=process_chunk,
            parallel=False
        )
        
        # Verify the result
        self.assertEqual(bytes_processed, 1024 * 1024)
        self.assertTrue(os.path.exists(self.output_file))
        self.assertEqual(os.path.getsize(self.output_file), 1024 * 1024)
        
        # Verify the content
        with open(self.input_file, 'rb') as in_file, open(self.output_file, 'rb') as out_file:
            in_data = in_file.read()
            out_data = out_file.read()
            
            for i in range(len(in_data)):
                self.assertEqual(out_data[i], in_data[i] ^ 0xFF)
    
    def test_process_file_parallel(self):
        """Test processing a file in parallel."""
        # Define a simple processing function
        def process_chunk(chunk):
            # XOR each byte with 0xFF (bitwise NOT)
            return bytes([b ^ 0xFF for b in chunk])
        
        # Process the file
        bytes_processed = self.processor.process_file(
            input_file=self.input_file,
            output_file=self.output_file,
            process_func=process_chunk,
            parallel=True,
            max_workers=2
        )
        
        # Verify the result
        self.assertEqual(bytes_processed, 1024 * 1024)
        self.assertTrue(os.path.exists(self.output_file))
        self.assertEqual(os.path.getsize(self.output_file), 1024 * 1024)
        
        # Verify the content
        with open(self.input_file, 'rb') as in_file, open(self.output_file, 'rb') as out_file:
            in_data = in_file.read()
            out_data = out_file.read()
            
            for i in range(len(in_data)):
                self.assertEqual(out_data[i], in_data[i] ^ 0xFF)


class TestParallelProcessor(unittest.TestCase):
    """Test cases for the ParallelProcessor class."""
    
    def test_map(self):
        """Test mapping a function to items in parallel."""
        # Create a parallel processor
        processor = ParallelProcessor(max_workers=4)
        
        # Define a test function
        def square(x):
            return x * x
        
        # Create test data
        items = list(range(100))
        
        # Process in parallel
        results = processor.map(square, items)
        
        # Verify the results
        self.assertEqual(len(results), 100)
        for i, result in enumerate(results):
            self.assertEqual(result, i * i)
    
    def test_process_batch(self):
        """Test processing items in batches."""
        # Create a parallel processor
        processor = ParallelProcessor(max_workers=2)
        
        # Define a test function
        def double(x):
            return x * 2
        
        # Create test data
        items = list(range(100))
        
        # Process in batches
        results = processor.process_batch(double, items, batch_size=10)
        
        # Verify the results
        self.assertEqual(len(results), 100)
        for i, result in enumerate(results):
            self.assertEqual(result, i * 2)


if __name__ == "__main__":
    unittest.main()
