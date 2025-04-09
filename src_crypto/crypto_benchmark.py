"""
Cryptographic Benchmarking and Optimization Module

This module provides tools for measuring and optimizing the performance of cryptographic operations.
It includes benchmarking capabilities for different algorithms and data sizes, as well as
optimizations for handling large files and parallel processing.

Features:
- Performance benchmarking for cryptographic algorithms
- Comparative analysis of different implementations
- Optimized handling of large files
- Parallel processing for improved performance
"""

import os
import time
import json
import logging
import multiprocessing
import statistics
import shutil
import tempfile
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, Tuple
import concurrent.futures
import gc

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("crypto_benchmark")


class BenchmarkType(Enum):
    """Types of benchmarks that can be performed."""
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNATURE = "signature"
    VERIFICATION = "verification"
    KEY_GENERATION = "key_generation"
    HASH = "hash"
    KDF = "key_derivation"


class BenchmarkResult:
    """
    Represents the result of a benchmark test.

    This class encapsulates all the performance metrics collected during a benchmark test,
    including execution time, memory usage, and throughput.
    """

    def __init__(self,
                benchmark_type: BenchmarkType,
                algorithm: str,
                data_size: int,
                iterations: int,
                execution_times: List[float],
                memory_usage: Optional[List[float]] = None,
                metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize a new benchmark result.

        Args:
            benchmark_type: The type of benchmark performed
            algorithm: The algorithm being benchmarked
            data_size: Size of the test data in bytes
            iterations: Number of iterations performed
            execution_times: List of execution times for each iteration (in seconds)
            memory_usage: Optional list of memory usage measurements (in bytes)
            metadata: Additional information about the benchmark
        """
        self.benchmark_type = benchmark_type
        self.algorithm = algorithm
        self.data_size = data_size
        self.iterations = iterations
        self.execution_times = execution_times
        self.memory_usage = memory_usage or []
        self.metadata = metadata or {}
        self.timestamp = time.time()

    @property
    def mean_time(self) -> float:
        """Calculate the mean execution time."""
        return statistics.mean(self.execution_times)

    @property
    def median_time(self) -> float:
        """Calculate the median execution time."""
        return statistics.median(self.execution_times)

    @property
    def min_time(self) -> float:
        """Get the minimum execution time."""
        return min(self.execution_times)

    @property
    def max_time(self) -> float:
        """Get the maximum execution time."""
        return max(self.execution_times)

    @property
    def std_dev(self) -> float:
        """Calculate the standard deviation of execution times."""
        if len(self.execution_times) > 1:
            return statistics.stdev(self.execution_times)
        return 0.0

    @property
    def throughput(self) -> float:
        """Calculate the throughput in bytes per second."""
        if self.mean_time > 0:
            return self.data_size / self.mean_time
        return 0.0

    @property
    def mean_memory(self) -> Optional[float]:
        """Calculate the mean memory usage."""
        if self.memory_usage:
            return statistics.mean(self.memory_usage)
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the benchmark result to a dictionary for serialization."""
        result = {
            "benchmark_type": self.benchmark_type.value,
            "algorithm": self.algorithm,
            "data_size": self.data_size,
            "iterations": self.iterations,
            "execution_times": self.execution_times,
            "memory_usage": self.memory_usage,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "statistics": {
                "mean_time": self.mean_time,
                "median_time": self.median_time,
                "min_time": self.min_time,
                "max_time": self.max_time,
                "std_dev": self.std_dev,
                "throughput": self.throughput
            }
        }

        if self.memory_usage:
            result["statistics"]["mean_memory"] = self.mean_memory

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BenchmarkResult':
        """Create a benchmark result from a dictionary."""
        return cls(
            benchmark_type=BenchmarkType(data["benchmark_type"]),
            algorithm=data["algorithm"],
            data_size=data["data_size"],
            iterations=data["iterations"],
            execution_times=data["execution_times"],
            memory_usage=data.get("memory_usage"),
            metadata=data.get("metadata", {})
        )

    def __str__(self) -> str:
        """Return a string representation of the benchmark result."""
        throughput_mb = self.throughput / (1024 * 1024)
        return (
            f"Benchmark: {self.benchmark_type.value} - {self.algorithm}\n"
            f"Data size: {self.data_size / 1024:.2f} KB\n"
            f"Iterations: {self.iterations}\n"
            f"Mean time: {self.mean_time * 1000:.2f} ms\n"
            f"Median time: {self.median_time * 1000:.2f} ms\n"
            f"Min time: {self.min_time * 1000:.2f} ms\n"
            f"Max time: {self.max_time * 1000:.2f} ms\n"
            f"Std dev: {self.std_dev * 1000:.2f} ms\n"
            f"Throughput: {throughput_mb:.2f} MB/s"
        )


class CryptoBenchmark:
    """
    Main class for cryptographic benchmarking.

    This class provides methods for benchmarking different cryptographic operations
    and analyzing the results.
    """

    def __init__(self,
                results_file: Optional[str] = None,
                warm_up_iterations: int = 3,
                encryption_engine=None,
                signature_engine=None,
                key_manager=None):
        """
        Initialize the benchmark system.

        Args:
            results_file: Optional file path to store benchmark results
            warm_up_iterations: Number of warm-up iterations to perform before measuring
            encryption_engine: Optional encryption engine to use for benchmarks
            signature_engine: Optional signature engine to use for benchmarks
            key_manager: Optional key manager to use for benchmarks
        """
        self.results_file = results_file
        self.warm_up_iterations = warm_up_iterations
        self.results = []

        # Store engines for benchmarking
        self.encryption_engine = encryption_engine
        self.signature_engine = signature_engine
        self.key_manager = key_manager

        # Initialize chunk processor for large files
        self.chunk_processor = ChunkProcessor()

        # Initialize parallel processor
        self.parallel_processor = ParallelProcessor()

        # Load previous results if available
        if results_file and os.path.exists(results_file):
            try:
                with open(results_file, 'r') as f:
                    data = json.load(f)
                    for result_data in data:
                        self.results.append(BenchmarkResult.from_dict(result_data))
                logger.info(f"Loaded {len(self.results)} benchmark results from {results_file}")
            except Exception as e:
                logger.error(f"Error loading benchmark results: {str(e)}")

    def _generate_test_data(self, size: int) -> bytes:
        """Generate random test data of the specified size."""
        return os.urandom(size)

    def benchmark_function(self,
                          func: Callable,
                          benchmark_type: BenchmarkType,
                          algorithm: str,
                          data_size: int,
                          iterations: int = 10,
                          measure_memory: bool = False,
                          args: Tuple = (),
                          kwargs: Dict[str, Any] = None) -> BenchmarkResult:
        """
        Benchmark a cryptographic function.

        Args:
            func: The function to benchmark
            benchmark_type: The type of benchmark being performed
            algorithm: The algorithm being benchmarked
            data_size: Size of the test data in bytes
            iterations: Number of iterations to perform
            measure_memory: Whether to measure memory usage
            args: Positional arguments to pass to the function
            kwargs: Keyword arguments to pass to the function

        Returns:
            BenchmarkResult containing the performance metrics
        """
        kwargs = kwargs or {}
        execution_times = []
        memory_usage = [] if measure_memory else None

        # Perform warm-up iterations
        for _ in range(self.warm_up_iterations):
            func(*args, **kwargs)

        # Force garbage collection before starting
        gc.collect()

        # Perform benchmark iterations
        for _ in range(iterations):
            # Measure memory before
            if measure_memory:
                memory_before = self._get_memory_usage()

            # Measure execution time
            start_time = time.time()
            func(*args, **kwargs)
            end_time = time.time()

            # Record execution time
            execution_time = end_time - start_time
            execution_times.append(execution_time)

            # Measure memory after
            if measure_memory:
                memory_after = self._get_memory_usage()
                memory_diff = memory_after - memory_before
                memory_usage.append(memory_diff)

            # Force garbage collection between iterations
            gc.collect()

        # Create and return the benchmark result
        result = BenchmarkResult(
            benchmark_type=benchmark_type,
            algorithm=algorithm,
            data_size=data_size,
            iterations=iterations,
            execution_times=execution_times,
            memory_usage=memory_usage
        )

        # Store the result
        self.results.append(result)
        self._save_results()

        return result

    def benchmark_encryption(self,
                           crypto_module: Any,
                           algorithm: str,
                           data_size: int,
                           key: bytes,
                           iterations: int = 10,
                           measure_memory: bool = False) -> BenchmarkResult:
        """
        Benchmark an encryption operation.

        Args:
            crypto_module: The crypto system instance with an 'encrypt' method.
            algorithm: The encryption algorithm to benchmark.
            data_size: Size of the test data in bytes.
            key: The encryption key.
            iterations: Number of iterations to perform.
            measure_memory: Whether to measure memory usage.

        Returns:
            BenchmarkResult containing the performance metrics.

        Raises:
            AttributeError: If crypto_module does not have an 'encrypt' method.
            Exception: Propagates exceptions from the encrypt method.
        """
        logger.info(f"Starting encryption benchmark: Algorithm={algorithm}, DataSize={data_size}, Iterations={iterations}")

        # Check if the crypto module has the required method
        if not hasattr(crypto_module, 'encrypt') or not callable(getattr(crypto_module, 'encrypt')):
            raise AttributeError("Provided 'crypto_module' must have a callable 'encrypt' method.")

        # Generate test data
        test_data = self._generate_test_data(data_size)

        # Define the wrapper function to be benchmarked
        def encrypt_wrapper():
            try:
                # Assuming the encrypt method signature is encrypt(data, key, algorithm)
                # Adjust if your method signature is different
                _ = crypto_module.encrypt(data=test_data, key=key, algorithm=algorithm)
            except Exception as e:
                logger.error(f"Encryption failed during benchmark: {e}", exc_info=True)
                raise # Re-raise the exception to stop the benchmark if needed

        # Run the benchmark using the generic function
        result = self.benchmark_function(
            func=encrypt_wrapper,
            benchmark_type=BenchmarkType.ENCRYPTION,
            algorithm=algorithm,
            data_size=data_size,
            iterations=iterations,
            measure_memory=measure_memory,
            # Pass necessary context if encrypt_wrapper needed args/kwargs,
            # but here data/key/algo are captured by the closure.
        )

        logger.info(f"Finished encryption benchmark for {algorithm}. Mean time: {result.mean_time:.4f}s")
        return result

    def benchmark_decryption(self,
                           crypto_module: Any,
                           algorithm: str,
                           encrypted_data: bytes,
                           key: bytes,
                           iterations: int = 10,
                           measure_memory: bool = False) -> BenchmarkResult:
        """
        Benchmark a decryption operation.

        Args:
            crypto_module: The crypto system instance with a 'decrypt' method.
            algorithm: The decryption algorithm to benchmark.
            encrypted_data: The data to be decrypted.
            key: The decryption key.
            iterations: Number of iterations to perform.
            measure_memory: Whether to measure memory usage.

        Returns:
            BenchmarkResult containing the performance metrics.

        Raises:
            AttributeError: If crypto_module does not have a 'decrypt' method.
            Exception: Propagates exceptions from the decrypt method.
        """
        logger.info(f"Starting decryption benchmark: Algorithm={algorithm}, DataSize={len(encrypted_data)}, Iterations={iterations}")

        if not hasattr(crypto_module, 'decrypt') or not callable(getattr(crypto_module, 'decrypt')):
            raise AttributeError("Provided 'crypto_module' must have a callable 'decrypt' method.")

        def decrypt_wrapper():
            try:
                # Assuming the decrypt method signature is decrypt(data, key, algorithm)
                _ = crypto_module.decrypt(data=encrypted_data, key=key, algorithm=algorithm)
            except Exception as e:
                logger.error(f"Decryption failed during benchmark: {e}", exc_info=True)
                raise

        result = self.benchmark_function(
            func=decrypt_wrapper,
            benchmark_type=BenchmarkType.DECRYPTION,
            algorithm=algorithm,
            data_size=len(encrypted_data),
            iterations=iterations,
            measure_memory=measure_memory
        )

        logger.info(f"Finished decryption benchmark for {algorithm}. Mean time: {result.mean_time:.4f}s")
        return result

    def benchmark_hashing(self,
                         crypto_module: Any,
                         algorithm: str,
                         data_size: int,
                         iterations: int = 100,
                         measure_memory: bool = False) -> BenchmarkResult:
        """
        Benchmark a hashing operation.

        Args:
            crypto_module: The crypto system instance with a 'hash' method.
            algorithm: The hashing algorithm to benchmark.
            data_size: Size of the test data in bytes.
            iterations: Number of iterations to perform.
            measure_memory: Whether to measure memory usage.

        Returns:
            BenchmarkResult containing the performance metrics.

        Raises:
            AttributeError: If crypto_module does not have a 'hash' method.
            Exception: Propagates exceptions from the hash method.
        """
        logger.info(f"Starting hashing benchmark: Algorithm={algorithm}, DataSize={data_size}, Iterations={iterations}")

        if not hasattr(crypto_module, 'hash') or not callable(getattr(crypto_module, 'hash')):
            raise AttributeError("Provided 'crypto_module' must have a callable 'hash' method.")

        # Generate test data
        test_data = self._generate_test_data(data_size)

        def hash_wrapper():
            try:
                # Assuming the hash method signature is hash(data, algorithm)
                _ = crypto_module.hash(data=test_data, algorithm=algorithm)
            except Exception as e:
                logger.error(f"Hashing failed during benchmark: {e}", exc_info=True)
                raise

        result = self.benchmark_function(
            func=hash_wrapper,
            benchmark_type=BenchmarkType.HASH,
            algorithm=algorithm,
            data_size=data_size,
            iterations=iterations,
            measure_memory=measure_memory
        )

        logger.info(f"Finished hashing benchmark for {algorithm}. Mean time: {result.mean_time:.4f}s")
        return result

    def _get_memory_usage(self) -> int:
        """
        Get the current memory usage of the process.

        Returns:
            Memory usage in bytes
        """
        try:
            import psutil
            process = psutil.Process(os.getpid())
            return process.memory_info().rss
        except ImportError:
            logger.warning("psutil not available, memory usage measurement disabled")
            return 0

    def _save_results(self):
        """Save benchmark results to the results file."""
        if not self.results_file:
            return

        try:
            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(self.results_file)), exist_ok=True)

            # Convert results to dictionaries
            results_data = [result.to_dict() for result in self.results]

            # Write to file
            with open(self.results_file, 'w') as f:
                json.dump(results_data, f, indent=2)

            logger.info(f"Saved {len(self.results)} benchmark results to {self.results_file}")
        except Exception as e:
            logger.error(f"Error saving benchmark results: {str(e)}")

    def compare_algorithms(self,
                          benchmark_type: BenchmarkType,
                          algorithms: List[str],
                          data_size: int) -> Dict[str, BenchmarkResult]:
        """
        Compare the performance of different algorithms.

        Args:
            benchmark_type: The type of benchmark to compare
            algorithms: List of algorithms to compare
            data_size: Size of the test data in bytes

        Returns:
            Dictionary mapping algorithm names to their benchmark results
        """
        # Filter results matching the criteria
        matching_results = {}

        for result in self.results:
            if (result.benchmark_type == benchmark_type and
                result.algorithm in algorithms and
                result.data_size == data_size):
                matching_results[result.algorithm] = result

        return matching_results

    def get_results(self,
                   benchmark_type: Optional[BenchmarkType] = None,
                   algorithm: Optional[str] = None,
                   min_data_size: Optional[int] = None,
                   max_data_size: Optional[int] = None) -> List[BenchmarkResult]:
        """
        Get benchmark results matching the specified criteria.

        Args:
            benchmark_type: Optional filter by benchmark type
            algorithm: Optional filter by algorithm
            min_data_size: Optional minimum data size
            max_data_size: Optional maximum data size

        Returns:
            List of benchmark results matching the criteria
        """
        filtered_results = []

        for result in self.results:
            # Apply filters
            if benchmark_type and result.benchmark_type != benchmark_type:
                continue
            if algorithm and result.algorithm != algorithm:
                continue
            if min_data_size is not None and result.data_size < min_data_size:
                continue
            if max_data_size is not None and result.data_size > max_data_size:
                continue

            filtered_results.append(result)

        return filtered_results

    def benchmark_encryption(self,
                          algorithm: str,
                          data_size: int,
                          key_size: int = 256,
                          iterations: int = 10,
                          use_chunks: bool = False,
                          chunk_size: int = 1024 * 1024) -> BenchmarkResult:
        """
        Benchmark encryption performance for a specific algorithm and data size.

        Args:
            algorithm: Encryption algorithm to benchmark
            data_size: Size of the test data in bytes
            key_size: Key size in bits
            iterations: Number of iterations to perform
            use_chunks: Whether to process data in chunks for large files
            chunk_size: Size of each chunk in bytes (if use_chunks is True)

        Returns:
            BenchmarkResult containing the performance metrics
        """
        if self.encryption_engine is None:
            raise ValueError("Encryption engine is required for encryption benchmarks")

        # Generate a random key
        key = os.urandom(key_size // 8)

        # Generate test data
        test_data = self._generate_test_data(data_size)

        # Define the encryption function
        def encrypt_func():
            if use_chunks and data_size > chunk_size:
                # Process in chunks for large data
                def process_chunk(chunk):
                    return self.encryption_engine.encrypt(data=chunk, key=key, algorithm=algorithm)["ciphertext"]

                # Create temporary files
                with tempfile.NamedTemporaryFile(delete=False) as input_file, \
                     tempfile.NamedTemporaryFile(delete=False) as output_file:
                    # Write test data to input file
                    input_file.write(test_data)
                    input_file.flush()

                    # Process the file in chunks
                    self.chunk_processor.process_file(
                        input_file=input_file.name,
                        output_file=output_file.name,
                        process_func=process_chunk,
                        parallel=False
                    )

                    # Clean up temporary files
                    os.unlink(input_file.name)
                    os.unlink(output_file.name)
            else:
                # Process all data at once
                self.encryption_engine.encrypt(data=test_data, key=key, algorithm=algorithm)

        # Benchmark the encryption function
        return self.benchmark_function(
            func=encrypt_func,
            benchmark_type=BenchmarkType.ENCRYPTION,
            algorithm=algorithm,
            data_size=data_size,
            iterations=iterations,
            measure_memory=True
        )

    def benchmark_decryption(self,
                          algorithm: str,
                          data_size: int,
                          key_size: int = 256,
                          iterations: int = 10,
                          use_chunks: bool = False,
                          chunk_size: int = 1024 * 1024) -> BenchmarkResult:
        """
        Benchmark decryption performance for a specific algorithm and data size.

        Args:
            algorithm: Decryption algorithm to benchmark
            data_size: Size of the test data in bytes
            key_size: Key size in bits
            iterations: Number of iterations to perform
            use_chunks: Whether to process data in chunks for large files
            chunk_size: Size of each chunk in bytes (if use_chunks is True)

        Returns:
            BenchmarkResult containing the performance metrics
        """
        if self.encryption_engine is None:
            raise ValueError("Encryption engine is required for decryption benchmarks")

        # Generate a random key
        key = os.urandom(key_size // 8)

        # Generate test data
        test_data = self._generate_test_data(data_size)

        # Encrypt the test data first
        encryption_result = self.encryption_engine.encrypt(data=test_data, key=key, algorithm=algorithm)

        # Define the decryption function
        def decrypt_func():
            if use_chunks and data_size > chunk_size:
                # Process in chunks for large data
                # Note: This is a simplified version; in a real implementation,
                # we would need to handle the encryption format properly
                def process_chunk(chunk):
                    # Create a dummy encryption result for this chunk
                    chunk_result = {
                        "algorithm": algorithm,
                        "ciphertext": chunk,
                        "nonce": encryption_result.get("nonce"),
                        "tag": encryption_result.get("tag"),
                        "associated_data": encryption_result.get("associated_data")
                    }
                    return self.encryption_engine.decrypt(encryption_result=chunk_result, key=key)

                # Create temporary files
                with tempfile.NamedTemporaryFile(delete=False) as input_file, \
                     tempfile.NamedTemporaryFile(delete=False) as output_file:
                    # Write encrypted data to input file
                    input_file.write(encryption_result["ciphertext"])
                    input_file.flush()

                    # Process the file in chunks
                    self.chunk_processor.process_file(
                        input_file=input_file.name,
                        output_file=output_file.name,
                        process_func=process_chunk,
                        parallel=False
                    )

                    # Clean up temporary files
                    os.unlink(input_file.name)
                    os.unlink(output_file.name)
            else:
                # Process all data at once
                self.encryption_engine.decrypt(encryption_result=encryption_result, key=key)

        # Benchmark the decryption function
        return self.benchmark_function(
            func=decrypt_func,
            benchmark_type=BenchmarkType.DECRYPTION,
            algorithm=algorithm,
            data_size=data_size,
            iterations=iterations,
            measure_memory=True
        )

    def benchmark_hashing(self,
                        algorithm: str,
                        data_size: int,
                        iterations: int = 10,
                        use_chunks: bool = False,
                        chunk_size: int = 1024 * 1024) -> BenchmarkResult:
        """
        Benchmark hashing performance for a specific algorithm and data size.

        Args:
            algorithm: Hash algorithm to benchmark (e.g., "SHA-256", "SHA3-256")
            data_size: Size of the test data in bytes
            iterations: Number of iterations to perform
            use_chunks: Whether to process data in chunks for large files
            chunk_size: Size of each chunk in bytes (if use_chunks is True)

        Returns:
            BenchmarkResult containing the performance metrics
        """
        # Import hashlib here to avoid dependency issues
        import hashlib

        # Generate test data
        test_data = self._generate_test_data(data_size)

        # Define the hashing function
        def hash_func():
            if use_chunks and data_size > chunk_size:
                # Process in chunks for large data
                def process_chunk(chunk):
                    # This is just for benchmarking; we're not actually using the hash
                    if algorithm.startswith("SHA-256"):
                        hashlib.sha256(chunk).digest()
                    elif algorithm.startswith("SHA3-256"):
                        hashlib.sha3_256(chunk).digest()
                    elif algorithm.startswith("MD5"):
                        hashlib.md5(chunk).digest()
                    elif algorithm.startswith("SHA-1"):
                        hashlib.sha1(chunk).digest()
                    elif algorithm.startswith("SHA-512"):
                        hashlib.sha512(chunk).digest()
                    else:
                        # Default to SHA-256
                        hashlib.sha256(chunk).digest()
                    return chunk  # Return the chunk unchanged

                # Create temporary files
                with tempfile.NamedTemporaryFile(delete=False) as input_file, \
                     tempfile.NamedTemporaryFile(delete=False) as output_file:
                    # Write test data to input file
                    input_file.write(test_data)
                    input_file.flush()

                    # Process the file in chunks
                    self.chunk_processor.process_file(
                        input_file=input_file.name,
                        output_file=output_file.name,
                        process_func=process_chunk,
                        parallel=False
                    )

                    # Clean up temporary files
                    os.unlink(input_file.name)
                    os.unlink(output_file.name)
            else:
                # Process all data at once
                if algorithm.startswith("SHA-256"):
                    hashlib.sha256(test_data).digest()
                elif algorithm.startswith("SHA3-256"):
                    hashlib.sha3_256(test_data).digest()
                elif algorithm.startswith("MD5"):
                    hashlib.md5(test_data).digest()
                elif algorithm.startswith("SHA-1"):
                    hashlib.sha1(test_data).digest()
                elif algorithm.startswith("SHA-512"):
                    hashlib.sha512(test_data).digest()
                else:
                    # Default to SHA-256
                    hashlib.sha256(test_data).digest()

        # Benchmark the hashing function
        return self.benchmark_function(
            func=hash_func,
            benchmark_type=BenchmarkType.HASH,
            algorithm=algorithm,
            data_size=data_size,
            iterations=iterations,
            measure_memory=True
        )

    def benchmark_key_generation(self,
                               algorithm: str,
                               key_size: int = 3072,
                               iterations: int = 5) -> BenchmarkResult:
        """
        Benchmark key generation performance for a specific algorithm and key size.

        Args:
            algorithm: Key generation algorithm to benchmark (e.g., "RSA", "ECC")
            key_size: Key size in bits
            iterations: Number of iterations to perform

        Returns:
            BenchmarkResult containing the performance metrics
        """
        if self.key_manager is None:
            raise ValueError("Key manager is required for key generation benchmarks")

        # Define the key generation function
        def keygen_func():
            if algorithm.lower() in ["rsa", "ecc"]:
                # Generate asymmetric key pair
                self.key_manager.generate_asymmetric_keypair(
                    algorithm=algorithm,
                    key_size=key_size
                )
            else:
                # Generate symmetric key
                self.key_manager.generate_symmetric_key(
                    algorithm=algorithm,
                    key_size=key_size
                )

        # Benchmark the key generation function
        return self.benchmark_function(
            func=keygen_func,
            benchmark_type=BenchmarkType.KEY_GENERATION,
            algorithm=f"{algorithm}-{key_size}",
            data_size=key_size,  # Use key size as data size
            iterations=iterations,
            measure_memory=True
        )

    def benchmark_signature(self,
                          algorithm: str,
                          data_size: int,
                          key_size: int = 3072,
                          iterations: int = 10) -> BenchmarkResult:
        """
        Benchmark signature performance for a specific algorithm and data size.

        Args:
            algorithm: Signature algorithm to benchmark
            data_size: Size of the test data in bytes
            key_size: Key size in bits
            iterations: Number of iterations to perform

        Returns:
            BenchmarkResult containing the performance metrics
        """
        if self.signature_engine is None or self.key_manager is None:
            raise ValueError("Signature engine and key manager are required for signature benchmarks")

        # Generate a key pair for signing
        public_key, private_key = self.key_manager.generate_asymmetric_keypair(
            algorithm=algorithm,
            key_size=key_size
        )

        # Generate test data
        test_data = self._generate_test_data(data_size)

        # Define the signature function
        def sign_func():
            self.signature_engine.sign(
                data=test_data,
                private_key=private_key,
                algorithm=algorithm
            )

        # Benchmark the signature function
        return self.benchmark_function(
            func=sign_func,
            benchmark_type=BenchmarkType.SIGNATURE,
            algorithm=algorithm,
            data_size=data_size,
            iterations=iterations,
            measure_memory=True
        )

    def benchmark_verification(self,
                             algorithm: str,
                             data_size: int,
                             key_size: int = 3072,
                             iterations: int = 10) -> BenchmarkResult:
        """
        Benchmark signature verification performance for a specific algorithm and data size.

        Args:
            algorithm: Signature algorithm to benchmark
            data_size: Size of the test data in bytes
            key_size: Key size in bits
            iterations: Number of iterations to perform

        Returns:
            BenchmarkResult containing the performance metrics
        """
        if self.signature_engine is None or self.key_manager is None:
            raise ValueError("Signature engine and key manager are required for verification benchmarks")

        # Generate a key pair for signing
        public_key, private_key = self.key_manager.generate_asymmetric_keypair(
            algorithm=algorithm,
            key_size=key_size
        )

        # Generate test data
        test_data = self._generate_test_data(data_size)

        # Create a signature to verify
        signature_result = self.signature_engine.sign(
            data=test_data,
            private_key=private_key,
            algorithm=algorithm
        )

        # Define the verification function
        def verify_func():
            self.signature_engine.verify(
                data=test_data,
                signature_result=signature_result,
                public_key=public_key
            )

        # Benchmark the verification function
        return self.benchmark_function(
            func=verify_func,
            benchmark_type=BenchmarkType.VERIFICATION,
            algorithm=algorithm,
            data_size=data_size,
            iterations=iterations,
            measure_memory=True
        )

    def benchmark_parallel_encryption(self,
                                    algorithm: str,
                                    data_size: int,
                                    key_size: int = 256,
                                    num_operations: int = 10,
                                    iterations: int = 5) -> BenchmarkResult:
        """
        Benchmark parallel encryption performance.

        Args:
            algorithm: Encryption algorithm to benchmark
            data_size: Size of each test data item in bytes
            key_size: Key size in bits
            num_operations: Number of parallel operations to perform
            iterations: Number of benchmark iterations

        Returns:
            BenchmarkResult containing the performance metrics
        """
        if self.encryption_engine is None:
            raise ValueError("Encryption engine is required for encryption benchmarks")

        # Generate a random key
        key = os.urandom(key_size // 8)

        # Generate test data items
        test_data_items = [self._generate_test_data(data_size) for _ in range(num_operations)]

        # Define the encryption function for a single item
        def encrypt_item(data):
            return self.encryption_engine.encrypt(data=data, key=key, algorithm=algorithm)

        # Define the parallel encryption function
        def parallel_encrypt_func():
            self.parallel_processor.map(encrypt_item, test_data_items)

        # Benchmark the parallel encryption function
        return self.benchmark_function(
            func=parallel_encrypt_func,
            benchmark_type=BenchmarkType.ENCRYPTION,
            algorithm=f"{algorithm}-parallel-{num_operations}",
            data_size=data_size * num_operations,  # Total data size
            iterations=iterations,
            measure_memory=True
        )

    def _generate_test_data(self, size: int) -> bytes:
        """Generate random test data of the specified size."""
        return os.urandom(size)

    def generate_report(self,
                       title: str = "Cryptographic Performance Report",
                       filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate a comprehensive performance report.

        Args:
            title: Title of the report
            filters: Optional filters to apply to the results

        Returns:
            Dictionary containing the report data
        """
        filters = filters or {}

        # Apply filters to get relevant results
        filtered_results = self.get_results(
            benchmark_type=filters.get("benchmark_type"),
            algorithm=filters.get("algorithm"),
            min_data_size=filters.get("min_data_size"),
            max_data_size=filters.get("max_data_size")
        )

        # Group results by benchmark type and algorithm
        grouped_results = {}
        for result in filtered_results:
            key = (result.benchmark_type.value, result.algorithm)
            if key not in grouped_results:
                grouped_results[key] = []
            grouped_results[key].append(result)

        # Generate report data
        report = {
            "title": title,
            "generated_at": time.time(),
            "filters": filters,
            "total_results": len(filtered_results),
            "benchmark_types": {},
            "algorithms": {},
            "data_sizes": {},
            "comparisons": []
        }

        # Count by benchmark type
        for result in filtered_results:
            benchmark_type = result.benchmark_type.value
            if benchmark_type not in report["benchmark_types"]:
                report["benchmark_types"][benchmark_type] = 0
            report["benchmark_types"][benchmark_type] += 1

        # Count by algorithm
        for result in filtered_results:
            algorithm = result.algorithm
            if algorithm not in report["algorithms"]:
                report["algorithms"][algorithm] = 0
            report["algorithms"][algorithm] += 1

        # Count by data size
        for result in filtered_results:
            data_size = result.data_size
            if data_size not in report["data_sizes"]:
                report["data_sizes"][data_size] = 0
            report["data_sizes"][data_size] += 1

        # Generate comparisons
        for (benchmark_type, algorithm), results in grouped_results.items():
            # Sort results by data size
            results.sort(key=lambda r: r.data_size)

            # Extract data for comparison
            comparison = {
                "benchmark_type": benchmark_type,
                "algorithm": algorithm,
                "data_points": [
                    {
                        "data_size": result.data_size,
                        "mean_time": result.mean_time,
                        "throughput": result.throughput
                    }
                    for result in results
                ]
            }

            report["comparisons"].append(comparison)

        return report


class ChunkProcessor:
    """
    Utility class for processing large files in chunks.

    This class provides methods for efficiently processing large files
    by breaking them into manageable chunks and processing them sequentially
    or in parallel.
    """

    def __init__(self, chunk_size: int = 1024 * 1024):
        """
        Initialize the chunk processor.

        Args:
            chunk_size: Size of each chunk in bytes (default: 1 MB)
        """
        self.chunk_size = chunk_size

    def process_file(self,
                    input_file: str,
                    output_file: str,
                    process_func: Callable[[bytes], bytes],
                    parallel: bool = False,
                    max_workers: Optional[int] = None) -> int:
        """
        Process a file in chunks.

        Args:
            input_file: Path to the input file
            output_file: Path to the output file
            process_func: Function to process each chunk
            parallel: Whether to process chunks in parallel
            max_workers: Maximum number of worker threads or processes

        Returns:
            Total number of bytes processed
        """
        # Get the file size
        file_size = os.path.getsize(input_file)

        # Calculate the number of chunks
        num_chunks = (file_size + self.chunk_size - 1) // self.chunk_size

        # Create the output directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

        # Process the file
        if parallel and num_chunks > 1:
            return self._process_file_parallel(
                input_file, output_file, process_func, num_chunks, max_workers
            )
        else:
            return self._process_file_sequential(
                input_file, output_file, process_func
            )

    def _process_file_sequential(self,
                               input_file: str,
                               output_file: str,
                               process_func: Callable[[bytes], bytes]) -> int:
        """
        Process a file sequentially in chunks.

        Args:
            input_file: Path to the input file
            output_file: Path to the output file
            process_func: Function to process each chunk

        Returns:
            Total number of bytes processed
        """
        total_bytes = 0

        with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
            while True:
                chunk = in_file.read(self.chunk_size)
                if not chunk:
                    break

                processed_chunk = process_func(chunk)
                out_file.write(processed_chunk)

                total_bytes += len(chunk)

        return total_bytes

    def _process_file_parallel(self,
                             input_file: str,
                             output_file: str,
                             process_func: Callable[[bytes], bytes],
                             num_chunks: int,
                             max_workers: Optional[int] = None) -> int:
        """
        Process a file in parallel using multiple workers.

        Args:
            input_file: Path to the input file
            output_file: Path to the output file
            process_func: Function to process each chunk
            num_chunks: Number of chunks to process
            max_workers: Maximum number of worker threads or processes

        Returns:
            Total number of bytes processed
        """
        # Determine the number of workers
        if max_workers is None:
            max_workers = min(num_chunks, multiprocessing.cpu_count())

        # Create a temporary directory for chunk files
        temp_dir = os.path.join(os.path.dirname(output_file), ".chunks")
        os.makedirs(temp_dir, exist_ok=True)

        try:
            # Split the input file into chunks
            chunk_files = self._split_file(input_file, temp_dir, num_chunks)

            # Process chunks in parallel
            processed_chunks = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit tasks for each chunk
                future_to_chunk = {
                    executor.submit(self._process_chunk, chunk_file, process_func): i
                    for i, chunk_file in enumerate(chunk_files)
                }

                # Collect results as they complete
                for future in concurrent.futures.as_completed(future_to_chunk):
                    chunk_index = future_to_chunk[future]
                    try:
                        processed_chunk = future.result()
                        processed_chunks.append((chunk_index, processed_chunk))
                    except Exception as e:
                        logger.error(f"Error processing chunk {chunk_index}: {str(e)}")
                        raise

            # Sort processed chunks by index
            processed_chunks.sort(key=lambda x: x[0])

            # Write processed chunks to the output file
            total_bytes = 0
            with open(output_file, 'wb') as out_file:
                for _, chunk_data in processed_chunks:
                    out_file.write(chunk_data)
                    total_bytes += len(chunk_data)

            return total_bytes

        finally:
            # Clean up temporary files
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.warning(f"Error cleaning up temporary files: {str(e)}")

    def _split_file(self,
                   input_file: str,
                   temp_dir: str,
                   num_chunks: int) -> List[str]:
        """
        Split a file into chunks.

        Args:
            input_file: Path to the input file
            temp_dir: Directory to store chunk files
            num_chunks: Number of chunks to create

        Returns:
            List of paths to chunk files
        """
        chunk_files = []

        with open(input_file, 'rb') as in_file:
            for i in range(num_chunks):
                chunk_file = os.path.join(temp_dir, f"chunk_{i}.bin")
                chunk_files.append(chunk_file)

                with open(chunk_file, 'wb') as out_file:
                    chunk = in_file.read(self.chunk_size)
                    out_file.write(chunk)

        return chunk_files

    def _process_chunk(self,
                      chunk_file: str,
                      process_func: Callable[[bytes], bytes]) -> bytes:
        """
        Process a single chunk file.

        Args:
            chunk_file: Path to the chunk file
            process_func: Function to process the chunk

        Returns:
            Processed chunk data
        """
        with open(chunk_file, 'rb') as f:
            chunk = f.read()

        return process_func(chunk)


class ParallelProcessor:
    """
    Utility class for parallel processing of cryptographic operations.

    This class provides methods for efficiently processing multiple items
    in parallel using thread or process pools.
    """

    def __init__(self,
                max_workers: Optional[int] = None,
                use_processes: bool = False):
        """
        Initialize the parallel processor.

        Args:
            max_workers: Maximum number of worker threads or processes
            use_processes: Whether to use processes instead of threads
        """
        self.max_workers = max_workers or multiprocessing.cpu_count()
        self.use_processes = use_processes

    def map(self,
           func: Callable,
           items: List[Any],
           *args,
           **kwargs) -> List[Any]:
        """
        Apply a function to each item in parallel.

        Args:
            func: Function to apply to each item
            items: List of items to process
            *args: Additional positional arguments to pass to the function
            **kwargs: Additional keyword arguments to pass to the function

        Returns:
            List of results
        """
        # Choose the appropriate executor
        executor_class = (
            concurrent.futures.ProcessPoolExecutor if self.use_processes
            else concurrent.futures.ThreadPoolExecutor
        )

        # Process items in parallel
        with executor_class(max_workers=self.max_workers) as executor:
            # Create a wrapper function that includes the additional arguments
            def wrapper(item):
                return func(item, *args, **kwargs)

            # Map the function to all items
            results = list(executor.map(wrapper, items))

        return results

    def process_batch(self,
                     func: Callable,
                     items: List[Any],
                     batch_size: int = 100,
                     *args,
                     **kwargs) -> List[Any]:
        """
        Process items in batches to avoid memory issues with large datasets.

        Args:
            func: Function to apply to each item
            items: List of items to process
            batch_size: Number of items to process in each batch
            *args: Additional positional arguments to pass to the function
            **kwargs: Additional keyword arguments to pass to the function

        Returns:
            List of results
        """
        results = []

        # Process items in batches
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            batch_results = self.map(func, batch, *args, **kwargs)
            results.extend(batch_results)

        return results
