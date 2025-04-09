"""
Script for testing the benchmarking module.

This script demonstrates how to use the CryptoBenchmark class to measure
the performance of various cryptographic operations.
"""

import os
import sys
import time
import json
import logging
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.crypto_benchmark import (
    BenchmarkType,
    BenchmarkResult,
    CryptoBenchmark,
    ChunkProcessor,
    ParallelProcessor
)
from src.core.encryption import EncryptionEngine
from src.core.signatures import SignatureEngine
from src.core.key_management import KeyManager


def main():
    """Run benchmark tests."""
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("benchmark_test")
    
    # Create a results directory
    results_dir = Path(__file__).parent.parent / "benchmark_results"
    results_dir.mkdir(exist_ok=True)
    
    # Initialize the components needed for benchmarking
    key_manager = KeyManager(
        keys_file=str(results_dir / "test_keys.json")
    )
    
    encryption_engine = EncryptionEngine(key_manager=key_manager)
    signature_engine = SignatureEngine(key_manager=key_manager)
    
    # Initialize the benchmark system
    benchmark = CryptoBenchmark(
        results_file=str(results_dir / "benchmark_results.json"),
        warm_up_iterations=2,
        encryption_engine=encryption_engine,
        signature_engine=signature_engine,
        key_manager=key_manager
    )
    
    # Run encryption benchmarks
    logger.info("Running encryption benchmarks...")
    encryption_algorithms = ["AES-GCM", "ChaCha20-Poly1305"]
    data_sizes = [1024, 10 * 1024, 100 * 1024]  # 1KB, 10KB, 100KB
    
    for algorithm in encryption_algorithms:
        for data_size in data_sizes:
            try:
                logger.info(f"Benchmarking {algorithm} encryption with {data_size} bytes...")
                result = benchmark.benchmark_encryption(
                    algorithm=algorithm,
                    data_size=data_size,
                    iterations=5
                )
                logger.info(f"Result: {result}")
            except Exception as e:
                logger.error(f"Error benchmarking {algorithm} encryption: {str(e)}")
    
    # Run decryption benchmarks
    logger.info("Running decryption benchmarks...")
    for algorithm in encryption_algorithms:
        for data_size in data_sizes:
            try:
                logger.info(f"Benchmarking {algorithm} decryption with {data_size} bytes...")
                result = benchmark.benchmark_decryption(
                    algorithm=algorithm,
                    data_size=data_size,
                    iterations=5
                )
                logger.info(f"Result: {result}")
            except Exception as e:
                logger.error(f"Error benchmarking {algorithm} decryption: {str(e)}")
    
    # Run hashing benchmarks
    logger.info("Running hashing benchmarks...")
    hash_algorithms = ["SHA-256", "SHA3-256", "SHA-512"]
    
    for algorithm in hash_algorithms:
        for data_size in data_sizes:
            try:
                logger.info(f"Benchmarking {algorithm} hashing with {data_size} bytes...")
                result = benchmark.benchmark_hashing(
                    algorithm=algorithm,
                    data_size=data_size,
                    iterations=5
                )
                logger.info(f"Result: {result}")
            except Exception as e:
                logger.error(f"Error benchmarking {algorithm} hashing: {str(e)}")
    
    # Run key generation benchmarks
    logger.info("Running key generation benchmarks...")
    key_algorithms = ["AES", "RSA"]
    key_sizes = [256, 2048]  # Different sizes for symmetric and asymmetric
    
    for algorithm in key_algorithms:
        key_size = key_sizes[0] if algorithm == "AES" else key_sizes[1]
        try:
            logger.info(f"Benchmarking {algorithm} key generation with {key_size} bits...")
            result = benchmark.benchmark_key_generation(
                algorithm=algorithm,
                key_size=key_size,
                iterations=3
            )
            logger.info(f"Result: {result}")
        except Exception as e:
            logger.error(f"Error benchmarking {algorithm} key generation: {str(e)}")
    
    # Run parallel encryption benchmark
    logger.info("Running parallel encryption benchmark...")
    try:
        logger.info("Benchmarking parallel AES-GCM encryption...")
        result = benchmark.benchmark_parallel_encryption(
            algorithm="AES-GCM",
            data_size=10 * 1024,  # 10KB per operation
            num_operations=10,    # 10 parallel operations
            iterations=3
        )
        logger.info(f"Result: {result}")
    except Exception as e:
        logger.error(f"Error benchmarking parallel encryption: {str(e)}")
    
    # Generate a report
    logger.info("Generating benchmark report...")
    report = benchmark.generate_report(
        title="Cryptographic Performance Report"
    )
    
    # Save the report
    report_file = results_dir / "benchmark_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Benchmark report saved to {report_file}")
    
    # Print a summary
    logger.info("Benchmark Summary:")
    logger.info(f"Total benchmarks: {len(benchmark.results)}")
    logger.info(f"Algorithms tested: {', '.join(report['algorithms'].keys())}")
    logger.info(f"Benchmark types: {', '.join(report['benchmark_types'].keys())}")
    
    # Find the fastest algorithm for each operation
    for benchmark_type in report["benchmark_types"]:
        fastest_algorithm = None
        fastest_time = float('inf')
        
        for result in benchmark.results:
            if result.benchmark_type.value == benchmark_type:
                if result.mean_time < fastest_time:
                    fastest_time = result.mean_time
                    fastest_algorithm = result.algorithm
        
        if fastest_algorithm:
            logger.info(f"Fastest algorithm for {benchmark_type}: {fastest_algorithm} ({fastest_time*1000:.2f} ms)")


if __name__ == "__main__":
    main()
