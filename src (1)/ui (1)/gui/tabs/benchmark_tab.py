"""
Benchmark Tab for the GUI.
"""

import os
import time
import json
import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QRadioButton, QFileDialog, QLineEdit, QProgressBar, QTextEdit,
    QGroupBox, QFormLayout, QCheckBox, QMessageBox, QListWidget,
    QListWidgetItem, QDialog, QDialogButtonBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QTabWidget, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor

from ....core.crypto_benchmark import (
    BenchmarkType,
    BenchmarkResult,
    CryptoBenchmark
)


class BenchmarkWorker(QThread):
    """Worker thread for running benchmarks."""
    
    # Signal emitted when a benchmark is completed
    benchmark_completed = pyqtSignal(BenchmarkResult)
    
    # Signal emitted when all benchmarks are completed
    all_completed = pyqtSignal()
    
    # Signal emitted when an error occurs
    error_occurred = pyqtSignal(str)
    
    def __init__(self, benchmark_func, **kwargs):
        """Initialize the worker thread."""
        super().__init__()
        self.benchmark_func = benchmark_func
        self.kwargs = kwargs
    
    def run(self):
        """Run the benchmark."""
        try:
            result = self.benchmark_func(**self.kwargs)
            self.benchmark_completed.emit(result)
            self.all_completed.emit()
        except Exception as e:
            self.error_occurred.emit(str(e))


class BenchmarkTab(QWidget):
    """Tab for running and viewing benchmarks."""
    
    def __init__(self, benchmark: CryptoBenchmark):
        """Initialize the benchmark tab."""
        super().__init__()
        
        self.benchmark = benchmark
        self.current_worker = None
        
        # Set up the UI
        self.setup_ui()
        
        # Refresh the results list
        self.refresh_results()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Create a splitter for resizable sections
        splitter = QSplitter(Qt.Orientation.Vertical)
        main_layout.addWidget(splitter)
        
        # Create the benchmark configuration section
        config_group = QGroupBox("Benchmark Configuration")
        config_layout = QVBoxLayout(config_group)
        
        # Benchmark type selection
        type_form = QFormLayout()
        
        self.benchmark_type_combo = QComboBox()
        for benchmark_type in BenchmarkType:
            self.benchmark_type_combo.addItem(benchmark_type.value, benchmark_type)
        self.benchmark_type_combo.currentIndexChanged.connect(self.update_algorithm_list)
        type_form.addRow("Benchmark Type:", self.benchmark_type_combo)
        
        # Algorithm selection
        self.algorithm_combo = QComboBox()
        type_form.addRow("Algorithm:", self.algorithm_combo)
        
        # Data size
        data_size_layout = QHBoxLayout()
        
        self.data_size_spin = QSpinBox()
        self.data_size_spin.setRange(1, 1000000000)  # 1 byte to 1 GB
        self.data_size_spin.setValue(1024)  # Default to 1 KB
        data_size_layout.addWidget(self.data_size_spin)
        
        self.data_size_unit_combo = QComboBox()
        self.data_size_unit_combo.addItems(["Bytes", "KB", "MB", "GB"])
        self.data_size_unit_combo.setCurrentText("KB")
        data_size_layout.addWidget(self.data_size_unit_combo)
        
        type_form.addRow("Data Size:", data_size_layout)
        
        # Key size (for key generation and signature benchmarks)
        self.key_size_spin = QSpinBox()
        self.key_size_spin.setRange(128, 8192)
        self.key_size_spin.setValue(2048)
        self.key_size_spin.setSingleStep(128)
        type_form.addRow("Key Size (bits):", self.key_size_spin)
        
        # Number of iterations
        self.iterations_spin = QSpinBox()
        self.iterations_spin.setRange(1, 100)
        self.iterations_spin.setValue(5)
        type_form.addRow("Iterations:", self.iterations_spin)
        
        # Use chunks for large files
        self.use_chunks_check = QCheckBox("Process in chunks")
        self.use_chunks_check.setChecked(False)
        type_form.addRow("Large Files:", self.use_chunks_check)
        
        # Chunk size
        chunk_size_layout = QHBoxLayout()
        
        self.chunk_size_spin = QSpinBox()
        self.chunk_size_spin.setRange(1, 1000000)
        self.chunk_size_spin.setValue(1)
        chunk_size_layout.addWidget(self.chunk_size_spin)
        
        self.chunk_size_unit_combo = QComboBox()
        self.chunk_size_unit_combo.addItems(["KB", "MB"])
        self.chunk_size_unit_combo.setCurrentText("MB")
        chunk_size_layout.addWidget(self.chunk_size_unit_combo)
        
        type_form.addRow("Chunk Size:", chunk_size_layout)
        
        # Add the form to the layout
        config_layout.addLayout(type_form)
        
        # Benchmark buttons
        buttons_layout = QHBoxLayout()
        
        self.run_button = QPushButton("Run Benchmark")
        self.run_button.clicked.connect(self.run_benchmark)
        buttons_layout.addWidget(self.run_button)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.cancel_benchmark)
        self.cancel_button.setEnabled(False)
        buttons_layout.addWidget(self.cancel_button)
        
        config_layout.addLayout(buttons_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        config_layout.addWidget(self.progress_bar)
        
        # Add the config group to the splitter
        splitter.addWidget(config_group)
        
        # Create the results section
        results_group = QGroupBox("Benchmark Results")
        results_layout = QVBoxLayout(results_group)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels([
            "Type", "Algorithm", "Data Size", "Mean Time (ms)", 
            "Throughput (MB/s)", "Iterations", "Timestamp"
        ])
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.results_table.currentItemChanged.connect(self.result_selected)
        results_layout.addWidget(self.results_table)
        
        # Results buttons
        results_buttons = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_results)
        results_buttons.addWidget(self.refresh_button)
        
        self.export_button = QPushButton("Export Report")
        self.export_button.clicked.connect(self.export_report)
        results_buttons.addWidget(self.export_button)
        
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        results_buttons.addWidget(self.clear_button)
        
        results_layout.addLayout(results_buttons)
        
        # Add the results group to the splitter
        splitter.addWidget(results_group)
        
        # Create the details section
        details_group = QGroupBox("Result Details")
        details_layout = QVBoxLayout(details_group)
        
        # Details text
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        
        # Add the details group to the splitter
        splitter.addWidget(details_group)
        
        # Set the initial splitter sizes
        splitter.setSizes([200, 300, 200])
        
        # Update the algorithm list
        self.update_algorithm_list()
    
    def update_algorithm_list(self):
        """Update the algorithm list based on the selected benchmark type."""
        self.algorithm_combo.clear()
        
        benchmark_type = self.benchmark_type_combo.currentData()
        if benchmark_type == BenchmarkType.ENCRYPTION or benchmark_type == BenchmarkType.DECRYPTION:
            self.algorithm_combo.addItems(["AES-GCM", "ChaCha20-Poly1305"])
            self.key_size_spin.setEnabled(True)
            self.key_size_spin.setRange(128, 256)
            self.key_size_spin.setValue(256)
            self.key_size_spin.setSingleStep(64)
        elif benchmark_type == BenchmarkType.HASH:
            self.algorithm_combo.addItems(["SHA-256", "SHA3-256", "SHA-512", "MD5", "SHA-1"])
            self.key_size_spin.setEnabled(False)
        elif benchmark_type == BenchmarkType.KEY_GENERATION:
            self.algorithm_combo.addItems(["RSA", "ECC", "AES"])
            self.key_size_spin.setEnabled(True)
            self.key_size_spin.setRange(128, 4096)
            self.key_size_spin.setValue(2048)
            self.key_size_spin.setSingleStep(128)
        elif benchmark_type == BenchmarkType.SIGNATURE or benchmark_type == BenchmarkType.VERIFICATION:
            self.algorithm_combo.addItems(["RSA", "ECDSA"])
            self.key_size_spin.setEnabled(True)
            self.key_size_spin.setRange(1024, 4096)
            self.key_size_spin.setValue(2048)
            self.key_size_spin.setSingleStep(128)
    
    def get_data_size(self) -> int:
        """Get the data size in bytes."""
        size = self.data_size_spin.value()
        unit = self.data_size_unit_combo.currentText()
        
        if unit == "KB":
            size *= 1024
        elif unit == "MB":
            size *= 1024 * 1024
        elif unit == "GB":
            size *= 1024 * 1024 * 1024
        
        return size
    
    def get_chunk_size(self) -> int:
        """Get the chunk size in bytes."""
        size = self.chunk_size_spin.value()
        unit = self.chunk_size_unit_combo.currentText()
        
        if unit == "KB":
            size *= 1024
        elif unit == "MB":
            size *= 1024 * 1024
        
        return size
    
    def run_benchmark(self):
        """Run the selected benchmark."""
        # Get the benchmark parameters
        benchmark_type = self.benchmark_type_combo.currentData()
        algorithm = self.algorithm_combo.currentText()
        data_size = self.get_data_size()
        key_size = self.key_size_spin.value()
        iterations = self.iterations_spin.value()
        use_chunks = self.use_chunks_check.isChecked()
        chunk_size = self.get_chunk_size()
        
        # Disable the run button and enable the cancel button
        self.run_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress_bar.setValue(0)
        
        # Create a worker thread for the benchmark
        if benchmark_type == BenchmarkType.ENCRYPTION:
            self.current_worker = BenchmarkWorker(
                self.benchmark.benchmark_encryption,
                algorithm=algorithm,
                data_size=data_size,
                key_size=key_size,
                iterations=iterations,
                use_chunks=use_chunks,
                chunk_size=chunk_size
            )
        elif benchmark_type == BenchmarkType.DECRYPTION:
            self.current_worker = BenchmarkWorker(
                self.benchmark.benchmark_decryption,
                algorithm=algorithm,
                data_size=data_size,
                key_size=key_size,
                iterations=iterations,
                use_chunks=use_chunks,
                chunk_size=chunk_size
            )
        elif benchmark_type == BenchmarkType.HASH:
            self.current_worker = BenchmarkWorker(
                self.benchmark.benchmark_hashing,
                algorithm=algorithm,
                data_size=data_size,
                iterations=iterations,
                use_chunks=use_chunks,
                chunk_size=chunk_size
            )
        elif benchmark_type == BenchmarkType.KEY_GENERATION:
            self.current_worker = BenchmarkWorker(
                self.benchmark.benchmark_key_generation,
                algorithm=algorithm,
                key_size=key_size,
                iterations=iterations
            )
        elif benchmark_type == BenchmarkType.SIGNATURE:
            self.current_worker = BenchmarkWorker(
                self.benchmark.benchmark_signature,
                algorithm=algorithm,
                data_size=data_size,
                key_size=key_size,
                iterations=iterations
            )
        elif benchmark_type == BenchmarkType.VERIFICATION:
            self.current_worker = BenchmarkWorker(
                self.benchmark.benchmark_verification,
                algorithm=algorithm,
                data_size=data_size,
                key_size=key_size,
                iterations=iterations
            )
        else:
            QMessageBox.warning(
                self,
                "Unsupported Benchmark",
                f"Benchmark type {benchmark_type.value} is not supported yet."
            )
            self.run_button.setEnabled(True)
            self.cancel_button.setEnabled(False)
            return
        
        # Connect signals
        self.current_worker.benchmark_completed.connect(self.benchmark_completed)
        self.current_worker.all_completed.connect(self.all_benchmarks_completed)
        self.current_worker.error_occurred.connect(self.benchmark_error)
        
        # Start the worker
        self.current_worker.start()
        
        # Update the progress bar
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
    
    def cancel_benchmark(self):
        """Cancel the current benchmark."""
        if self.current_worker and self.current_worker.isRunning():
            self.current_worker.terminate()
            self.current_worker = None
            
            self.run_button.setEnabled(True)
            self.cancel_button.setEnabled(False)
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            
            QMessageBox.information(
                self,
                "Benchmark Cancelled",
                "The benchmark was cancelled."
            )
    
    def benchmark_completed(self, result: BenchmarkResult):
        """Handle a completed benchmark."""
        # Add the result to the table
        self.add_result_to_table(result)
    
    def all_benchmarks_completed(self):
        """Handle completion of all benchmarks."""
        self.run_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        
        QMessageBox.information(
            self,
            "Benchmark Completed",
            "The benchmark has completed successfully."
        )
    
    def benchmark_error(self, error_message: str):
        """Handle a benchmark error."""
        self.run_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        QMessageBox.critical(
            self,
            "Benchmark Error",
            f"An error occurred during the benchmark: {error_message}"
        )
    
    def refresh_results(self):
        """Refresh the results table."""
        # Clear the table
        self.results_table.setRowCount(0)
        
        # Add all results to the table
        for result in self.benchmark.results:
            self.add_result_to_table(result)
        
        # Resize columns to content
        self.results_table.resizeColumnsToContents()
    
    def add_result_to_table(self, result: BenchmarkResult):
        """Add a benchmark result to the table."""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Type
        type_item = QTableWidgetItem(result.benchmark_type.value)
        self.results_table.setItem(row, 0, type_item)
        
        # Algorithm
        algorithm_item = QTableWidgetItem(result.algorithm)
        self.results_table.setItem(row, 1, algorithm_item)
        
        # Data size
        if result.data_size < 1024:
            data_size_str = f"{result.data_size} B"
        elif result.data_size < 1024 * 1024:
            data_size_str = f"{result.data_size / 1024:.2f} KB"
        elif result.data_size < 1024 * 1024 * 1024:
            data_size_str = f"{result.data_size / (1024 * 1024):.2f} MB"
        else:
            data_size_str = f"{result.data_size / (1024 * 1024 * 1024):.2f} GB"
        
        data_size_item = QTableWidgetItem(data_size_str)
        self.results_table.setItem(row, 2, data_size_item)
        
        # Mean time
        mean_time_item = QTableWidgetItem(f"{result.mean_time * 1000:.2f}")
        self.results_table.setItem(row, 3, mean_time_item)
        
        # Throughput
        throughput_mb = result.throughput / (1024 * 1024)
        throughput_item = QTableWidgetItem(f"{throughput_mb:.2f}")
        self.results_table.setItem(row, 4, throughput_item)
        
        # Iterations
        iterations_item = QTableWidgetItem(str(result.iterations))
        self.results_table.setItem(row, 5, iterations_item)
        
        # Timestamp
        timestamp = datetime.datetime.fromtimestamp(result.timestamp)
        timestamp_item = QTableWidgetItem(timestamp.strftime("%Y-%m-%d %H:%M:%S"))
        self.results_table.setItem(row, 6, timestamp_item)
        
        # Store the result in the first item
        type_item.setData(Qt.ItemDataRole.UserRole, result)
    
    def result_selected(self, current, previous):
        """Handle result selection."""
        if current is None:
            self.details_text.clear()
            return
        
        # Get the result
        result = current.data(Qt.ItemDataRole.UserRole)
        if not result:
            row = current.row()
            result = self.results_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        
        if not result:
            self.details_text.clear()
            return
        
        # Format the result details
        details = f"<h2>Benchmark Details</h2>"
        details += f"<p><b>Type:</b> {result.benchmark_type.value}</p>"
        details += f"<p><b>Algorithm:</b> {result.algorithm}</p>"
        
        # Data size
        if result.data_size < 1024:
            data_size_str = f"{result.data_size} bytes"
        elif result.data_size < 1024 * 1024:
            data_size_str = f"{result.data_size / 1024:.2f} KB"
        elif result.data_size < 1024 * 1024 * 1024:
            data_size_str = f"{result.data_size / (1024 * 1024):.2f} MB"
        else:
            data_size_str = f"{result.data_size / (1024 * 1024 * 1024):.2f} GB"
        
        details += f"<p><b>Data Size:</b> {data_size_str}</p>"
        details += f"<p><b>Iterations:</b> {result.iterations}</p>"
        details += f"<p><b>Timestamp:</b> {datetime.datetime.fromtimestamp(result.timestamp).strftime('%Y-%m-%d %H:%M:%S')}</p>"
        
        # Performance metrics
        details += f"<h3>Performance Metrics</h3>"
        details += f"<p><b>Mean Time:</b> {result.mean_time * 1000:.2f} ms</p>"
        details += f"<p><b>Median Time:</b> {result.median_time * 1000:.2f} ms</p>"
        details += f"<p><b>Min Time:</b> {result.min_time * 1000:.2f} ms</p>"
        details += f"<p><b>Max Time:</b> {result.max_time * 1000:.2f} ms</p>"
        details += f"<p><b>Standard Deviation:</b> {result.std_dev * 1000:.2f} ms</p>"
        
        throughput_mb = result.throughput / (1024 * 1024)
        details += f"<p><b>Throughput:</b> {throughput_mb:.2f} MB/s</p>"
        
        # Memory usage
        if result.memory_usage:
            mean_memory = statistics.mean(result.memory_usage)
            if mean_memory < 1024:
                memory_str = f"{mean_memory:.2f} bytes"
            elif mean_memory < 1024 * 1024:
                memory_str = f"{mean_memory / 1024:.2f} KB"
            elif mean_memory < 1024 * 1024 * 1024:
                memory_str = f"{mean_memory / (1024 * 1024):.2f} MB"
            else:
                memory_str = f"{mean_memory / (1024 * 1024 * 1024):.2f} GB"
            
            details += f"<p><b>Mean Memory Usage:</b> {memory_str}</p>"
        
        # Metadata
        if result.metadata:
            details += f"<h3>Metadata</h3>"
            for key, value in result.metadata.items():
                details += f"<p><b>{key}:</b> {value}</p>"
        
        # Set the details text
        self.details_text.setHtml(details)
    
    def export_report(self):
        """Export a benchmark report."""
        # Ask for the file path
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Benchmark Report",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        # Generate the report
        report = self.benchmark.generate_report(
            title="Cryptographic Performance Report"
        )
        
        # Save the report
        try:
            with open(file_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            QMessageBox.information(
                self,
                "Export Successful",
                f"Benchmark report exported to {file_path}"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Failed to export benchmark report: {str(e)}"
            )
    
    def clear_results(self):
        """Clear all benchmark results."""
        # Ask for confirmation
        reply = QMessageBox.question(
            self,
            "Clear Results",
            "Are you sure you want to clear all benchmark results?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Clear the results
        self.benchmark.results = []
        
        # Save the empty results
        if self.benchmark.results_file:
            try:
                # Create the directory if it doesn't exist
                os.makedirs(os.path.dirname(os.path.abspath(self.benchmark.results_file)), exist_ok=True)
                
                # Write empty results to file
                with open(self.benchmark.results_file, 'w') as f:
                    json.dump([], f)
            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Save Failed",
                    f"Failed to save empty results: {str(e)}"
                )
        
        # Refresh the table
        self.refresh_results()
        
        # Clear the details
        self.details_text.clear()
