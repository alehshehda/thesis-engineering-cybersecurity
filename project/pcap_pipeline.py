#!/usr/bin/env python3
"""
PCAP Rotation and FlowMeter Conversion Pipeline
Captures network traffic with tcpdump, rotates PCAP files every minute,
converts to CSV using CICFlowMeter or NexusFlowMeter, and manages retention policies.

Filters traffic to/from LAN VM (192.168.10.50) for ML attack detection.

Requirements:
- Python 3.8+
- pip install watchdog
- pip install cicflowmeter (https://pypi.org/project/cicflowmeter/)
- pip install nexusflowmeter (from GitHub: https://github.com/Collgamer0008/NexusFlowMeter)
- Root privileges (run as root user)

Usage:
    python3 pcap_pipeline.py cicflowmeter
    python3 pcap_pipeline.py nexusflowmeter
"""

import os
import sys
import time
import signal
import logging
import subprocess
import threading
import shutil
import re
from pathlib import Path
from datetime import datetime, timedelta
from queue import Queue, Empty

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ============================================================================
# FLOWMETER TYPE ENUM
# ============================================================================

class FlowMeterType:
    """Supported flow meter types."""
    CIC = "cicflowmeter"
    NEXUS = "nexusflowmeter"

    @staticmethod
    def from_string(value: str):
        """Convert string to FlowMeterType, case-insensitive."""
        value_lower = value.lower()
        if value_lower == FlowMeterType.CIC:
            return FlowMeterType.CIC
        elif value_lower == FlowMeterType.NEXUS:
            return FlowMeterType.NEXUS
        else:
            return None


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Pipeline configuration based on user requirements."""

    # Network capture settings
    INTERFACE = "enp1s0"
    # BPF filter: capture only traffic where 192.168.10.50 is source OR destination
    BPF_FILTER = "host 192.168.10.50"
    SNAPLEN = 128  # Bytes - captures L3/L4 headers (matches CIC dataset standard)

    # File storage paths (root user)
    PCAP_DIR = "/root/Thesis/project/pcaps"
    CSV_DIR = "/root/Thesis/project/csv"
    LOG_DIR = "/root/Thesis/project/log"
    REPORTS_DIR = "/root/Thesis/project/reports"  # NexusFlowMeter reports directory

    # Rotation and retention
    ROTATION_SECONDS = 60  # 1 minute per PCAP
    # NOTE: tcpdump -G rotation starts from first packet, not script start time.
    # With sparse traffic, rotation times may drift from expected boundaries.
    PCAP_RETENTION_MINUTES = 30  # Delete PCAPs older than 30 minutes
    CSV_RETENTION_MINUTES = 30  # Delete CSVs older than 30 minutes
    REPORTS_RETENTION_MINUTES = 30  # Delete reports older than 30 minutes

    # File completion check
    FILE_STABILITY_DELAY = 2  # Seconds to wait to ensure file is complete
    FILE_SIZE_CHECK_INTERVAL = 0.5  # Seconds between file size checks

    # Processing settings
    MAX_CONVERSION_RETRIES = 3
    CONVERSION_RETRY_DELAY = 5  # Seconds between retries
    WORKER_THREADS = 2  # Number of parallel conversion workers
    CONVERSION_TIMEOUT = 300  # 5 minutes timeout for conversion

    # FlowMeter selection (set at runtime)
    FLOWMETER_TYPE = None  # Will be set to FlowMeterType.CIC or FlowMeterType.NEXUS

    # CICFlowMeter settings
    CIC_VERBOSE = False  # Enable verbose logging in CICFlowMeter
    CIC_FIELDS = None  # Comma-separated fields to include (None = all fields)

    # NexusFlowMeter settings
    FLOW_TIMEOUT = 60  # Flow timeout in seconds (default for NexusFlowMeter)
    MAX_WORKERS = 4  # Max workers for NexusFlowMeter chunk processing
    OUTPUT_FORMAT = "csv"  # Output format: csv, json, xlsx
    VERBOSE_NEXUS = False  # Enable verbose logging in NexusFlowMeter

    # Disk space monitoring
    MIN_FREE_SPACE_MB = 1000  # Minimum free disk space (1GB)
    SPACE_CHECK_INTERVAL = 60  # Check disk space every 60 seconds

    # Logging
    LOG_LEVEL = logging.INFO
    LOG_FORMAT = "[%(asctime)s] %(levelname)s - %(name)s - %(message)s"
    LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging():
    """Initialize logging to console and file."""
    try:
        Path(Config.LOG_DIR).mkdir(parents=True, exist_ok=True)
    except PermissionError:
        print(f"Error: Cannot create log directory {Config.LOG_DIR}. Check permissions.")
        sys.exit(1)

    log_file = Path(Config.LOG_DIR) / f"pipeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    # Create logger
    logger = logging.getLogger("PcapPipeline")
    logger.setLevel(Config.LOG_LEVEL)

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(Config.LOG_LEVEL)
    console_formatter = logging.Formatter(
        Config.LOG_FORMAT,
        datefmt=Config.LOG_DATE_FORMAT
    )
    console_handler.setFormatter(console_formatter)

    # File handler
    try:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(Config.LOG_LEVEL)
        file_handler.setFormatter(console_formatter)
        logger.addHandler(file_handler)
    except PermissionError:
        print(f"Warning: Cannot create log file {log_file}. Logging to console only.")

    logger.addHandler(console_handler)
    return logger


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def check_disk_space(directory):
    """Check available disk space in directory."""
    try:
        stat = shutil.disk_usage(directory)
        free_mb = stat.free / (1024 * 1024)
        return free_mb
    except Exception as e:
        # Use module-level logger if available, else print
        if 'logger' in globals():
            logger.error(f"Failed to check disk space for {directory}: {e}")
        return None


def validate_network_interface(interface):
    """Validate that network interface exists and has safe name format."""
    # Validate format first (alphanumeric, dash, underscore, colon only)
    if not re.match(r'^[a-zA-Z0-9_:-]+$', interface):
        if 'logger' in globals():
            logger.error(f"Invalid interface name format: {interface}")
        return False

    # Check if interface exists
    try:
        result = subprocess.run(
            ["ip", "link", "show", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception as e:
        if 'logger' in globals():
            logger.error(f"Failed to validate interface {interface}: {e}")
        return False


def print_usage():
    """Print usage information and exit."""
    print("=" * 70)
    print("PCAP Rotation and FlowMeter Conversion Pipeline")
    print("=" * 70)
    print()
    print("Usage:")
    print("    python3 pcap_pipeline.py <flowmeter>")
    print()
    print("Arguments:")
    print("    flowmeter    The flow meter to use for PCAP to CSV conversion")
    print("                 Options: cicflowmeter, nexusflowmeter")
    print()
    print("Examples:")
    print("    python3 pcap_pipeline.py cicflowmeter")
    print("    python3 pcap_pipeline.py nexusflowmeter")
    print()
    print("Description:")
    print("    - cicflowmeter:   Uses CICFlowMeter (80 features)")
    print("    - nexusflowmeter: Uses NexusFlowMeter (34 features)")
    print()
    print("=" * 70)
    sys.exit(1)


# ============================================================================
# DISK SPACE MONITOR
# ============================================================================

class DiskSpaceMonitor:
    """Monitors disk space and warns when low."""

    def __init__(self, logger_instance):
        self.logger = logger_instance
        self.running = False
        self.thread = None

    def start(self):
        """Start monitoring disk space."""
        if self.running:
            self.logger.warning("Disk space monitor is already running")
            return

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        self.logger.info("Disk space monitor started")

    def stop(self):
        """Stop monitoring."""
        if not self.running:
            return

        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        self.logger.info("Disk space monitor stopped")

    def _monitor_loop(self):
        """Monitor disk space periodically."""
        while self.running:
            try:
                # Check PCAP directory
                free_mb = check_disk_space(Config.PCAP_DIR)
                if free_mb is not None and free_mb < Config.MIN_FREE_SPACE_MB:
                    self.logger.warning(
                        f"Low disk space: {free_mb:.2f} MB free "
                        f"(minimum: {Config.MIN_FREE_SPACE_MB} MB)"
                    )

                # Sleep in small increments to allow quick shutdown
                for _ in range(Config.SPACE_CHECK_INTERVAL):
                    if not self.running:
                        break
                    time.sleep(1)
            except Exception as e:
                self.logger.error(f"Disk space monitor error: {e}")


# ============================================================================
# PCAP CLEANUP MANAGER
# ============================================================================

class CleanupManager:
    """Manages automatic deletion of old PCAP and CSV files."""

    def __init__(self, logger_instance):
        self.logger = logger_instance
        self.running = False
        self.thread = None

    def start(self):
        """Start the cleanup thread."""
        if self.running:
            self.logger.warning("Cleanup manager is already running")
            return

        self.running = True
        self.thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.thread.start()
        self.logger.info("Cleanup manager started")

    def stop(self):
        """Stop the cleanup thread."""
        if not self.running:
            return

        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                self.logger.warning("Cleanup thread did not stop gracefully")
        self.logger.info("Cleanup manager stopped")

    def _cleanup_loop(self):
        """Periodic cleanup of old files."""
        while self.running:
            try:
                self._cleanup_old_files(
                    Config.PCAP_DIR,
                    "*.pcap",
                    Config.PCAP_RETENTION_MINUTES
                )
                self._cleanup_old_files(
                    Config.CSV_DIR,
                    "*.csv",
                    Config.CSV_RETENTION_MINUTES
                )
                # Cleanup reports (NexusFlowMeter only)
                if Config.FLOWMETER_TYPE == FlowMeterType.NEXUS:
                    self._cleanup_old_files(
                        Config.REPORTS_DIR,
                        "*.txt",
                        Config.REPORTS_RETENTION_MINUTES
                    )
                # Check every 30 seconds
                for _ in range(30):
                    if not self.running:
                        break
                    time.sleep(1)
            except Exception as e:
                self.logger.error(f"Cleanup error: {e}")

    def _cleanup_old_files(self, directory, pattern, retention_minutes):
        """Delete files older than retention period."""
        try:
            directory_path = Path(directory)
            if not directory_path.exists():
                return

            cutoff_time = datetime.now() - timedelta(minutes=retention_minutes)
            deleted_count = 0

            for file_path in directory_path.glob(pattern):
                if file_path.is_file():
                    file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_mtime < cutoff_time:
                        try:
                            file_path.unlink()
                            deleted_count += 1
                            self.logger.debug(f"Deleted old file: {file_path.name}")
                        except OSError as e:
                            self.logger.error(f"Failed to delete {file_path}: {e}")

            if deleted_count > 0:
                self.logger.info(
                    f"Cleaned up {deleted_count} files from {directory} "
                    f"(older than {retention_minutes} minutes)"
                )
        except Exception as e:
            self.logger.error(f"Error cleaning {directory}: {e}")


# ============================================================================
# FLOWMETER CONVERTER (ABSTRACT BASE)
# ============================================================================

class FlowMeterConverter:
    """Base class for PCAP to CSV conversion using flow meters."""

    def __init__(self, conversion_queue, logger_instance):
        self.queue = conversion_queue
        self.logger = logger_instance
        self.workers = []
        self.running = False
        self.failed_conversions = set()  # Track failed files

    def start(self):
        """Start conversion worker threads."""
        if self.running:
            self.logger.warning(f"{self.get_name()} converter is already running")
            return

        self.running = True
        self.workers = []

        for i in range(Config.WORKER_THREADS):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"ConversionWorker-{i}",
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        self.logger.info(f"Started {Config.WORKER_THREADS} {self.get_name()} conversion workers")

    def stop(self):
        """Stop all conversion workers."""
        if not self.running:
            return

        self.running = False

        # Send stop signals (None) to all workers - use non-blocking put
        for _ in self.workers:
            try:
                self.queue.put(None, block=False)
            except:
                # Queue might be full, workers will stop via self.running flag
                pass

        # Wait for workers with proper timeout
        for worker in self.workers:
            if worker.is_alive():
                worker.join(timeout=10)
                if worker.is_alive():
                    self.logger.warning(f"Worker {worker.name} did not stop gracefully")

        self.workers = []
        self.logger.info(f"All {self.get_name()} conversion workers stopped")

    def _worker_loop(self):
        """Worker thread main loop."""
        while self.running:
            pcap_path = None
            try:
                pcap_path = self.queue.get(timeout=1)
            except Empty:
                continue

            try:
                # None is stop signal
                if pcap_path is None:
                    break

                self._convert_with_retry(pcap_path)

            except Exception as e:
                self.logger.error(f"Worker error processing {pcap_path}: {e}")
            finally:
                # Always mark task as done after successful get()
                if pcap_path is not None:
                    try:
                        self.queue.task_done()
                    except ValueError:
                        pass

    def _convert_with_retry(self, pcap_path):
        """Convert PCAP to CSV with retry logic."""
        pcap_file = Path(pcap_path)

        if not pcap_file.exists():
            self.logger.warning(f"PCAP file not found: {pcap_path}")
            return

        # Check if already failed
        if str(pcap_file) in self.failed_conversions:
            self.logger.debug(f"Skipping previously failed conversion: {pcap_file.name}")
            return

        # Generate CSV output path
        csv_filename = pcap_file.stem + ".csv"
        csv_path = Path(Config.CSV_DIR) / csv_filename

        # Ensure CSV directory exists
        csv_path.parent.mkdir(parents=True, exist_ok=True)

        # Retry loop
        for attempt in range(1, Config.MAX_CONVERSION_RETRIES + 1):
            try:
                self.logger.info(
                    f"Converting {pcap_file.name} with {self.get_name()} "
                    f"(attempt {attempt}/{Config.MAX_CONVERSION_RETRIES})"
                )

                # Use flow meter CLI
                success = self._run_flowmeter(str(pcap_file), str(csv_path))

                if success and csv_path.exists() and csv_path.stat().st_size > 0:
                    self.logger.info(f"Successfully converted: {pcap_file.name} -> {csv_filename}")
                    return
                else:
                    self.logger.warning(
                        f"{self.get_name()} conversion failed or produced empty output "
                        f"(attempt {attempt}/{Config.MAX_CONVERSION_RETRIES})"
                    )

            except FileNotFoundError:
                self.logger.error(
                    f"{self.get_name()} not found. Please install: "
                    f"{self.get_install_command()}"
                )
                self.failed_conversions.add(str(pcap_file))
                return
            except Exception as e:
                self.logger.error(f"{self.get_name()} conversion error (attempt {attempt}): {e}")

            # Wait before retry (except on last attempt)
            if attempt < Config.MAX_CONVERSION_RETRIES:
                self.logger.debug(f"Waiting {Config.CONVERSION_RETRY_DELAY}s before retry...")
                time.sleep(Config.CONVERSION_RETRY_DELAY)

        # All retries failed
        self.logger.error(
            f"Failed to convert {pcap_file.name} with {self.get_name()} after "
            f"{Config.MAX_CONVERSION_RETRIES} attempts. Skipping this file."
        )
        self.failed_conversions.add(str(pcap_file))

    def _run_flowmeter(self, pcap_path, csv_path):
        """Run flow meter CLI - to be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement _run_flowmeter")

    def get_name(self):
        """Get the name of the flow meter - to be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement get_name")

    def get_install_command(self):
        """Get installation command - to be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement get_install_command")


# ============================================================================
# CICFLOWMETER CONVERTER
# ============================================================================

class CICFlowMeterConverter(FlowMeterConverter):
    """Handles PCAP to CSV conversion using CICFlowMeter."""

    def get_name(self):
        return "CICFlowMeter"

    def get_install_command(self):
        return "pip install cicflowmeter"

    def _run_flowmeter(self, pcap_path, csv_path):
        """
        Run CICFlowMeter CLI to convert PCAP to CSV.

        Command: cicflowmeter -f <pcap_file> -c <csv_file>
        """
        process = None
        try:
            # Build command
            cmd = [
                "cicflowmeter",
                "-f", pcap_path,
                "-c", csv_path
            ]

            # Add optional parameters
            if Config.CIC_VERBOSE:
                cmd.append("-v")

            if Config.CIC_FIELDS:
                cmd.extend(["--fields", Config.CIC_FIELDS])

            self.logger.debug(f"Running: {' '.join(cmd)}")

            # Run conversion with Popen for better timeout control
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            try:
                stdout, stderr = process.communicate(timeout=Config.CONVERSION_TIMEOUT)

                if process.returncode == 0:
                    self.logger.debug(f"CICFlowMeter stdout: {stdout[:200]}")
                    return True
                else:
                    self.logger.error(f"CICFlowMeter stderr: {stderr}")
                    return False

            except subprocess.TimeoutExpired:
                # Kill the timed-out process
                process.kill()
                process.wait()
                self.logger.error(
                    f"CICFlowMeter processing timeout "
                    f"({Config.CONVERSION_TIMEOUT}s) for {Path(pcap_path).name}. Process killed."
                )
                return False

        except FileNotFoundError:
            raise  # Re-raise to be caught by caller
        except Exception as e:
            if process and process.poll() is None:
                process.kill()
                process.wait()
            self.logger.error(f"Error running CICFlowMeter: {e}")
            return False


# ============================================================================
# NEXUSFLOWMETER CONVERTER
# ============================================================================

class NexusFlowMeterConverter(FlowMeterConverter):
    """Handles PCAP to CSV conversion using NexusFlowMeter."""

    def get_name(self):
        return "NexusFlowMeter"

    def get_install_command(self):
        return "pip install nexusflowmeter"

    def _run_flowmeter(self, pcap_path, csv_path):
        """
        Run NexusFlowMeter CLI to convert PCAP to CSV.

        Command: nexusflowmeter <pcap_file> <output_file> [--report-dir <dir>]
        """
        process = None
        try:
            # Ensure reports directory exists
            try:
                Path(Config.REPORTS_DIR).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.logger.warning(f"Could not create reports directory: {e}. Continuing without reports.")

            # Build command
            cmd = [
                "nexusflowmeter",
                pcap_path,
                csv_path
            ]

            # Add optional parameters
            if Config.FLOW_TIMEOUT != 60:  # Only add if non-default
                cmd.extend(["--flow-timeout", str(Config.FLOW_TIMEOUT)])

            if Config.MAX_WORKERS != 4:  # Only add if non-default
                cmd.extend(["--max-workers", str(Config.MAX_WORKERS)])

            if Config.OUTPUT_FORMAT != "csv":
                cmd.extend(["--output-format", Config.OUTPUT_FORMAT])

            # Add report directory (NexusFlowMeter-specific feature)
            if Path(Config.REPORTS_DIR).exists():
                cmd.extend(["--report-dir", Config.REPORTS_DIR])
                self.logger.debug(f"Reports will be saved to: {Config.REPORTS_DIR}")

            if Config.VERBOSE_NEXUS:
                cmd.append("--verbose")

            self.logger.debug(f"Running: {' '.join(cmd)}")

            # Run conversion with Popen for better timeout control
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            try:
                stdout, stderr = process.communicate(timeout=Config.CONVERSION_TIMEOUT)

                if process.returncode == 0:
                    self.logger.debug(f"NexusFlowMeter stdout: {stdout[:200]}")
                    return True
                else:
                    self.logger.error(f"NexusFlowMeter stderr: {stderr}")
                    return False

            except subprocess.TimeoutExpired:
                # Kill the timed-out process
                process.kill()
                process.wait()
                self.logger.error(
                    f"NexusFlowMeter processing timeout "
                    f"({Config.CONVERSION_TIMEOUT}s) for {Path(pcap_path).name}. Process killed."
                )
                return False

        except FileNotFoundError:
            raise  # Re-raise to be caught by caller
        except Exception as e:
            if process and process.poll() is None:
                process.kill()
                process.wait()
            self.logger.error(f"Error running NexusFlowMeter: {e}")
            return False


# ============================================================================
# PCAP FILE WATCHER
# ============================================================================

class PcapFileHandler(FileSystemEventHandler):
    """Watches for new PCAP files and queues them for conversion."""

    def __init__(self, conversion_queue, logger_instance):
        super().__init__()
        self.queue = conversion_queue
        self.logger = logger_instance
        self.processed_files = set()
        self.lock = threading.Lock()

    def on_created(self, event):
        """Handle new file creation events."""
        if event.is_directory:
            return

        file_path = event.src_path

        # Only process .pcap files
        if not file_path.endswith(".pcap"):
            return

        # When a new PCAP file is created by tcpdump's -G rotation,
        # it means the previous file is complete
        self.logger.debug(f"New PCAP file detected: {Path(file_path).name}")
        self._process_completed_files()

    def _process_completed_files(self):
        """Process completed PCAP files when a new one is created."""
        try:
            with self.lock:
                pcap_dir = Path(Config.PCAP_DIR)

                # Get all PCAP files in directory, sorted by creation time
                pcap_files = sorted(
                    [f for f in pcap_dir.glob("*.pcap") if f.is_file()],
                    key=lambda x: x.stat().st_ctime
                )

                if len(pcap_files) < 2:
                    # Need at least 2 files: one complete, one being written
                    return

                # Process all files except the newest one (which is being written)
                # Only process files not yet queued
                unprocessed_files = [
                    f for f in pcap_files[:-1]
                    if str(f) not in self.processed_files
                ]

                for pcap_file in unprocessed_files:
                    # Verify file is complete and stable
                    if self._is_file_complete(pcap_file):
                        file_path_str = str(pcap_file)
                        self.processed_files.add(file_path_str)
                        self.logger.info(f"Queuing PCAP for conversion: {pcap_file.name}")

                        try:
                            self.queue.put(file_path_str, timeout=5)
                        except Exception as e:
                            self.logger.error(f"Failed to queue PCAP: {file_path_str} - {e}")
                            self.processed_files.discard(file_path_str)
                    else:
                        self.logger.debug(f"File not stable yet: {pcap_file.name}")

        except Exception as e:
            self.logger.error(f"Error processing completed files: {e}")

    def _is_file_complete(self, file_path):
        """
        Check if file is complete (not being written to).

        Note: For tcpdump with -G rotation, files remain open until rotation.
        This check is mainly for startup processing of existing files.
        During runtime, rely on rotation events (new file creation) to detect completion.
        """
        try:
            # Check if file size is stable
            initial_size = file_path.stat().st_size
            time.sleep(Config.FILE_SIZE_CHECK_INTERVAL)
            final_size = file_path.stat().st_size

            # File is complete if size hasn't changed
            is_stable = initial_size == final_size
            is_not_empty = final_size > 0

            return is_stable and is_not_empty

        except (OSError, FileNotFoundError) as e:
            self.logger.debug(f"File check error for {file_path}: {e}")
            return False


class PcapWatcher:
    """File system watcher for PCAP directory."""

    def __init__(self, conversion_queue, logger_instance):
        self.logger = logger_instance
        self.observer = Observer()
        self.handler = PcapFileHandler(conversion_queue, logger_instance)
        self.running = False

    def start(self):
        """Start watching PCAP directory."""
        if self.running:
            self.logger.warning("PCAP watcher is already running")
            return

        try:
            # Ensure directory exists
            Path(Config.PCAP_DIR).mkdir(parents=True, exist_ok=True)

            # Process any existing completed PCAP files first
            self._process_existing_files()

            self.observer.schedule(
                self.handler,
                Config.PCAP_DIR,
                recursive=False
            )
            self.observer.start()
            self.running = True
            self.logger.info(f"Started watching directory: {Config.PCAP_DIR}")
        except Exception as e:
            self.logger.error(f"Failed to start PCAP watcher: {e}")
            raise

    def _process_existing_files(self):
        """Process any existing PCAP files on startup (except the newest)."""
        try:
            with self.handler.lock:  # Thread-safe access to processed_files
                pcap_dir = Path(Config.PCAP_DIR)
                if not pcap_dir.exists():
                    return

                # Get all existing PCAP files, sorted by creation time
                pcap_files = sorted(
                    [f for f in pcap_dir.glob("*.pcap") if f.is_file()],
                    key=lambda x: x.stat().st_ctime
                )

                if not pcap_files:
                    self.logger.info("No existing PCAP files to process")
                    return

                # Process all except the newest file (which might still be active)
                files_to_process = pcap_files[:-1] if len(pcap_files) > 1 else []

                for pcap_file in files_to_process:
                    if self.handler._is_file_complete(pcap_file):
                        file_path_str = str(pcap_file)
                        self.handler.processed_files.add(file_path_str)
                        self.logger.info(f"Processing existing PCAP: {pcap_file.name}")

                        try:
                            self.handler.queue.put(file_path_str, timeout=5)
                        except Exception as e:
                            self.logger.error(f"Failed to queue existing PCAP: {file_path_str} - {e}")

        except Exception as e:
            self.logger.error(f"Error processing existing files: {e}")

    def stop(self):
        """Stop watching."""
        if not self.running:
            return

        self.running = False
        try:
            self.observer.stop()
            self.observer.join(timeout=5)
            if self.observer.is_alive():
                self.logger.warning("File watcher did not stop gracefully")
        except Exception as e:
            self.logger.error(f"Error stopping file watcher: {e}")
        self.logger.info("Stopped file watcher")


# ============================================================================
# TCPDUMP CAPTURE MANAGER
# ============================================================================

class TcpdumpCapture:
    """Manages tcpdump subprocess for packet capture."""

    def __init__(self, logger_instance):
        self.logger = logger_instance
        self.process = None

    def start(self):
        """Start tcpdump with rotation."""
        if self.process and self.process.poll() is None:
            self.logger.warning("tcpdump is already running")
            return

        # Validate network interface
        if not validate_network_interface(Config.INTERFACE):
            raise RuntimeError(
                f"Network interface '{Config.INTERFACE}' not found or invalid. "
                f"Use 'ip link show' to list available interfaces."
            )

        # Ensure output directory exists
        try:
            Path(Config.PCAP_DIR).mkdir(parents=True, exist_ok=True)
        except PermissionError:
            self.logger.error(f"Cannot create PCAP directory {Config.PCAP_DIR}. Check permissions.")
            raise

        # Build output filename pattern with timestamp
        output_pattern = str(Path(Config.PCAP_DIR) / "capture_%Y%m%d_%H%M%S.pcap")

        # Build tcpdump command
        cmd = [
            "tcpdump",
            "-i", Config.INTERFACE,
            "-s", str(Config.SNAPLEN),
            "-G", str(Config.ROTATION_SECONDS),
            "-w", output_pattern,
            "-Z", "root",
        ]

        # Add BPF filter
        if Config.BPF_FILTER:
            cmd.append(Config.BPF_FILTER)

        try:
            self.logger.info(f"Starting tcpdump on interface {Config.INTERFACE}")
            self.logger.info(f"BPF Filter: {Config.BPF_FILTER}")
            self.logger.info(f"Rotation interval: {Config.ROTATION_SECONDS}s (from first packet)")
            self.logger.debug(f"Command: {' '.join(cmd)}")

            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid
            )

            self.logger.info(f"tcpdump started (PID: {self.process.pid})")

            # Check if process started successfully
            time.sleep(2)
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                raise RuntimeError(f"tcpdump failed to start: {stderr}")

        except FileNotFoundError:
            self.logger.error("tcpdump not found. Please install: apt install tcpdump")
            raise
        except PermissionError:
            self.logger.error("Permission denied. Run as root user or with sudo")
            raise
        except Exception as e:
            self.logger.error(f"Failed to start tcpdump: {e}")
            raise

    def stop(self):
        """Stop tcpdump gracefully and ensure complete file writes."""
        if not self.process or self.process.poll() is not None:
            return

        self.logger.info("Stopping tcpdump...")
        try:
            # Send SIGTERM for graceful shutdown
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)

            try:
                # Wait for tcpdump to complete gracefully
                self.process.wait(timeout=10)
                self.logger.info("tcpdump stopped gracefully")
            except subprocess.TimeoutExpired:
                self.logger.warning("tcpdump did not stop gracefully, forcing kill")
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                self.process.wait()

        except ProcessLookupError:
            self.logger.info("tcpdump process already terminated")
        except Exception as e:
            self.logger.error(f"Error stopping tcpdump: {e}")
        finally:
            self.process = None


# ============================================================================
# MAIN PIPELINE ORCHESTRATOR
# ============================================================================

class PcapPipeline:
    """Main pipeline orchestrator."""

    def __init__(self, flowmeter_type, logger_instance):
        self.logger = logger_instance
        self.conversion_queue = Queue()
        self.tcpdump = TcpdumpCapture(logger_instance)
        self.watcher = PcapWatcher(self.conversion_queue, logger_instance)

        # Create appropriate converter based on flowmeter type
        if flowmeter_type == FlowMeterType.CIC:
            self.converter = CICFlowMeterConverter(self.conversion_queue, logger_instance)
            self.flowmeter_name = "CICFlowMeter"
            self.feature_count = "80 features"
        elif flowmeter_type == FlowMeterType.NEXUS:
            self.converter = NexusFlowMeterConverter(self.conversion_queue, logger_instance)
            self.flowmeter_name = "NexusFlowMeter"
            self.feature_count = "34 features"
        else:
            raise ValueError(f"Invalid flowmeter type: {flowmeter_type}")

        self.cleanup_manager = CleanupManager(logger_instance)
        self.disk_monitor = DiskSpaceMonitor(logger_instance)
        self.running = False

    def start(self):
        """Start all pipeline components."""
        if self.running:
            self.logger.warning("Pipeline is already running")
            return

        self.logger.info("=" * 70)
        self.logger.info(f"Starting PCAP Rotation and {self.flowmeter_name} Pipeline")
        self.logger.info("=" * 70)
        self.logger.info(f"Interface: {Config.INTERFACE}")
        self.logger.info(f"BPF Filter: {Config.BPF_FILTER}")
        self.logger.info(f"Snaplen: {Config.SNAPLEN} bytes (CIC dataset standard)")
        self.logger.info(f"Target: LAN VM (192.168.10.50)")
        self.logger.info(f"PCAP Directory: {Config.PCAP_DIR}")
        self.logger.info(f"CSV Directory: {Config.CSV_DIR}")
        
        # Show reports directory only for NexusFlowMeter
        if Config.FLOWMETER_TYPE == FlowMeterType.NEXUS:
            self.logger.info(f"Reports Directory: {Config.REPORTS_DIR}")
        
        self.logger.info(f"Rotation Interval: {Config.ROTATION_SECONDS} seconds")
        self.logger.info(f"PCAP Retention: {Config.PCAP_RETENTION_MINUTES} minutes")
        self.logger.info(f"CSV Retention: {Config.CSV_RETENTION_MINUTES} minutes")
        
        # Show reports retention only for NexusFlowMeter
        if Config.FLOWMETER_TYPE == FlowMeterType.NEXUS:
            self.logger.info(f"Reports Retention: {Config.REPORTS_RETENTION_MINUTES} minutes")
        
        self.logger.info(f"Flow Processor: {self.flowmeter_name} ({self.feature_count})")
        self.logger.info(f"Conversion Retries: {Config.MAX_CONVERSION_RETRIES}")
        self.logger.info("=" * 70)

        try:
            # Ensure directories exist
            Path(Config.PCAP_DIR).mkdir(parents=True, exist_ok=True)
            Path(Config.CSV_DIR).mkdir(parents=True, exist_ok=True)
            
            # Create reports directory only for NexusFlowMeter
            if Config.FLOWMETER_TYPE == FlowMeterType.NEXUS:
                try:
                    Path(Config.REPORTS_DIR).mkdir(parents=True, exist_ok=True)
                    self.logger.info(f"Reports directory ready: {Config.REPORTS_DIR}")
                except Exception as e:
                    self.logger.warning(f"Could not create reports directory: {e}. Continuing without reports.")

            # Check initial disk space
            free_mb = check_disk_space(Config.PCAP_DIR)
            if free_mb is not None:
                self.logger.info(f"Available disk space: {free_mb:.2f} MB")
                if free_mb < Config.MIN_FREE_SPACE_MB:
                    self.logger.warning(f"Low disk space warning!")

            # Start components in order
            self.disk_monitor.start()
            self.cleanup_manager.start()
            self.converter.start()
            self.watcher.start()
            self.tcpdump.start()

            self.running = True
            self.logger.info("Pipeline started successfully")
            self.logger.info("Architecture: Capture 1 min → Stop → Start next → Convert previous")
            self.logger.info("Press Ctrl+C to stop")

        except Exception as e:
            self.logger.error(f"Failed to start pipeline: {e}")
            self.stop()
            raise

    def stop(self):
        """Stop all pipeline components gracefully."""
        if not self.running:
            return

        self.logger.info("Stopping pipeline...")
        self.running = False

        # Stop tcpdump first and wait for it to complete
        self.tcpdump.stop()

        # Wait for file to be fully written after tcpdump stops
        self.logger.info(f"Waiting {Config.FILE_STABILITY_DELAY}s for file stability...")
        time.sleep(Config.FILE_STABILITY_DELAY)

        # Process the final PCAP file
        self._process_final_pcap()

        # Stop file watcher
        self.watcher.stop()

        # Wait for pending conversions with timeout
        self.logger.info("Waiting for pending conversions...")
        pending_timeout = 60  # 60 seconds
        start_time = time.time()

        while not self.conversion_queue.empty():
            if (time.time() - start_time) > pending_timeout:
                self.logger.warning("Timeout waiting for conversions, stopping anyway")
                break
            time.sleep(0.5)

        # Stop converter and cleanup
        self.converter.stop()
        self.cleanup_manager.stop()
        self.disk_monitor.stop()

        self.logger.info("Pipeline stopped")

        # Report failed conversions
        if self.converter.failed_conversions:
            self.logger.warning(
                f"Failed to convert {len(self.converter.failed_conversions)} "
                f"PCAP files after {Config.MAX_CONVERSION_RETRIES} retries"
            )

    def _process_final_pcap(self):
        """Process the final PCAP file that was being written when stopped."""
        try:
            with self.watcher.handler.lock:  # Thread-safe access
                pcap_dir = Path(Config.PCAP_DIR)
                if not pcap_dir.exists():
                    return

                # Get all PCAP files, sorted by creation time (newest last)
                pcap_files = sorted(
                    [f for f in pcap_dir.glob("*.pcap") if f.is_file()],
                    key=lambda x: x.stat().st_ctime
                )

                if not pcap_files:
                    return

                # The last file is the one that was being written
                final_pcap = pcap_files[-1]

                # Check if it's not already processed and has content
                if (str(final_pcap) not in self.watcher.handler.processed_files and
                        final_pcap.stat().st_size > 0):

                    self.logger.info(f"Processing final PCAP file: {final_pcap.name}")
                    try:
                        self.conversion_queue.put(str(final_pcap), timeout=5)
                        self.watcher.handler.processed_files.add(str(final_pcap))
                    except Exception as e:
                        self.logger.error(f"Failed to queue final PCAP: {final_pcap} - {e}")

        except Exception as e:
            self.logger.error(f"Error processing final PCAP: {e}")

    def run(self):
        """Run the pipeline (blocking)."""
        try:
            self.start()

            # Keep main thread alive
            while self.running:
                time.sleep(1)

                # Check if tcpdump is still running
                if self.tcpdump.process and self.tcpdump.process.poll() is not None:
                    self.logger.error("tcpdump process died unexpectedly")
                    stdout, stderr = self.tcpdump.process.communicate()
                    if stderr:
                        self.logger.error(f"tcpdump error: {stderr}")
                    break

        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        except Exception as e:
            self.logger.error(f"Pipeline error: {e}", exc_info=True)
        finally:
            self.stop()


# ============================================================================
# SIGNAL HANDLERS
# ============================================================================

pipeline = None


def signal_handler(sig, frame):
    """Handle termination signals."""
    if pipeline and pipeline.logger:
        pipeline.logger.info(f"Received signal {sig}")
    if pipeline:
        pipeline.stop()
    sys.exit(0)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point."""
    global pipeline

    # Check if running as root
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root user")
        print("Usage: sudo python3 pcap_pipeline.py <flowmeter>")
        sys.exit(1)

    # Parse command line arguments
    if len(sys.argv) != 2:
        print_usage()

    flowmeter_arg = sys.argv[1]
    flowmeter_type = FlowMeterType.from_string(flowmeter_arg)

    if flowmeter_type is None:
        print(f"Error: Invalid flowmeter type '{flowmeter_arg}'")
        print()
        print_usage()

    # Set flowmeter type in config
    Config.FLOWMETER_TYPE = flowmeter_type

    # Setup logging after argument parsing
    logger = setup_logging()

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Create and run pipeline
        pipeline = PcapPipeline(flowmeter_type, logger)
        pipeline.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
