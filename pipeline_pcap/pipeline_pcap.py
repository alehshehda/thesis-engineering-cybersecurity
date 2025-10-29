#!/usr/bin/env python3

"""
PCAP Rotation and Java CICFlowMeter Conversion Pipeline

Captures network traffic with tcpdump, rotates PCAP files every minute,
converts to CSV using Java CICFlowMeter, and manages retention policies.

Requirements:
- Python 3.8+
- pip install watchdog
- Java CICFlowMeter installed at /root/CICFlowMeter/
- cic_cmd.sh script in pipeline directory
- Root privileges

Usage:
    sudo python3 pipeline_pcap.py
"""

import os
import sys
import time
import json
import signal
import logging
import subprocess
import threading
from pathlib import Path
from datetime import datetime, timedelta
from queue import Queue, Empty
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from logging.handlers import RotatingFileHandler


# ==================== Configuration Loader ====================

class ConfigLoader:
    """Load and validate pipeline configuration from JSON"""

    def __init__(self, config_path='pipeline_config.json'):
        self.config_path = config_path
        self.config = self.load_config()

    def load_config(self):
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            logging.info(f"Configuration loaded from {self.config_path}")
            return config
        except FileNotFoundError:
            logging.error(f"Config file not found: {self.config_path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in config file: {e}")
            sys.exit(1)

    def get(self, *keys, default=None):
        """Get nested config value using dot notation"""
        value = self.config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
            if value is None:
                return default
        return value


# ==================== Java CICFlowMeter Converter ====================

class JavaCICFlowMeterConverter:
    """Converts PCAP files to CSV using Java CICFlowMeter via cic_cmd.sh"""

    def __init__(self, config):
        self.config = config
        self.timeout = config.get('processing', 'conversion_timeout', default=300)
        self.cic_cmd_script = config.get('java_cicflowmeter', 'cic_cmd_script',
                                         default='/root/Thesis/pipeline_pcap/cic_cmd.sh')
        self.cic_log_dir = config.get('paths', 'cic_log_dir',
                                      default='/root/Thesis/pipeline_pcap/log/cicflowmeter_log')

        # Create CIC log directory
        os.makedirs(self.cic_log_dir, exist_ok=True)

        # Verify script exists and is executable
        if not os.path.exists(self.cic_cmd_script):
            raise FileNotFoundError(f"CICFlowMeter script not found: {self.cic_cmd_script}")
        if not os.access(self.cic_cmd_script, os.X_OK):
            raise PermissionError(f"CICFlowMeter script not executable: {self.cic_cmd_script}")

        logging.info("Java CICFlowMeter converter initialized")
        logging.info(f"Script: {self.cic_cmd_script}")
        logging.info(f"CIC logs: {self.cic_log_dir}")
        logging.info(f"Timeout: {self.timeout}s")

    def _validate_pcap(self, pcap_path):
        """Validate PCAP file before conversion"""
        try:
            # Check file exists
            if not os.path.exists(pcap_path):
                return False, "File not found"

            # Check minimum size (empty PCAP header is ~24 bytes)
            file_size = os.path.getsize(pcap_path)
            if file_size < 24:
                return False, "File too small"

            # Check file is not being modified
            initial_size = file_size
            time.sleep(0.5)
            current_size = os.path.getsize(pcap_path)
            if current_size != initial_size:
                return False, "File still being written"

            return True, "Valid"
        except Exception as e:
            return False, str(e)

    def convert(self, pcap_path, output_dir):
        """
        Convert PCAP to CSV using cic_cmd.sh script

        Args:
            pcap_path: Input PCAP file path
            output_dir: Output directory for CSV file

        Returns:
            tuple: (success: bool, output_csv_path: str or None)
        """
        try:
            pcap_name = os.path.basename(pcap_path)
            logging.info(f"Converting {pcap_name} with Java CICFlowMeter")

            # Validate PCAP before conversion
            valid, reason = self._validate_pcap(pcap_path)
            if not valid:
                logging.warning(f"PCAP validation failed for {pcap_name}: {reason}")
                return False, None

            # Call cic_cmd.sh script with log directory parameter
            cmd = [self.cic_cmd_script, pcap_path, output_dir, self.cic_log_dir]
            start_time = time.time()

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            elapsed = time.time() - start_time

            # Check for errors
            if result.returncode != 0:
                logging.error(f"CICFlowMeter failed with exit code {result.returncode}")
                if result.stderr:
                    logging.error(f"STDERR: {result.stderr.strip()}")
                return False, None

            # Find generated CSV file
            expected_csv = os.path.join(output_dir, f"{pcap_name}_Flow.csv")
            if not os.path.exists(expected_csv):
                logging.error(f"Expected CSV not found: {expected_csv}")
                logging.error(f"Output directory contents: {os.listdir(output_dir)}")
                return False, None

            # Get flow count
            flow_count = "unknown"
            try:
                with open(expected_csv, 'r') as f:
                    flow_count = sum(1 for _ in f) - 1
            except Exception as e:
                logging.warning(f"Could not count flows: {e}")

            logging.info(f"Converted {pcap_name} successfully - {flow_count} flows in {elapsed:.2f}s")
            logging.info(f"Output: {os.path.basename(expected_csv)}")

            return True, expected_csv

        except subprocess.TimeoutExpired:
            logging.error(f"CICFlowMeter timeout after {self.timeout}s for {pcap_name}")
            return False, None
        except Exception as e:
            logging.error(f"CICFlowMeter conversion error: {e}")
            return False, None


# ==================== PCAP File Watcher ====================

class PCAPFileHandler(FileSystemEventHandler):
    """
    Watches for new PCAP files and queues them for conversion
    Only queues files that are completely closed (not the current capture)
    """

    def __init__(self, pcap_queue, config):
        self.pcap_queue = pcap_queue
        self.config = config
        self.processing_delay = config.get('processing', 'processing_delay_seconds', default=2)
        self.file_close_wait = config.get('processing', 'file_close_wait_seconds', default=5)
        self.processed_files = set()
        self.pending_files = {}  # Store files waiting for next rotation
        self.lock = threading.Lock()

    def on_created(self, event):
        """Handle new PCAP file creation"""
        if event.is_directory:
            return

        # Only process .pcap files
        if not event.src_path.endswith('.pcap'):
            return

        # Avoid duplicate processing
        if event.src_path in self.processed_files:
            return

        with self.lock:
            # When a new PCAP is created, the PREVIOUS one is complete
            # Queue all pending files for conversion with safety check
            current_time = time.time()

            for pending_file, timestamp in list(self.pending_files.items()):
                # Ensure file has been closed (wait configured seconds after creation)
                if current_time - timestamp >= self.file_close_wait:
                    if os.path.exists(pending_file):
                        # Double-check file is not being written
                        initial_size = os.path.getsize(pending_file)
                        time.sleep(1)
                        if os.path.getsize(pending_file) == initial_size:
                            self.pcap_queue.put(pending_file)
                            self.processed_files.add(pending_file)
                            logging.info(f"Queued PCAP for conversion: {os.path.basename(pending_file)}")
                            del self.pending_files[pending_file]
                        else:
                            logging.debug(f"File still being written, waiting: {os.path.basename(pending_file)}")

            # Add the new file to pending (it's being written now)
            self.pending_files[event.src_path] = current_time
            logging.debug(f"New PCAP detected, will queue after close: {os.path.basename(event.src_path)}")


# ==================== Conversion Worker ====================

class ConversionWorker(threading.Thread):
    """Worker thread that processes PCAP conversion queue"""

    def __init__(self, pcap_queue, converter, csv_dir, max_retries):
        super().__init__(daemon=True)
        self.pcap_queue = pcap_queue
        self.converter = converter
        self.csv_dir = csv_dir
        self.max_retries = max_retries
        self.running = True

    def run(self):
        """Process conversion queue"""
        logging.info("Conversion worker started")

        while self.running:
            try:
                # Get PCAP from queue (timeout to allow checking self.running)
                pcap_path = self.pcap_queue.get(timeout=1)
                pcap_name = os.path.basename(pcap_path)

                # Verify file still exists
                if not os.path.exists(pcap_path):
                    logging.warning(f"PCAP file disappeared: {pcap_name}")
                    self.pcap_queue.task_done()
                    continue

                # Convert with retries
                success = False
                output_csv = None

                for attempt in range(1, self.max_retries + 1):
                    success, output_csv = self.converter.convert(pcap_path, self.csv_dir)

                    if success:
                        break
                    else:
                        if attempt < self.max_retries:
                            wait_time = 2 ** attempt
                            logging.warning(f"Retry {attempt}/{self.max_retries} for {pcap_name} in {wait_time}s")
                            time.sleep(wait_time)

                if not success:
                    logging.error(f"Failed to convert {pcap_name} after {self.max_retries} attempts")

                # Mark task as done
                self.pcap_queue.task_done()

            except Empty:
                continue  # No items in queue, check if still running
            except Exception as e:
                logging.error(f"Worker error: {e}")
                try:
                    self.pcap_queue.task_done()
                except:
                    pass

    def stop(self):
        """Stop worker thread"""
        self.running = False


# ==================== PCAP Rotator ====================

class PCAPRotator(threading.Thread):
    """Manages tcpdump with automatic PCAP rotation"""

    def __init__(self, config):
        super().__init__(daemon=True)
        self.config = config
        self.interface = config.get('capture', 'interface')
        self.bpf_filter = config.get('capture', 'bpf_filter')
        self.snaplen = config.get('capture', 'snaplen', default=128)
        self.rotation_seconds = config.get('capture', 'rotation_seconds', default=60)
        self.pcap_dir = config.get('paths', 'pcap_dir')
        self.tcpdump_process = None
        self.running = False

        # Ensure PCAP directory exists
        os.makedirs(self.pcap_dir, exist_ok=True)

    def run(self):
        """Start tcpdump with rotation"""
        self.running = True

        # Build tcpdump command with rotation
        filename_pattern = os.path.join(
            self.pcap_dir,
            'capture_%Y%m%d_%H%M%S.pcap'
        )

        cmd = [
            'tcpdump',
            '-i', self.interface,
            '-s', str(self.snaplen),
            '-G', str(self.rotation_seconds),  # Rotation trigger
            '-w', filename_pattern,
            '-Z', 'root',
            self.bpf_filter
        ]

        logging.info("Starting tcpdump with rotation")
        logging.info(f"Interface: {self.interface}")
        logging.info(f"Filter: {self.bpf_filter}")
        logging.info(f"Snaplen: {self.snaplen} bytes")
        logging.info(f"Rotation: Every {self.rotation_seconds} seconds")
        logging.info(f"Output: {self.pcap_dir}")
        logging.info(f"Pattern: capture_YYYYMMDD_HHMMSS.pcap")

        try:
            self.tcpdump_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            logging.info(f"tcpdump started with PID {self.tcpdump_process.pid}")
            logging.info("File watcher will queue PCAPs after rotation completes")

            # Wait for process to complete (or be terminated)
            self.tcpdump_process.wait()

        except Exception as e:
            logging.error(f"tcpdump error: {e}")

    def stop(self):
        """Stop tcpdump gracefully"""
        self.running = False
        if self.tcpdump_process:
            logging.info("Stopping tcpdump")
            self.tcpdump_process.terminate()

            try:
                self.tcpdump_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logging.warning("tcpdump did not stop gracefully, killing process")
                logging.warning("tcpdump did not stop gracefully, killing process")
                self.tcpdump_process.kill()

            # Wait additional time to ensure file is completely closed
            logging.info("Waiting 5 seconds for tcpdump to flush buffers")
            time.sleep(5)

            logging.info("tcpdump stopped")


# ==================== Cleanup Manager ====================

class CleanupManager(threading.Thread):
    """Manages old file cleanup based on retention policies"""

    def __init__(self, config):
        super().__init__(daemon=True)
        self.config = config
        self.pcap_dir = config.get('paths', 'pcap_dir')
        self.csv_dir = config.get('paths', 'csv_dir')
        self.csv_processed_dir = config.get('paths', 'csv_processed_dir')  # NEW
        self.pcap_retention_mins = config.get('retention', 'pcap_minutes', default=30)
        self.csv_retention_mins = config.get('retention', 'csv_minutes', default=30)
        self.processed_csv_retention_mins = config.get('retention', 'processed_csv_minutes', default=30)  # NEW
        self.cleanup_interval = config.get('retention', 'cleanup_interval_seconds', default=60)
        self.running = False

    def run(self):
        """Periodically clean up old files"""
        self.running = True

        logging.info("Cleanup manager started")
        logging.info(f"PCAP retention: {self.pcap_retention_mins} minutes")
        logging.info(f"CSV retention: {self.csv_retention_mins} minutes")
        logging.info(f"Processed CSV retention: {self.processed_csv_retention_mins} minutes")
        logging.info(f"Cleanup interval: {self.cleanup_interval}s")

        while self.running:
            try:
                # Cleanup PCAPs
                pcap_deleted = self._cleanup_directory(
                    self.pcap_dir,
                    self.pcap_retention_mins,
                    '*.pcap'
                )

                # Cleanup CSVs
                csv_deleted = self._cleanup_directory(
                    self.csv_dir,
                    self.csv_retention_mins,
                    '*.csv'
                )

                # Cleanup Processed CSVs
                processed_csv_deleted = self._cleanup_directory(
                    self.csv_processed_dir,
                    self.processed_csv_retention_mins,
                    '*.csv'
                )

                if pcap_deleted > 0 or csv_deleted > 0 or processed_csv_deleted > 0:
                    logging.info(f"Cleanup completed: deleted {pcap_deleted} PCAPs, "
                                 f"{csv_deleted} CSVs, {processed_csv_deleted} processed CSVs")

                # Sleep until next cleanup
                time.sleep(self.cleanup_interval)

            except Exception as e:
                logging.error(f"Cleanup error: {e}")

    def _cleanup_directory(self, directory, retention_minutes, pattern):
        """Clean up old files in directory"""
        if not os.path.exists(directory):
            logging.warning(f"Cleanup directory does not exist: {directory}")
            return 0

        cutoff_time = datetime.now() - timedelta(minutes=retention_minutes)
        deleted_count = 0

        for file_path in Path(directory).glob(pattern):
            try:
                file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                if file_mtime < cutoff_time:
                    file_path.unlink()
                    logging.debug(f"Deleted old file: {file_path.name}")
                    deleted_count += 1
            except Exception as e:
                logging.warning(f"Could not delete {file_path}: {e}")

        return deleted_count

    def stop(self):
        """Stop cleanup manager"""
        self.running = False


# ==================== Main Pipeline ====================

class PCAPPipeline:
    """Main PCAP processing pipeline coordinator"""

    def __init__(self, config_path='pipeline_config.json'):
        # Load configuration
        self.config = ConfigLoader(config_path)

        # Setup logging first
        self._setup_logging()

        # Initialize components
        self.pcap_queue = Queue()

        try:
            self.converter = JavaCICFlowMeterConverter(self.config)
        except Exception as e:
            logging.error(f"Failed to initialize converter: {e}")
            sys.exit(1)

        self.rotator = None
        self.workers = []
        self.file_observer = None
        self.cleanup_manager = None
        self.running = False

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _setup_logging(self):
        """Configure logging"""
        log_dir = self.config.get('paths', 'log_dir')
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, 'pipeline_pcap.log')
        log_level = self.config.get('logging', 'level', default='INFO')
        log_format = self.config.get('logging', 'format')
        max_bytes = self.config.get('logging', 'max_bytes', default=10485760)
        backup_count = self.config.get('logging', 'backup_count', default=5)

        # Clear any existing handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        # Setup rotating file handler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setFormatter(logging.Formatter(log_format))

        # Setup console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(log_format))

        # Configure root logger
        logging.basicConfig(
            level=getattr(logging, log_level),
            handlers=[file_handler, console_handler]
        )

        logging.info("=" * 60)
        logging.info("PCAP PIPELINE STARTING")
        logging.info("=" * 60)
        logging.info(f"Version: 3.0 (Java CICFlowMeter with Smart Rotation)")
        logging.info(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logging.info(f"Configuration: {self.config.config_path}")

    def start(self):
        """Start all pipeline components"""
        self.running = True

        try:
            # Create output directories
            csv_dir = self.config.get('paths', 'csv_dir')
            pcap_dir = self.config.get('paths', 'pcap_dir')
            os.makedirs(csv_dir, exist_ok=True)
            os.makedirs(pcap_dir, exist_ok=True)

            logging.info(f"PCAP directory: {pcap_dir}")
            logging.info(f"CSV directory: {csv_dir}")

            # Start file watcher before rotator to catch initial file
            event_handler = PCAPFileHandler(self.pcap_queue, self.config)
            self.file_observer = Observer()
            self.file_observer.schedule(event_handler, pcap_dir, recursive=False)
            self.file_observer.start()
            logging.info(f"File watcher monitoring: {pcap_dir}")
            logging.info("Strategy: Queue files after rotation with safety buffer")

            # Start PCAP rotator
            if self.config.get('capture', 'enabled', default=True):
                self.rotator = PCAPRotator(self.config)
                self.rotator.start()
                logging.info("PCAP rotator started")
            else:
                logging.warning("PCAP capture disabled in config")

            # Start conversion workers
            num_workers = self.config.get('processing', 'worker_threads', default=2)
            max_retries = self.config.get('processing', 'max_retries', default=3)

            for i in range(num_workers):
                worker = ConversionWorker(
                    self.pcap_queue,
                    self.converter,
                    csv_dir,
                    max_retries
                )
                worker.start()
                self.workers.append(worker)

            logging.info(f"Started {num_workers} conversion workers")

            # Start cleanup manager
            self.cleanup_manager = CleanupManager(self.config)
            self.cleanup_manager.start()
            logging.info("Cleanup manager started")

            logging.info("=" * 60)
            logging.info("PIPELINE FULLY OPERATIONAL")
            logging.info("=" * 60)
            logging.info("Workflow:")
            logging.info("1. Capture traffic for 60 seconds")
            logging.info("2. Rotate to new PCAP file")
            logging.info("3. Wait 5 seconds for file to close")
            logging.info("4. Convert previous completed PCAP")
            logging.info("5. Repeat")
            logging.info("=" * 60)

            # Keep main thread alive
            while self.running:
                time.sleep(1)

        except KeyboardInterrupt:
            logging.info("Keyboard interrupt received")
            self.stop()
        except Exception as e:
            logging.error(f"Pipeline error: {e}")
            self.stop()

    def stop(self):
        """Stop all pipeline components"""
        if not self.running:
            return

        logging.info("=" * 60)
        logging.info("STOPPING PIPELINE")
        logging.info("=" * 60)

        self.running = False

        # Stop PCAP rotator first
        if self.rotator:
            self.rotator.stop()
            logging.info("PCAP rotator stopped")

        # Stop file watcher
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join(timeout=5)
            logging.info("File watcher stopped")

        # Wait for queue to drain
        if not self.pcap_queue.empty():
            queue_size = self.pcap_queue.qsize()
            logging.info(f"Waiting for {queue_size} pending conversions to complete")
            try:
                self.pcap_queue.join()
            except:
                pass

        # Stop workers
        for worker in self.workers:
            worker.stop()
        for worker in self.workers:
            worker.join(timeout=5)
        logging.info("Conversion workers stopped")

        # Stop cleanup manager
        if self.cleanup_manager:
            self.cleanup_manager.stop()
            logging.info("Cleanup manager stopped")

        logging.info("=" * 60)
        logging.info("PIPELINE STOPPED")
        logging.info("=" * 60)

    def _signal_handler(self, signum, frame):
        """Handle termination signals"""
        logging.info(f"Received signal {signum}")
        self.stop()
        sys.exit(0)


# ==================== Entry Point ====================

def main():
    """Main entry point"""
    print("\n" + "=" * 60)
    print("PCAP Pipeline - Java CICFlowMeter Integration")
    print("=" * 60 + "\n")

    # Check for config file
    config_file = 'pipeline_config.json'
    if not os.path.exists(config_file):
        print(f"Error: Configuration file not found: {config_file}")
        print("\nPlease create pipeline_config.json with required settings")
        print("See documentation for configuration format")
        sys.exit(1)

    # Check for root privileges
    if os.geteuid() != 0:
        print("Error: This script requires root privileges")
        print("\nPlease run with: sudo python3 pipeline_pcap.py")
        sys.exit(1)

    # Check for cic_cmd.sh
    if not os.path.exists('cic_cmd.sh'):
        print("Error: cic_cmd.sh script not found")
        print("\nPlease create cic_cmd.sh in the current directory")
        print("See documentation for script format")
        sys.exit(1)

    print("Configuration file found")
    print("Running as root")
    print("CICFlowMeter script found")
    print("\nStarting pipeline with smart rotation")
    print("Captures for 60s, rotates, then converts previous PCAP")
    print("Prevents data loss from converting active files\n")

    # Start pipeline
    try:
        pipeline = PCAPPipeline(config_file)
        pipeline.start()
    except Exception as e:
        print(f"\nFatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
