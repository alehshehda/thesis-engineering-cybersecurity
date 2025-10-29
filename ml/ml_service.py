#!/usr/bin/env python3

"""
SSH Brute-Force Detection Service
Main service script for starting/stopping the ML detection system
"""

import sys
import signal
import time
import logging
from logging.handlers import RotatingFileHandler
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

# Local imports
from src.csv_monitor import CSVMonitorService


class SSHDetectionService:
    """
    Main service controller for SSH brute-force detection
    """

    def __init__(self, config_path: str = "ml_config.json"):
        """
        Initialize the detection service

        Args:
            config_path: Path to configuration file
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.monitor_service = None
        self.is_running = False

        # Set up logging
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        self.logger.info("SSH Detection Service initialized")

    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from ml_config.json

        Returns:
            Configuration dictionary
        """
        if not self.config_path.exists():
            print(f"ERROR: Configuration file '{self.config_path}' not found")
            print("Please ensure ml_config.json exists in the ML module directory")
            sys.exit(1)

        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            return config
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in configuration file: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: Failed to load configuration: {e}")
            sys.exit(1)

    def _setup_logging(self):
        """
        Set up logging with RotatingFileHandler
        """
        # Create logs directory
        log_dir = Path(self.config['paths']['logs'])
        log_dir.mkdir(parents=True, exist_ok=True)

        # Configure root logger
        log_file = log_dir / f"ml_service_{datetime.now().strftime('%Y%m%d')}.log"

        # Get logging configuration
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO'))
        max_bytes = log_config.get('max_bytes', 1073741824)
        backup_count = log_config.get('backup_count', 5)
        log_format = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Create rotating file handler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(log_level)

        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)

        # Create formatter
        formatter = logging.Formatter(log_format)
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

    def _signal_handler(self, signum, frame):
        """
        Handle shutdown signals

        Args:
            signum: Signal number
            frame: Current stack frame
        """
        self.logger.info(f"Received signal {signum}, initiating shutdown")
        self.stop()
        sys.exit(0)

    def _validate_directories(self) -> bool:
        """
        Validate that all required directories exist

        Returns:
            True if all directories exist, False otherwise
        """
        paths = self.config['paths']
        required_dirs = ['alerts', 'logs', 'statistics', 'models']

        for dir_name in required_dirs:
            dir_path = Path(paths[dir_name])
            if not dir_path.exists():
                self.logger.warning(f"Directory does not exist: {dir_path}, creating it")
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    self.logger.error(f"Failed to create directory {dir_path}: {e}")
                    return False

        # Check CSV input directory
        csv_input = Path(paths['csv_input'])
        if not csv_input.exists():
            self.logger.error(f"CSV input directory does not exist: {csv_input}")
            return False

        # Check CSV processed directory
        csv_processed = Path(paths['csv_processed'])
        if not csv_processed.exists():
            self.logger.warning(f"CSV processed directory does not exist: {csv_processed}, creating it")
            try:
                csv_processed.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.logger.error(f"Failed to create processed directory {csv_processed}: {e}")
                return False

        return True

    def _validate_models(self) -> bool:
        """
        Validate that required model files exist

        Returns:
            True if models exist, False otherwise
        """
        models_dir = Path(self.config['paths']['models'])

        required_files = ['ssh_bruteforce_model.pkl', 'feature_scaler.pkl']

        for file_name in required_files:
            file_path = models_dir / file_name
            if not file_path.exists():
                self.logger.error(f"Required model file not found: {file_path}")
                self.logger.error("Please train the model first using src/train_model.py")
                return False

        return True

    def start(self):
        """
        Start the detection service
        """
        self.logger.info("Starting SSH Brute-Force Detection Service")

        # Validate directories
        if not self._validate_directories():
            self.logger.error("Directory validation failed")
            sys.exit(1)

        # Validate models
        if not self._validate_models():
            self.logger.error("Model validation failed")
            sys.exit(1)

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Initialize and start CSV monitor service
        try:
            self.monitor_service = CSVMonitorService(self.config)
            self.is_running = True
            self.logger.info("Service started successfully")

            # Start monitoring
            self.monitor_service.start()

            # Keep service running
            while self.is_running:
                time.sleep(1)

        except Exception as e:
            self.logger.error(f"Service failed: {e}", exc_info=True)
            self.stop()
            sys.exit(1)

    def stop(self):
        """
        Stop the detection service
        """
        self.logger.info("Stopping SSH Brute-Force Detection Service")
        self.is_running = False

        if self.monitor_service:
            self.monitor_service.stop()

        self.logger.info("Service stopped")

    def status(self):
        """
        Check service status
        """
        if self.is_running and self.monitor_service:
            stats = self.monitor_service.get_statistics()
            self.logger.info(f"Service is running - {stats}")
        else:
            self.logger.info("Service is not running")


def main():
    """
    Main entry point
    """
    service = SSHDetectionService()
    service.start()


if __name__ == "__main__":
    main()