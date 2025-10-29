#!/usr/bin/env python3

"""
CSV Monitor Service for SSH Brute-Force Detection
Monitors CSV directory and processes new files
"""

import os
import time
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Local imports
from detection_engine import SSHDetectionEngine
from alert_generator import AlertGenerator

logger = logging.getLogger(__name__)


class CSVHandler(FileSystemEventHandler):
    """
    Handles CSV file events from watchdog
    """

    def __init__(self, monitor_service):
        """
        Initialize CSV handler

        Args:
            monitor_service: Reference to CSVMonitorService
        """
        self.monitor = monitor_service
        super().__init__()

    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory and event.src_path.endswith('.csv'):
            logger.info(f"New CSV detected: {event.src_path}")
            self.monitor.queue_csv_file(event.src_path)


class CSVMonitorService:
    """
    Service for monitoring CSV directory and processing files
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize CSV monitor service

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.csv_input_dir = Path(config['paths']['csv_input'])
        self.csv_processed_dir = Path(config['paths']['csv_processed'])
        self.wait_time = config['processing'].get('wait_time_seconds', 10)
        self.process_existing = config['processing'].get('process_existing_on_startup', True)

        # Initialize detection engine and alert generator
        self.detection_engine = SSHDetectionEngine(config)
        self.alert_generator = AlertGenerator(config)

        # File tracking
        self.csv_queue: List[str] = []
        self.processed_files: Set[str] = set()
        self.is_running = False

        # Statistics
        self.stats = {
            'total_processed': 0,
            'total_attacks_detected': 0,
            'total_alerts_generated': 0,
            'total_alerts_skipped': 0,
            'start_time': None
        }

        # Watchdog observer
        self.observer = None

        logger.info(f"CSV Monitor Service initialized - watching {self.csv_input_dir}")
        logger.info(f"Wait time: {self.wait_time} seconds")

    def queue_csv_file(self, csv_path: str):
        """
        Add CSV file to processing queue

        Args:
            csv_path: Path to CSV file
        """
        csv_path = str(Path(csv_path).absolute())

        if csv_path not in self.csv_queue and csv_path not in self.processed_files:
            self.csv_queue.append(csv_path)
            logger.info(f"Queued CSV file: {Path(csv_path).name}")

    def start(self):
        """
        Start monitoring CSV directory
        """
        logger.info("Starting CSV Monitor Service")
        self.is_running = True
        self.stats['start_time'] = datetime.now()

        # Process existing CSV files if configured
        if self.process_existing:
            self._process_existing_files()

        # Start watchdog observer
        self.observer = Observer()
        event_handler = CSVHandler(self)
        self.observer.schedule(event_handler, str(self.csv_input_dir), recursive=False)
        self.observer.start()
        logger.info("File system observer started")

        # Main processing loop
        try:
            while self.is_running:
                if self.csv_queue:
                    csv_path = self.csv_queue.pop(0)
                    self._process_csv_file(csv_path)
                else:
                    time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        finally:
            self.stop()

    def stop(self):
        """
        Stop monitoring service
        """
        logger.info("Stopping CSV Monitor Service")
        self.is_running = False

        if self.observer:
            self.observer.stop()
            self.observer.join()

        logger.info("CSV Monitor Service stopped")

    def _process_existing_files(self):
        """
        Process existing CSV files in input directory
        """
        csv_files = list(self.csv_input_dir.glob('*.csv'))

        if csv_files:
            logger.info(f"Found {len(csv_files)} existing CSV files")
            for csv_file in sorted(csv_files):
                self.queue_csv_file(str(csv_file))
        else:
            logger.info("No existing CSV files found")

    def _process_csv_file(self, csv_path: str):
        """
        Process a single CSV file

        Args:
            csv_path: Path to CSV file
        """
        csv_path = Path(csv_path)

        # Wait for file to be fully written
        logger.info(f"Waiting {self.wait_time} seconds before processing {csv_path.name}")
        time.sleep(self.wait_time)

        # Check if file still exists
        if not csv_path.exists():
            logger.warning(f"CSV file disappeared during wait period: {csv_path.name}, skipping")
            return

        try:
            # Run detection
            logger.info(f"Processing CSV file: {csv_path.name}")
            result = self.detection_engine.detect_attacks(csv_path)

            # Update statistics
            self.stats['total_processed'] += 1

            # Generate alerts and statistics only if attacks detected
            if result.has_attacks():
                self.stats['total_attacks_detected'] += len(result.attack_flows)

                # Get alert criteria from config
                min_attack_flows = self.config['detection']['min_attack_flows']
                threshold = self.config['detection']['threshold']

                logger.info(f"Alert criteria: min_flows={min_attack_flows}, threshold={threshold*100}%")

                # Group flows by attacker
                attacker_flows = {}
                for attack_flow in result.attack_flows:
                    attacker_ip = attack_flow['attacker_ip']
                    if attacker_ip not in attacker_flows:
                        attacker_flows[attacker_ip] = []
                    attacker_flows[attacker_ip].append(attack_flow)

                # Generate alerts for each attacker (ONLY if meets min_attack_flows)
                alerts_generated = 0
                alerts_skipped = 0

                for attacker_ip, flows in attacker_flows.items():
                    flow_count = len(flows)

                    # CHECK: Only generate alert if meets minimum flow requirement
                    if flow_count >= min_attack_flows:
                        try:
                            alert_file = self.alert_generator.generate_alert_json(
                                attacker_ip=attacker_ip,
                                attacker_flows=flows,
                                csv_sources=[csv_path.name],
                                detection_timestamp=result.timestamp
                            )
                            self.stats['total_alerts_generated'] += 1
                            alerts_generated += 1
                            logger.info(f"ALERT GENERATED: {attacker_ip} with {flow_count} flows "
                                       f"(>= {min_attack_flows} required)")
                            logger.info(f"Alert file: {alert_file}")
                        except Exception as e:
                            logger.warning(f"Failed to generate alert for {attacker_ip}: {e}")
                    else:
                        self.stats['total_alerts_skipped'] += 1
                        alerts_skipped += 1
                        logger.info(f"ALERT SKIPPED: {attacker_ip} has {flow_count} flows "
                                   f"(minimum required: {min_attack_flows})")

                logger.info(f"Alert summary: {alerts_generated} generated, {alerts_skipped} skipped")

                # Generate statistics JSON (even if no alerts generated)
                try:
                    stats_file = self.alert_generator.generate_statistics_json(
                        result=result,
                        model_info=self.detection_engine.get_model_info()
                    )
                    logger.info(f"Generated statistics: {stats_file}")
                except Exception as e:
                    logger.warning(f"Failed to generate statistics: {e}")
            else:
                logger.info(f"No attacks detected in {csv_path.name}, no statistics generated")

            # Move CSV to processed directory
            try:
                processed_path = self.csv_processed_dir / csv_path.name
                shutil.move(str(csv_path), str(processed_path))
                logger.info(f"Moved {csv_path.name} to processed directory")
                self.processed_files.add(str(csv_path))
            except Exception as e:
                logger.warning(f"Failed to move CSV file to processed directory: {e}")

        except Exception as e:
            logger.error(f"Error processing {csv_path.name}: {e}", exc_info=True)

    def get_statistics(self) -> Dict:
        """
        Get service statistics

        Returns:
            Statistics dictionary
        """
        stats = self.stats.copy()
        if stats['start_time']:
            uptime = datetime.now() - stats['start_time']
            stats['uptime_seconds'] = int(uptime.total_seconds())
        return stats
