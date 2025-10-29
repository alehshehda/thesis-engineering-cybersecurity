#!/usr/bin/env python3

"""
CSV Monitor Service for SSH Brute-Force Detection
Monitors CSV directory and processes new files with sliding window support
"""

import time
import logging
import shutil
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Set
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Local imports
from detection_engine import SSHDetectionEngine, DetectionResult
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
    Service for monitoring CSV directory and processing files with sliding window
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

        # Window configuration
        self.window_size = config['detection'].get('window_size_minutes', 5)  # 5 CSVs
        self.window_mode = config['detection'].get('window_mode', 'rolling')

        # Initialize detection engine and alert generator
        self.detection_engine = SSHDetectionEngine(config)
        self.alert_generator = AlertGenerator(config)

        # File tracking
        self.csv_queue: List[str] = []
        self.processed_files: Set[str] = set()
        self.is_running = False

        # Sliding window buffer (stores tuples of (csv_path, dataframe))
        self.window_buffer = deque(maxlen=self.window_size)

        # Statistics
        self.stats = {
            'total_processed': 0,
            'total_attacks_detected': 0,
            'total_alerts_generated': 0,
            'total_alerts_skipped': 0,
            'total_window_detections': 0,
            'start_time': None
        }

        # Watchdog observer
        self.observer = None

        logger.info(f"CSV Monitor Service initialized - watching {self.csv_input_dir}")
        logger.info(f"Window mode: {self.window_mode}, Window size: {self.window_size} CSVs")
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
        logger.info("Starting CSV Monitor Service with Sliding Window")
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
                    self._add_to_window_and_detect(csv_path)
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
        logger.info(f"Final window size: {len(self.window_buffer)} CSVs")

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

    def _add_to_window_and_detect(self, csv_path: str):
        """
        Add CSV to sliding window buffer and run detection on current window

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
            # Load CSV data
            logger.info(f"Loading CSV into window: {csv_path.name}")
            df = pd.read_csv(csv_path)
            flow_count = len(df)
            logger.info(f"Loaded {flow_count} flows from {csv_path.name}")

            # Check if window is full - if so, remove oldest
            if len(self.window_buffer) >= self.window_size:
                oldest_csv, oldest_df = self.window_buffer[0]  # Get oldest (will be auto-removed by deque)
                logger.info(f"Window full ({self.window_size} CSVs), oldest will be removed")

            # Add new CSV to window (deque auto-removes oldest if full)
            old_size = len(self.window_buffer)
            self.window_buffer.append((str(csv_path), df))
            new_size = len(self.window_buffer)

            logger.info(f"Added {csv_path.name} to window. Window size: {old_size} -> {new_size} CSVs")

            # If a CSV was dropped, move it to processed
            if old_size == self.window_size and new_size == self.window_size:
                # The oldest CSV path is no longer in buffer, but we need to track it
                # Get all CSV paths currently in window
                current_paths = {csv for csv, _ in self.window_buffer}

                # Find CSVs in processed_files that aren't in current window
                for proc_file in list(self.processed_files):
                    if proc_file not in current_paths and Path(proc_file).exists():
                        # This file was in window but now dropped, move to processed
                        try:
                            proc_path = Path(proc_file)
                            processed_dest = self.csv_processed_dir / proc_path.name
                            shutil.move(str(proc_path), str(processed_dest))
                            logger.info(f"Moved dropped CSV to processed: {proc_path.name}")
                        except Exception as e:
                            logger.warning(f"Failed to move dropped CSV: {e}")

            # Mark as processed (in window)
            self.processed_files.add(str(csv_path))

            # Run detection on current window
            self._detect_on_window()

            # Update statistics
            self.stats['total_processed'] += 1
            self.stats['total_window_detections'] += 1

        except Exception as e:
            logger.error(f"Error processing {csv_path.name}: {e}", exc_info=True)

    def _detect_on_window(self):
        """
        Run detection on all CSVs currently in the sliding window
        """
        if not self.window_buffer:
            logger.warning("Window is empty, skipping detection")
            return

        try:
            window_size = len(self.window_buffer)
            csv_names = [Path(csv_path).name for csv_path, _ in self.window_buffer]

            logger.info("=" * 70)
            logger.info(f"WINDOW DETECTION: Processing {window_size} CSVs")
            logger.info(f"Window contents: {csv_names}")
            logger.info("=" * 70)

            # Combine all dataframes in window
            all_dataframes = [df for _, df in self.window_buffer]
            combined_df = pd.concat(all_dataframes, ignore_index=True)
            total_flows = len(combined_df)

            logger.info(f"Combined window data: {total_flows} total flows from {window_size} CSVs")

            # Map features
            df_mapped = self.detection_engine.feature_mapper.map_cicflow_to_cicids(combined_df)

            # Validate mapping
            is_valid, msg = self.detection_engine.feature_mapper.validate_mapping(df_mapped)
            if not is_valid:
                logger.error(f"Feature mapping validation failed: {msg}")
                return

            # Preprocess data
            df_features = self.detection_engine.preprocess_data(df_mapped)

            # Scale features
            X_scaled = self.detection_engine.scaler.transform(df_features)

            # Get predictions and probabilities
            predictions = self.detection_engine.model.predict(X_scaled)
            probabilities = self.detection_engine.model.predict_proba(X_scaled)

            # Create result object for window
            result = DetectionResult(f"window_{window_size}_csvs", total_flows)
            result.csv_sources = csv_names  # Track which CSVs contributed

            # Process predictions
            threshold = self.config['detection']['threshold']
            for idx, (pred, prob) in enumerate(zip(predictions, probabilities)):
                if pred == 1:
                    attack_prob = prob[1]

                    if attack_prob >= threshold:
                        # Get flow data
                        flow_data = {
                            'src_ip': combined_df.iloc[idx].get('Src IP', 'unknown'),
                            'dst_ip': combined_df.iloc[idx].get('Dst IP', 'unknown'),
                            'src_port': int(combined_df.iloc[idx].get('Src Port', 0)),
                            'dst_port': int(combined_df.iloc[idx].get('Dst Port', 0)),
                            'protocol': int(combined_df.iloc[idx].get('Protocol', 0)),
                            'timestamp': combined_df.iloc[idx].get('Timestamp', ''),
                            'flow_duration': float(combined_df.iloc[idx].get('Flow Duration', 0))
                        }

                        attacker_ip = flow_data['src_ip']
                        result.add_attack_flow(idx, attacker_ip, attack_prob, flow_data)

            # Generate alerts if attacks detected
            if result.has_attacks():
                self.stats['total_attacks_detected'] += len(result.attack_flows)

                # Get alert criteria from config
                min_attack_flows = self.config['detection']['min_attack_flows']

                logger.info(f"Alert criteria: min_flows={min_attack_flows}, threshold={threshold * 100}%")

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
                                csv_sources=csv_names,
                                detection_timestamp=result.timestamp
                            )
                            self.stats['total_alerts_generated'] += 1
                            alerts_generated += 1
                            logger.info(f"ALERT GENERATED: {attacker_ip} with {flow_count} flows "
                                        f"across {window_size} CSVs (>= {min_attack_flows} required)")
                            logger.info(f"Alert file: {alert_file}")
                        except Exception as e:
                            logger.warning(f"Failed to generate alert for {attacker_ip}: {e}")
                    else:
                        self.stats['total_alerts_skipped'] += 1
                        alerts_skipped += 1
                        logger.info(f"ALERT SKIPPED: {attacker_ip} has {flow_count} flows "
                                    f"(minimum required: {min_attack_flows})")

                logger.info(f"Alert summary: {alerts_generated} generated, {alerts_skipped} skipped")

                # Generate statistics JSON
                try:
                    stats_file = self.alert_generator.generate_statistics_json(
                        result=result,
                        model_info=self.detection_engine.get_model_info()
                    )
                    logger.info(f"Generated statistics: {stats_file}")
                except Exception as e:
                    logger.warning(f"Failed to generate statistics: {e}")
            else:
                logger.info(f"No attacks detected in window of {window_size} CSVs")

            logger.info("=" * 70)

        except Exception as e:
            logger.error(f"Error during window detection: {e}", exc_info=True)

    def get_statistics(self) -> Dict:
        """
        Get service statistics

        Returns:
            Statistics dictionary
        """
        stats = self.stats.copy()
        stats['current_window_size'] = len(self.window_buffer)
        stats['window_csv_files'] = [Path(csv).name for csv, _ in self.window_buffer]

        if stats['start_time']:
            uptime = datetime.now() - stats['start_time']
            stats['uptime_seconds'] = int(uptime.total_seconds())

        return stats
