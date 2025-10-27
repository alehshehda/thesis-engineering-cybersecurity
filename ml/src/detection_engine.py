#!/usr/bin/env python3

"""
SSH Brute-Force Detection Engine
Core ML detection logic with rolling window support
"""

import pandas as pd
import numpy as np
import json
import logging
import joblib
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from collections import deque

# Local imports
from feature_mapper import FeatureMapper

logger = logging.getLogger(__name__)


class DetectionResult:
    """Container for detection results"""

    def __init__(self, csv_filename: str, total_flows: int):
        self.csv_filename = csv_filename
        self.timestamp = datetime.now()
        self.total_flows = total_flows
        self.processing_time = 0.0
        self.attack_flows = []
        self.attackers = {}
        self.alerts_generated = []

    def add_attack_flow(self, flow_index: int, attacker_ip: str, probability: float, flow_data: Dict):
        """Add detected attack flow"""
        self.attack_flows.append({
            'flow_index': flow_index,
            'attacker_ip': attacker_ip,
            'probability': probability,
            'flow_data': flow_data
        })

        if attacker_ip not in self.attackers:
            self.attackers[attacker_ip] = 0
        self.attackers[attacker_ip] += 1

    def has_attacks(self) -> bool:
        """Check if any attacks were detected"""
        return len(self.attack_flows) > 0

    def get_summary(self) -> Dict:
        """Get summary of detection results"""
        return {
            'csv_filename': self.csv_filename,
            'timestamp': self.timestamp.isoformat(),
            'total_flows': self.total_flows,
            'attack_flows_count': len(self.attack_flows),
            'unique_attackers': len(self.attackers),
            'attackers': self.attackers,
            'processing_time': round(self.processing_time, 3)
        }


class SSHDetectionEngine:
    """
    SSH Brute-Force Detection Engine
    Processes CSV files and detects attacks using trained ML model
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize detection engine

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.feature_mapper = FeatureMapper()

        # Load model and scaler
        models_path = Path(config['paths']['models'])
        self.model = self._load_model(models_path / 'ssh_bruteforce_model.pkl')
        self.scaler = self._load_model(models_path / 'feature_scaler.pkl')

        # Detection parameters
        self.threshold = config['detection']['threshold']
        self.min_attack_flows = config['detection']['min_attack_flows']
        self.ssh_port = config['detection'].get('ssh_port', 22)

        # Window configuration
        self.window_mode = config['detection'].get('window_mode', 'rolling')
        self.window_size_minutes = config['detection'].get('window_size_minutes', 5)

        # Rolling window storage
        self.flow_window = deque(maxlen=1000)

        logger.info(f"Detection Engine initialized - threshold={self.threshold}, "
                    f"min_flows={self.min_attack_flows}, window={self.window_mode}")

    def _load_model(self, model_path: Path):
        """
        Load model or scaler from file

        Args:
            model_path: Path to model file

        Returns:
            Loaded model
        """
        try:
            model = joblib.load(model_path)
            logger.info(f"Loaded model from {model_path}")
            return model
        except Exception as e:
            logger.error(f"Failed to load model from {model_path}: {e}")
            raise

    def preprocess_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Preprocess data for detection

        Args:
            df: DataFrame with CICIDS2017 format

        Returns:
            Preprocessed DataFrame
        """
        df_processed = df.copy()

        # Handle inf/NaN values using feature mapper
        df_processed = self.feature_mapper.preprocess_features(df_processed)

        # Get feature columns (exclude Label)
        feature_cols = self.feature_mapper.get_feature_columns()

        # Check for missing features
        missing_features = [col for col in feature_cols if col not in df_processed.columns]
        if missing_features:
            logger.warning(f"Missing {len(missing_features)} features, filling with zeros")
            for feature in missing_features:
                df_processed[feature] = 0

        # Ensure correct column order
        df_processed = df_processed[feature_cols]

        return df_processed

    def detect_attacks(self, csv_path: Path) -> DetectionResult:
        """
        Detect SSH brute-force attacks in CSV file

        Args:
            csv_path: Path to CSV file

        Returns:
            DetectionResult object
        """
        start_time = time.time()
        logger.info(f"Processing {csv_path.name}")

        try:
            # Read CSV file
            df_raw = pd.read_csv(csv_path)
            total_flows = len(df_raw)

            if total_flows == 0:
                logger.warning(f"Empty CSV file: {csv_path.name}")
                result = DetectionResult(csv_path.name, 0)
                result.processing_time = time.time() - start_time
                return result

            logger.info(f"Loaded {total_flows} flows from {csv_path.name}")

            # Map CICFlowMeter format to CICIDS2017 format
            df_mapped = self.feature_mapper.map_cicflow_to_cicids(df_raw)

            # Validate mapping
            is_valid, msg = self.feature_mapper.validate_mapping(df_mapped)
            if not is_valid:
                logger.error(f"Feature mapping validation failed: {msg}")
                result = DetectionResult(csv_path.name, total_flows)
                result.processing_time = time.time() - start_time
                return result

            # Preprocess data
            df_features = self.preprocess_data(df_mapped)

            # Scale features
            X_scaled = self.scaler.transform(df_features)

            # Get predictions and probabilities
            predictions = self.model.predict(X_scaled)
            probabilities = self.model.predict_proba(X_scaled)

            # Create result object
            result = DetectionResult(csv_path.name, total_flows)

            # Process predictions
            for idx, (pred, prob) in enumerate(zip(predictions, probabilities)):
                if pred == 1:
                    attack_prob = prob[1]

                    if attack_prob >= self.threshold:
                        # Get flow data
                        flow_data = {
                            'src_ip': df_raw.iloc[idx].get('Src IP', 'unknown'),
                            'dst_ip': df_raw.iloc[idx].get('Dst IP', 'unknown'),
                            'src_port': int(df_raw.iloc[idx].get('Src Port', 0)),
                            'dst_port': int(df_raw.iloc[idx].get('Dst Port', 0)),
                            'protocol': int(df_raw.iloc[idx].get('Protocol', 0)),
                            'timestamp': df_raw.iloc[idx].get('Timestamp', ''),
                            'flow_duration': float(df_raw.iloc[idx].get('Flow Duration', 0))
                        }

                        attacker_ip = flow_data['src_ip']
                        result.add_attack_flow(idx, attacker_ip, attack_prob, flow_data)

            result.processing_time = time.time() - start_time

            if result.has_attacks():
                logger.info(f"Detected {len(result.attack_flows)} attack flows from "
                            f"{len(result.attackers)} unique attackers in {csv_path.name}")
            else:
                logger.info(f"No attacks detected in {csv_path.name}")

            return result

        except Exception as e:
            logger.error(f"Error processing {csv_path.name}: {e}", exc_info=True)
            result = DetectionResult(csv_path.name, 0)
            result.processing_time = time.time() - start_time
            return result

    def filter_ssh_flows(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Filter DataFrame to only include SSH flows

        Args:
            df: Input DataFrame

        Returns:
            Filtered DataFrame
        """
        if 'Dst Port' in df.columns:
            df_ssh = df[df['Dst Port'] == self.ssh_port].copy()
            logger.info(f"Filtered to {len(df_ssh)} SSH flows (port {self.ssh_port})")
            return df_ssh
        else:
            logger.warning("Dst Port column not found, returning all flows")
            return df

    def get_model_info(self) -> Dict:
        """
        Get information about loaded model

        Returns:
            Dictionary with model information
        """
        return {
            'model_type': type(self.model).__name__,
            'threshold': self.threshold,
            'min_attack_flows': self.min_attack_flows,
            'window_mode': self.window_mode,
            'window_size_minutes': self.window_size_minutes
        }