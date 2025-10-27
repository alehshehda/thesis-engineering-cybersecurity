#!/usr/bin/env python3

"""
SSH Brute-Force Detection Model Training
Trains Random Forest model using CICIDS2017 data (Monday + Tuesday only)
"""

import pandas as pd
import numpy as np
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Tuple, Dict, Any

# ML imports
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
from imblearn.over_sampling import SMOTE
import joblib

class SSHBruteForceTrainer:
    """
    Trains Random Forest model for SSH brute-force detection
    Uses only Monday and Tuesday data (SSH-Patator attacks)
    """

    def __init__(self, config_path: str = "ml_config.json"):
        """
        Initialize trainer

        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)

        # Setup logging
        self._setup_logging()
        self.logger = logging.getLogger(__name__)

        # Paths
        self.dataset_path = Path(self.config['paths']['dataset'])
        self.models_path = Path(self.config['paths']['models'])
        self.models_path.mkdir(parents=True, exist_ok=True)

        self.logger.info("SSH Brute-Force Trainer initialized")

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from file"""
        config_file = Path(config_path)
        if not config_file.exists():
            print(f"ERROR: Configuration file '{config_path}' not found")
            exit(1)

        with open(config_file, 'r') as f:
            return json.load(f)

    def _setup_logging(self):
        """Setup logging with RotatingFileHandler"""
        log_dir = Path(self.config['paths']['logs'])
        log_dir.mkdir(parents=True, exist_ok=True)

        log_file = log_dir / f"training_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO'))
        max_bytes = log_config.get('max_bytes', 1073741824)
        backup_count = log_config.get('backup_count', 5)
        log_format = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(log_level)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)

        formatter = logging.Formatter(log_format)
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

    def load_dataset(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Load CICIDS2017 dataset (Monday and Tuesday only for SSH detection)

        Returns:
            Tuple of (training_df, test_df)
        """
        self.logger.info(f"Loading dataset from {self.dataset_path}")

        # Only Monday and Tuesday have SSH-Patator attacks
        train_files = [
            'Monday-WorkingHours.pcap_ISCX.csv',
            'Tuesday-WorkingHours.pcap_ISCX.csv'
        ]

        # Load training data
        train_dfs = []
        for filename in train_files:
            filepath = self.dataset_path / filename
            if filepath.exists():
                self.logger.info(f"Loading {filename}")
                df = pd.read_csv(filepath)
                train_dfs.append(df)
            else:
                self.logger.error(f"Required file not found: {filename}")
                raise FileNotFoundError(f"Required training file not found: {filepath}")

        if not train_dfs:
            self.logger.error("No training data loaded")
            raise ValueError("No training data files found")

        df_combined = pd.concat(train_dfs, ignore_index=True)

        self.logger.info(f"Loaded {len(df_combined)} total samples from Monday + Tuesday")

        # Split into train/test (80/20)
        df_train, df_test = train_test_split(df_combined, test_size=0.2, random_state=42, stratify=df_combined[' Label'])

        self.logger.info(f"Split: {len(df_train)} training, {len(df_test)} testing samples")

        return df_train, df_test

    def prepare_data(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Prepare data for training

        Args:
            df: Raw DataFrame with CICIDS2017 format

        Returns:
            Tuple of (X, y)
        """
        self.logger.info("Preparing data for training")

        # Filter for SSH brute-force attacks
        ssh_label = 'SSH-Patator'
        benign_label = 'BENIGN'

        df_ssh = df[df[' Label'].isin([ssh_label, benign_label])].copy()
        self.logger.info(f"Filtered to {len(df_ssh)} SSH-related flows")

        # Create binary labels
        df_ssh['Label_Binary'] = (df_ssh[' Label'] == ssh_label).astype(int)

        # Get all columns except Label
        all_columns = df_ssh.columns.tolist()
        feature_cols = [col for col in all_columns if col not in [' Label', 'Label_Binary']]

        self.logger.info(f"Using {len(feature_cols)} feature columns from dataset")

        X = df_ssh[feature_cols].copy()
        y = df_ssh['Label_Binary']

        # Handle inf and NaN values
        X.replace([np.inf, -np.inf], np.nan, inplace=True)

        # Count NaN values
        nan_count = X.isna().sum().sum()
        if nan_count > 0:
            self.logger.warning(f"Found {nan_count} NaN/inf values, filling with zeros")
            X.fillna(0, inplace=True)

        self.logger.info(f"Prepared {len(X)} samples with {len(feature_cols)} features")
        self.logger.info(f"Class distribution - Benign: {(y==0).sum()}, Attack: {(y==1).sum()}")

        return X, y

    def train_model(self, X_train: pd.DataFrame, y_train: pd.Series,
                   X_test: pd.DataFrame = None, y_test: pd.Series = None):
        """
        Train Random Forest model

        Args:
            X_train: Training features
            y_train: Training labels
            X_test: Test features (optional)
            y_test: Test labels (optional)
        """
        self.logger.info("Starting model training")

        # Apply SMOTE for class balancing
        self.logger.info("Applying SMOTE for class balancing")
        smote = SMOTE(random_state=42)
        X_resampled, y_resampled = smote.fit_resample(X_train, y_train)
        self.logger.info(f"After SMOTE - Benign: {(y_resampled==0).sum()}, Attack: {(y_resampled==1).sum()}")

        # Scale features
        self.logger.info("Scaling features")
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_resampled)

        # Train Random Forest
        rf_config = self.config['model']['random_forest']
        self.logger.info(f"Training Random Forest with config: {rf_config}")

        model = RandomForestClassifier(
            n_estimators=rf_config['n_estimators'],
            max_depth=rf_config['max_depth'],
            min_samples_split=rf_config['min_samples_split'],
            min_samples_leaf=rf_config['min_samples_leaf'],
            class_weight=rf_config['class_weight'],
            random_state=rf_config['random_state'],
            n_jobs=-1,
            verbose=1
        )

        start_time = time.time()
        model.fit(X_scaled, y_resampled)
        training_time = time.time() - start_time

        self.logger.info(f"Training completed in {training_time:.2f} seconds")

        # Evaluate on training set
        y_pred_train = model.predict(X_scaled)
        train_accuracy = accuracy_score(y_resampled, y_pred_train)
        self.logger.info(f"Training accuracy: {train_accuracy:.4f}")

        # Evaluate on test set if provided
        if X_test is not None and y_test is not None:
            X_test_scaled = scaler.transform(X_test)
            y_pred_test = model.predict(X_test_scaled)
            y_proba_test = model.predict_proba(X_test_scaled)

            self._evaluate_model(y_test, y_pred_test, y_proba_test)

        # Save model and scaler
        self._save_model(model, scaler)

        # Save feature names for validation
        self._save_feature_names(X_train.columns.tolist())

    def _evaluate_model(self, y_true, y_pred, y_proba):
        """Evaluate model performance"""
        self.logger.info("="*60)
        self.logger.info("Model Evaluation on Test Set")
        self.logger.info("="*60)
        self.logger.info(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
        self.logger.info(f"Precision: {precision_score(y_true, y_pred):.4f}")
        self.logger.info(f"Recall: {recall_score(y_true, y_pred):.4f}")
        self.logger.info(f"F1-Score: {f1_score(y_true, y_pred):.4f}")
        self.logger.info(f"ROC-AUC: {roc_auc_score(y_true, y_proba[:, 1]):.4f}")

        cm = confusion_matrix(y_true, y_pred)
        self.logger.info(f"\nConfusion Matrix:\n{cm}")
        self.logger.info(f"\nClassification Report:\n{classification_report(y_true, y_pred)}")
        self.logger.info("="*60)

    def _save_model(self, model, scaler):
        """Save trained model and scaler"""
        model_path = self.models_path / 'ssh_bruteforce_model.pkl'
        scaler_path = self.models_path / 'feature_scaler.pkl'

        joblib.dump(model, model_path)
        joblib.dump(scaler, scaler_path)

        self.logger.info(f"Model saved to {model_path}")
        self.logger.info(f"Scaler saved to {scaler_path}")

    def _save_feature_names(self, feature_names: list):
        """Save feature names for validation"""
        features_path = self.models_path / 'feature_names.json'

        with open(features_path, 'w') as f:
            json.dump({'features': feature_names, 'count': len(feature_names)}, f, indent=2)

        self.logger.info(f"Feature names saved to {features_path} ({len(feature_names)} features)")

def main():
    """Main training script"""
    trainer = SSHBruteForceTrainer()

    # Load dataset (Monday + Tuesday only)
    df_train, df_test = trainer.load_dataset()

    # Prepare training data
    X_train, y_train = trainer.prepare_data(df_train)

    # Prepare test data
    X_test, y_test = trainer.prepare_data(df_test)

    # Train model
    trainer.train_model(X_train, y_train, X_test, y_test)

    print("\nTraining complete! Model saved to models/ directory")

if __name__ == "__main__":
    main()
