#!/usr/bin/env python3

"""
Feature Mapping System for SSH Brute-Force Detection
Maps between CICFlowMeter output and CICIDS2017 features with EXACT column names
"""

import pandas as pd
import numpy as np
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

class FeatureMapper:
    """
    Maps features between CICFlowMeter output and CICIDS2017 format
    Uses EXACT column names from CICIDS2017 dataset (with inconsistent spacing)
    """

    def __init__(self):
        """Initialize feature mapping dictionaries"""

        # EXACT column names from CICIDS2017 training data (79 columns)
        # NOTE: This dataset has inconsistent leading spaces - this is preserved intentionally
        self.cicids_columns = [
            ' Destination Port',
            ' Flow Duration',
            ' Total Fwd Packets',
            ' Total Backward Packets',
            'Total Length of Fwd Packets',      # NO space
            ' Total Length of Bwd Packets',
            ' Fwd Packet Length Max',
            ' Fwd Packet Length Min',
            ' Fwd Packet Length Mean',
            ' Fwd Packet Length Std',
            'Bwd Packet Length Max',             # NO space
            ' Bwd Packet Length Min',
            ' Bwd Packet Length Mean',
            ' Bwd Packet Length Std',
            'Flow Bytes/s',                      # NO space
            ' Flow Packets/s',
            ' Flow IAT Mean',
            ' Flow IAT Std',
            ' Flow IAT Max',
            ' Flow IAT Min',
            'Fwd IAT Total',                     # NO space
            ' Fwd IAT Mean',
            ' Fwd IAT Std',
            ' Fwd IAT Max',
            ' Fwd IAT Min',
            'Bwd IAT Total',                     # NO space
            ' Bwd IAT Mean',
            ' Bwd IAT Std',
            ' Bwd IAT Max',
            ' Bwd IAT Min',
            'Fwd PSH Flags',                     # NO space
            ' Bwd PSH Flags',
            ' Fwd URG Flags',
            ' Bwd URG Flags',
            ' Fwd Header Length',
            ' Bwd Header Length',
            'Fwd Packets/s',                     # NO space
            ' Bwd Packets/s',
            ' Min Packet Length',
            ' Max Packet Length',
            ' Packet Length Mean',
            ' Packet Length Std',
            ' Packet Length Variance',
            'FIN Flag Count',                    # NO space
            ' SYN Flag Count',
            ' RST Flag Count',
            ' PSH Flag Count',
            ' ACK Flag Count',
            ' URG Flag Count',
            ' CWE Flag Count',
            ' ECE Flag Count',
            ' Down/Up Ratio',
            ' Average Packet Size',
            ' Avg Fwd Segment Size',
            ' Avg Bwd Segment Size',
            ' Fwd Header Length.1',              # Duplicate column
            'Fwd Avg Bytes/Bulk',                # NO space
            ' Fwd Avg Packets/Bulk',
            ' Fwd Avg Bulk Rate',
            ' Bwd Avg Bytes/Bulk',
            ' Bwd Avg Packets/Bulk',
            'Bwd Avg Bulk Rate',                 # NO space
            'Subflow Fwd Packets',               # NO space
            ' Subflow Fwd Bytes',
            ' Subflow Bwd Packets',
            ' Subflow Bwd Bytes',
            'Init_Win_bytes_forward',            # NO space
            ' Init_Win_bytes_backward',
            ' act_data_pkt_fwd',
            ' min_seg_size_forward',
            'Active Mean',                       # NO space
            ' Active Std',
            ' Active Max',
            ' Active Min',
            'Idle Mean',                         # NO space
            ' Idle Std',
            ' Idle Max',
            ' Idle Min',
            ' Label'
        ]

        # Mapping from CICFlowMeter to CICIDS2017 (exact column names with inconsistent spaces)
        self.feature_mapping = {
            'Dst Port': ' Destination Port',
            'Flow Duration': ' Flow Duration',
            'Tot Fwd Pkts': ' Total Fwd Packets',
            'Tot Bwd Pkts': ' Total Backward Packets',
            'TotLen Fwd Pkts': 'Total Length of Fwd Packets',      # NO space
            'TotLen Bwd Pkts': ' Total Length of Bwd Packets',
            'Fwd Pkt Len Max': ' Fwd Packet Length Max',
            'Fwd Pkt Len Min': ' Fwd Packet Length Min',
            'Fwd Pkt Len Mean': ' Fwd Packet Length Mean',
            'Fwd Pkt Len Std': ' Fwd Packet Length Std',
            'Bwd Pkt Len Max': 'Bwd Packet Length Max',            # NO space
            'Bwd Pkt Len Min': ' Bwd Packet Length Min',
            'Bwd Pkt Len Mean': ' Bwd Packet Length Mean',
            'Bwd Pkt Len Std': ' Bwd Packet Length Std',
            'Flow Byts/s': 'Flow Bytes/s',                         # NO space
            'Flow Pkts/s': ' Flow Packets/s',
            'Flow IAT Mean': ' Flow IAT Mean',
            'Flow IAT Std': ' Flow IAT Std',
            'Flow IAT Max': ' Flow IAT Max',
            'Flow IAT Min': ' Flow IAT Min',
            'Fwd IAT Tot': 'Fwd IAT Total',                        # NO space
            'Fwd IAT Mean': ' Fwd IAT Mean',
            'Fwd IAT Std': ' Fwd IAT Std',
            'Fwd IAT Max': ' Fwd IAT Max',
            'Fwd IAT Min': ' Fwd IAT Min',
            'Bwd IAT Tot': 'Bwd IAT Total',                        # NO space
            'Bwd IAT Mean': ' Bwd IAT Mean',
            'Bwd IAT Std': ' Bwd IAT Std',
            'Bwd IAT Max': ' Bwd IAT Max',
            'Bwd IAT Min': ' Bwd IAT Min',
            'Fwd PSH Flags': 'Fwd PSH Flags',                      # NO space
            'Bwd PSH Flags': ' Bwd PSH Flags',
            'Fwd URG Flags': ' Fwd URG Flags',
            'Bwd URG Flags': ' Bwd URG Flags',
            'Fwd Header Len': ' Fwd Header Length',
            'Bwd Header Len': ' Bwd Header Length',
            'Fwd Pkts/s': 'Fwd Packets/s',                         # NO space
            'Bwd Pkts/s': ' Bwd Packets/s',
            'Pkt Len Min': ' Min Packet Length',
            'Pkt Len Max': ' Max Packet Length',
            'Pkt Len Mean': ' Packet Length Mean',
            'Pkt Len Std': ' Packet Length Std',
            'Pkt Len Var': ' Packet Length Variance',
            'FIN Flag Cnt': 'FIN Flag Count',                      # NO space
            'SYN Flag Cnt': ' SYN Flag Count',
            'RST Flag Cnt': ' RST Flag Count',
            'PSH Flag Cnt': ' PSH Flag Count',
            'ACK Flag Cnt': ' ACK Flag Count',
            'URG Flag Cnt': ' URG Flag Count',
            'CWE Flag Count': ' CWE Flag Count',
            'ECE Flag Cnt': ' ECE Flag Count',
            'Down/Up Ratio': ' Down/Up Ratio',
            'Pkt Size Avg': ' Average Packet Size',
            'Fwd Seg Size Avg': ' Avg Fwd Segment Size',
            'Bwd Seg Size Avg': ' Avg Bwd Segment Size',
            'Fwd Header Len_dup': ' Fwd Header Length.1',          # Duplicate
            'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',               # NO space
            'Fwd Pkts/b Avg': ' Fwd Avg Packets/Bulk',
            'Fwd Blk Rate Avg': ' Fwd Avg Bulk Rate',
            'Bwd Byts/b Avg': ' Bwd Avg Bytes/Bulk',
            'Bwd Pkts/b Avg': ' Bwd Avg Packets/Bulk',
            'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',               # NO space
            'Subflow Fwd Pkts': 'Subflow Fwd Packets',             # NO space
            'Subflow Fwd Byts': ' Subflow Fwd Bytes',
            'Subflow Bwd Pkts': ' Subflow Bwd Packets',
            'Subflow Bwd Byts': ' Subflow Bwd Bytes',
            'Init Fwd Win Byts': 'Init_Win_bytes_forward',         # NO space
            'Init Bwd Win Byts': ' Init_Win_bytes_backward',
            'Fwd Act Data Pkts': ' act_data_pkt_fwd',
            'Fwd Seg Size Min': ' min_seg_size_forward',
            'Active Mean': 'Active Mean',                          # NO space
            'Active Std': ' Active Std',
            'Active Max': ' Active Max',
            'Active Min': ' Active Min',
            'Idle Mean': 'Idle Mean',                              # NO space
            'Idle Std': ' Idle Std',
            'Idle Max': ' Idle Max',
            'Idle Min': ' Idle Min',
            'Label': ' Label'
        }

        logger.info("FeatureMapper initialized with exact CICIDS2017 column names (including inconsistent spacing)")

    def map_cicflow_to_cicids(self, df_cicflow: pd.DataFrame) -> pd.DataFrame:
        """
        Map CICFlowMeter DataFrame to CICIDS2017 format

        Args:
            df_cicflow: DataFrame with CICFlowMeter columns

        Returns:
            DataFrame with CICIDS2017 columns (79 features)
        """
        logger.info(f"Mapping CICFlowMeter data with {len(df_cicflow)} rows and {len(df_cicflow.columns)} columns")

        # Create new DataFrame with CICIDS2017 columns
        df_cicids = pd.DataFrame()

        # Map features (handle duplicate Fwd Header Len)
        mapped_count = 0
        for cicflow_col, cicids_col in self.feature_mapping.items():
            # Handle duplicate Fwd Header Len
            if cicflow_col == 'Fwd Header Len_dup':
                if 'Fwd Header Len' in df_cicflow.columns:
                    df_cicids[cicids_col] = df_cicflow['Fwd Header Len']
                    mapped_count += 1
                else:
                    logger.warning(f"Column 'Fwd Header Len' not found for duplicate mapping, filling with zeros")
                    df_cicids[cicids_col] = 0
            elif cicflow_col in df_cicflow.columns:
                df_cicids[cicids_col] = df_cicflow[cicflow_col]
                mapped_count += 1
            else:
                logger.warning(f"Column '{cicflow_col}' not found in CICFlowMeter data, filling with zeros")
                df_cicids[cicids_col] = 0

        logger.info(f"Mapped {mapped_count} features from CICFlowMeter to CICIDS2017 format")

        # Ensure columns are in exact CICIDS2017 order
        df_cicids = df_cicids[self.cicids_columns]

        logger.info(f"Final mapped DataFrame: {len(df_cicids)} rows, {len(df_cicids.columns)} columns")

        return df_cicids

    def validate_mapping(self, df: pd.DataFrame) -> Tuple[bool, str]:
        """
        Validate that DataFrame has correct CICIDS2017 format

        Args:
            df: DataFrame to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if len(df.columns) != 79:
            return False, f"Expected 79 columns, got {len(df.columns)}"

        for i, col in enumerate(self.cicids_columns):
            if i >= len(df.columns):
                return False, f"Missing column at position {i}: {col}"
            if df.columns[i] != col:
                return False, f"Column mismatch at position {i}: expected '{col}', got '{df.columns[i]}'"

        return True, "Validation successful"

    def get_feature_columns(self) -> List[str]:
        """
        Get list of feature columns (excluding Label)

        Returns:
            List of 78 feature column names
        """
        return [col for col in self.cicids_columns if col != ' Label']

    def preprocess_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Preprocess features: handle inf/NaN values

        Args:
            df: DataFrame with CICIDS2017 format

        Returns:
            Preprocessed DataFrame
        """
        df_processed = df.copy()

        # Replace inf with NaN
        df_processed.replace([np.inf, -np.inf], np.nan, inplace=True)

        # Fill NaN with 0
        nan_count = df_processed.isna().sum().sum()
        if nan_count > 0:
            logger.warning(f"Found {nan_count} NaN values, filling with zeros")
            df_processed.fillna(0, inplace=True)

        return df_processed
