# ML Detection Module

Machine Learning-based SSH brute-force attack detection system for network security thesis project.

## Overview

The ML module monitors CSV files from the pipeline, detects SSH brute-force attacks using a trained Random Forest model, and generates alerts with detailed statistics. It uses the CICIDS2017 dataset for training and features exact column mapping for compatibility.

## Architecture
```

┌─────────────────────┐
│ CSV Files From      |
| pipeline module     |
│ (CICFlowMeter)      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Feature Mapper      │
│ (exact spacing)     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Detection Engine    |
| Random Forest       |
| classifier          |
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Alert Generator     |
│ JSON output         |
└─────────────────────┘
```

## Directory Structure
```
/root/Thesis/ml/
├── ml_service.py            # Main service entry point
├── ml_config.json           # Configuration file
├── ml_setup.sh              # Setup and validation script
├── requirements.txt         # Python dependencies
├── alerts/                  # Generated alerts (JSON)
├── log/                     # Service logs
├── model/                   # Trained ML model
├── statistics/              # Detection statistics (JSON)
├── src/                     # Source code
│ ├── alert_generator.py
│ ├── csv_monitor.py
│ ├── detection_engine.py
│ ├── feature_mapper.py
│ └── train_model.py
└── venv/                    # Python virtual environment
```


## Requirements

### System Requirements
- GNU-Linux(Tested on Debian13)
- Python 3.8 or higher
- 8GB RAM minimum (for training)

### Python Dependencies
```bash
scikit-learn>=1.3.0
pandas>=2.0.0
numpy>=1.24.0
joblib>=1.3.0
imbalanced-learn>=0.11.0
watchdog>=3.0.0
```

### Dataset Requirements
- **CICIDS2017 Dataset**: Required for training
- Location: `/root/Thesis/dataset/CIC-IDS-2017/CSVs/MachineLearningCVE/`
- Required files:
  - `Monday-WorkingHours.pcap_ISCX.csv`
  - `Tuesday-WorkingHours.pcap_ISCX.csv`

## Installation

### 1. Run Setup Script
```bash
cd /root/Thesis/ml
chmod +x ml_setup.sh
./ml_setup.sh
```

The setup script will:
- Check Python 3.8+ version
- Create virtual environment
- Install all dependencies
- Validate `ml_config.json`
- Check CICIDS2017 dataset files
- Verify directory structure

### 2. Activate Virtual Environment
```bash
source venv/bin/activate
```

### 3. Train the Model
```bash
python3 src/train_model.py
```

Training time depends on your system resources and produces:
- `model/ssh_bruteforce_model.pkl` - Trained Random Forest model
- `model/feature_scaler.pkl` - Feature scaling parameters
- `model/feature_names.json` - Column names for validation

## Configuration

Edit `ml_config.json` to match your configuration:
```bash
{
    "detection": {
        "threshold": 0.80,                      // - Attack probability threshold (0.80 = 80% confidence required)
        "min_attack_flows": 3,                  // - Minimum attack flows to trigger alert
        "window_size_minutes": 5,               // - Rolling window size for aggregation
        "window_mode": "rolling",               // - Window mode (rolling or fixed)
        "ssh_port": 22                          // - SSH port number to filter
    },
    "paths": {
        "csv_input": "/root/Thesis/pipeline_pcap/csv/",                          // - Input directory for CSV files from pipeline
        "csv_processed": "/root/Thesis/pipeline_pcap/processed/",                // - Destination for processed CSV files
        "alerts": "/root/Thesis/ml/alerts/",                                     // - Output directory for alert JSON files
        "logs": "/root/Thesis/ml/log/",                                          // - Logging directory for ML service
        "statistics": "/root/Thesis/ml/statistics/",                             // - Output directory for statistics JSON files
        "models": "/root/Thesis/ml/model/",                                      // - Directory for trained ML models
        "dataset": "/root/Thesis/dataset/CIC-IDS-2017/CSVs/MachineLearningCVE/"  // - CICIDS2017 training dataset location
    },
    "processing": {
        "wait_time_seconds": 10,                // - Wait 10 seconds after CSV detection before processing
        "process_existing_on_startup": "True",  // - Process existing CSV files when service starts
        "sequential_processing": "True",        // - Process one CSV at a time (not parallel)
        "max_csv_cache_size": 10                // - Maximum CSVs to keep in processing queue
    },
    "logging": {
        "level": "INFO",                                                  // - Log level (DEBUG/INFO/WARNING/ERROR)
        "max_bytes": 1073741824,                                          // - Rotate log at 1GB (1024^3 bytes)
        "backup_count": 5,                                                // - Keep 5 old log files after rotation
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"  // - Log message format pattern
    },
    "model": {
        "algorithm": "random_forest",           // - ML algorithm type (random_forest)
        "random_forest": {
            "n_estimators": 100,                // - Number of trees in forest (100)
            "max_depth": 20,                    // - Maximum tree depth (20 levels)
            "min_samples_split": 5,             // - Minimum samples required to split node
            "min_samples_leaf": 2,              // - Minimum samples required in leaf node
            "class_weight": "balanced",         // - Balance class weights for imbalanced data
            "random_state": 42                  // - Random seed for reproducibility
        }
    }
}
```

## Training the Model

### Training Process

Activate environment
```bash
source venv/bin/activate
```

Run training
```bash
python3 src/train_model.py
```

### Training Workflow

1. **Load Data**: Monday + Tuesday CSV files (SSH-Patator + BENIGN)
2. **Preprocess**: Handle NaN/inf values, fill missing features
3. **Balance**: Apply SMOTE for class balancing
4. **Scale**: StandardScaler normalization
5. **Train**: Random Forest (100 estimators, max_depth=20)
6. **Evaluate**: Test on 20% holdout set
7. **Save**: Model, scaler, and feature names

### Training Output

Example Model Evaluation on Test Set

Accuracy: 0.9987  
Precision: 0.9984  
Recall: 0.9991  
F1-Score: 0.9987  
ROC-AUC: 0.9999  


## Usage

### Start Detection Service

Ensure virtual environment is activated
```bash
source venv/bin/activate
```
Start service
```bash
python3 ml_service.py start
```

### Detection Workflow

1. **Monitor**: Watches `csv_input/` directory for new CSV files
2. **Wait**: n-second delay ensures file is complete
3. **Map Features**: CICFlowMeter (84 cols) → CICIDS2017 (79 cols)
4. **Detect**: Run Random Forest prediction
5. **Alert**: Generate alerts if attacks detected
6. **Statistics**: Save detection statistics (only when attacks found)
7. **Move**: Transfer CSV to `pipeline_pcap/processed/` directory

### Stop the Service

Press `Ctrl+C` for graceful shutdown

## Feature Mapping

### Critical: Exact Column Name Matching

The feature mapper handles **inconsistent leading spaces** in CICIDS2017 dataset:
- 65 columns WITH leading space (e.g., `' Flow Duration'`)
- 14 columns WITHOUT leading space (e.g., `'Active Mean'`)

### Mapping Details

- **Source**: CICFlowMeter CSV (84 columns)
- **Target**: CICIDS2017 format (79 columns)
- **Mapped**: 78 features + 1 label
- **Duplicate**: `Fwd Header Len` → both `' Fwd Header Length'` and `' Fwd Header Length.1'`

### Example Mappings

CICFlowMeter → CICIDS2017

Dst Port → Destination Port (with space)  
Flow Byts/s → Flow Bytes/s (no space)  
Fwd Byts/b Avg → Fwd Avg Bytes/Bulk (no space)  
Active Mean → Active Mean (no space)  

## Output Files

### Alert Files

**Location**: `alerts/`  
**Format**: JSON  
**Naming**: `alert_{attacker_ip}_{timestamp}.json`  
**Created**: Only when attacks detected

Example alert:
```bash
{
    "alert_id": "SSH_BF_1921681050_20251027_153322",        // - Unique alert identifier (format: SSH_BF_ip_timestamp)
    "timestamp": "2025-10-27T15:33:22.123456",              // - ISO 8601 timestamp when alert was generated
    "attacker_ip": "192.168.10.50",                         // - Source IP address of attacker
    "attack_type": "SSH_BRUTE_FORCE",                       // - Type of detected attack (SSH_BRUTE_FORCE)
    "severity": "HIGH",                                     // - Alert severity level (LOW/MEDIUM/HIGH/CRITICAL)
    "total_flows": 47,                                      // - Total number of attack flows detected from this IP
    "confidence": {
        "average": 0.8734,                                  // - Average confidence score across all flows (87.34%)
        "min": 0.5124,                                      // - Minimum confidence score (51.24%)
        "max": 0.9987,                                      // - Maximum confidence score (99.87%)
        "breakdown": {
            "0.50-0.60": 2,                                 // - Number of flows with 50-60% confidence
            "0.60-0.70": 5,                                 // - Number of flows with 60-70% confidence
            "0.70-0.80": 8,                                 // - Number of flows with 70-80% confidence
            "0.80-0.90": 15,                                // - Number of flows with 80-90% confidence
            "0.90-1.00": 17                                 // - Number of flows with 90-100% confidence
        }
    },
    "flows": [...],                                            // - Array of detailed flow information (truncated)
    "source_csvs": ["capture_20251027_153221.pcap_Flow.csv"],  // - Source CSV files that contributed to detection
    "targets": [...]                                           // - Array of target systems/ports (truncated)
}

```


### Statistics Files

**Location**: `statistics/`  
**Format**: JSON  
**Naming**: `stats_{csv_base}_{timestamp}.json`  
**Created**: Only when attacks detected

Example statistics:
```bash
{
    "timestamp": "2025-10-27T15:33:22.456789",                // - ISO 8601 timestamp when statistics were generated
    "csv_filename": "capture_20251027_153221.pcap_Flow.csv",  // - Source CSV file that was analyzed
    "processing_time": 0.842,                                 // - Time taken to process CSV in seconds (0.842s)
    "total_flows": 140,                                       // - Total number of network flows in CSV file
    "attack_flows": 47,                                       // - Number of flows classified as attacks
    "attack_percentage": 33.57,                               // - Percentage of flows that are attacks (33.57%)
    "unique_attackers": 1,                                    // - Number of distinct attacker IP addresses
    "confidence": {
        "average": 0.8734,                                    // - Average confidence score across attack flows (87.34%)
        "min": 0.5124,                                        // - Lowest confidence score among attacks (51.24%)
        "max": 0.9987,                                        // - Highest confidence score among attacks (99.87%)
        "breakdown": {...}                                    // - Distribution of flows by confidence ranges
    },
    "model": {
        "model_type": "RandomForestClassifier",               // - ML algorithm used (Random Forest)
        "threshold": 0.80,                                    // - Minimum probability for attack classification
        "window_mode": "rolling"                              // - Detection window mode (rolling or fixed)
    }
}

```

### Logs

**Location**: `logs/`  
**Format**: Rotating log files (1GB max, 5 backups)  
**Naming**: `ml_service_YYYYMMDD.log`

## Monitoring

### Performance Metrics

Logged for each CSV:
- Processing time (seconds)
- Flow count analyzed
- Attacks detected
- Confidence scores
- Memory usage

## Model Performance

### Training Dataset
- **Monday**: BENIGN traffic only
- **Tuesday**: SSH-Patator attacks + BENIGN traffic
- **Split**: 80% training, 20% testing
- **Class Balance**: SMOTE applied

### Evaluation Metrics
- **Accuracy**: ~99.87%
- **Precision**: ~99.84% (low false positives)
- **Recall**: ~99.91% (low false negatives)
- **F1-Score**: ~99.87% (balanced performance)
- **ROC-AUC**: ~99.99% (excellent discrimination)

### Detection Characteristics
- **Real-time**: Processes CSVs as they arrive
- **Latency**: ~1 second per CSV
- **Throughput**: Can handle 60 CSVs/minute
- **Accuracy**: Maintains high accuracy on live traffic

## Integration Notes

### Pipeline → ML Flow

1. Pipeline creates CSV in `pipeline_pcap/csv/`
2. ML monitors same directory
3. ML waits 10 seconds after detection
4. ML processes CSV with detection engine
5. ML moves CSV to `pipeline_pcap/processed/`
6. Alerts/statistics generated if attacks found

## References

- CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- CICFlowMeter: https://github.com/ahlashkari/CICFlowMeter

## Credits

- **CICFlowMeter**: Canadian Institute for Cybersecurity
- **CICIDS2017 Dataset**: Used for ML training

## License

Part of Engineer's Thesis project - Network Security with ML
