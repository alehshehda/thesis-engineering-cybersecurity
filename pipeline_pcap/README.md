# PCAP Pipeline Module

Network traffic capture and processing pipeline for SSH brute-force detection thesis project.

## Overview

The pipeline module captures network traffic, rotates PCAP files automatically, and converts them to CSV format using Java CICFlowMeter. It provides continuous monitoring with automatic cleanup of old files.

## Architecture

```

┌─────────────────┐
│     tcpdump     |
|Captures packets |
|   60s rotation  |
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    PCAP Files   |
| Stored in pcap/ | 
|    directory    │ 
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ File Watcher    |
| for PCAP files  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│JavaCICFlowMeter │
|   PCAP → CSV    |
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ CSV Files       |
│ Ready for ML    |
| detection       |
└─────────────────┘
```

## Directory Structure
```
/root/Thesis/pipeline_pcap/  
├── pipeline_pcap.py         # Main pipeline script  
├── pipeline_config.json     # Configuration file  
├── cic_cmd.sh               # CICFlowMeter wrapper script  
├── pipeline_setup.sh        # Setup and validation script  
├── requirements.txt         # Python dependencies 
├── pcap/                    # Captured PCAP files  
├── csv/                     # Converted CSV files  
├── log/                     # Pipeline logs  
│      └── cicflowmeter_log/ # CICFlowMeter logs  
```


## Requirements

### System Requirements
- GNU-Linux(Tested on Debian13)
- Root privileges (for packet capture)
- Python 3.8 or higher
- Java Runtime Environment (for CICFlowMeter)

### Dependencies
- **tcpdump**: Network packet capture
- **Java**: CICFlowMeter execution
- **Python packages**: watchdog>=3.0.0

### External Tools
- **CICFlowMeter**: Installed at `/root/CICFlowMeter/`
- **jnetpcap**: Native library for CICFlowMeter

## Installation

### 1. Install System Dependencies

Install tcpdump and Java
```bash
sudo apt update  
sudo apt upgrade -y  
sudo apt install default-jdk   
sudo apt install libpcap-dev  
```


### 2. Install CICFlowMeter

Follow CICFlowMeter installation guide and install to `/root/CICFlowMeter/` - https://github.com/UNBCIC/CICFlowMeter

### 3. Run Setup Script
```bash
cd /root/Thesis/pipeline_pcap  
chmod +x pipeline_setup.sh
```


The setup script will:
- Check Python version
- Create virtual environment
- Install Python dependencies
- Validate configuration
- Check network interface
- Verify CICFlowMeter installation
- Create required directories

### 4. Activate Virtual Environment

```bash
source venv/bin/activate
```

## Configuration

Edit `pipeline_config.json` to match your configuration:
```bash
{
  "capture": {
    "interface": "enp1s0",                    // - Network interface to capture packets from
    "bpf_filter": "host 192.168.10.50",       // - Berkeley Packet Filter for selective traffic capture
    "snaplen": 128,                           // - Maximum bytes per packet (128 = headers only)
    "rotation_seconds": 60,                   // - Create new PCAP file every 60 seconds
    "enabled": true                           // - Enable/disable packet capture
  },
  "paths": {
    "pcap_dir": "/root/Thesis/pipeline_pcap/pcap",                    // - Storage for captured PCAP files
    "csv_dir": "/root/Thesis/pipeline_pcap/csv",                      // - Output directory for converted CSV files
    "csv_processed_dir": "/root/Thesis/pipeline_pcap/processed",      // - Output directory for processed CSV files
    "log_dir": "/root/Thesis/pipeline_pcap/log",                      // - Main pipeline logging directory
    "cic_log_dir": "/root/Thesis/pipeline_pcap/log/cicflowmeter_log"  // - CICFlowMeter Java process logs
  },
  "retention": {
    "pcap_minutes": 30,                       // - Keep PCAP files for 30 minutes before deletion
    "csv_minutes": 30,                        // - Keep CSV files for 30 minutes before deletion
    "processed_csv_minutes": 30,              // - Keep processed CSV files for 30 minutes before deletion
    "cleanup_interval_seconds": 60            // - Run cleanup check every 60 seconds
  },
  "processing": {
    "worker_threads": 2,                      // - Number of parallel conversion workers
    "conversion_timeout": 300,                // - Kill conversion after 5 minutes (300 seconds)
    "max_retries": 3,                         // - Retry failed conversions up to 3 times
    "processing_delay_seconds": 2,            // - Delay between file operations
    "file_close_wait_seconds": 5              // - Wait 5 seconds after rotation before processing
  },
  "java_cicflowmeter": {
    "cic_cmd_script": "/root/Thesis/pipeline_pcap/cic_cmd.sh",   // - Path to CICFlowMeter wrapper script
    "enabled": true                                              // - Enable/disable CICFlowMeter conversion
  },
  "logging": {
    "level": "INFO",                                        // - Log level (DEBUG/INFO/WARNING/ERROR)
    "format": "%(asctime)s - %(levelname)s - %(message)s",  // - Log message format/pattern
    "max_bytes": 1073741824,                                // - Rotate log at 1GB (1024^3 bytes)
    "backup_count": 5                                       // - Keep 5 old log files after rotation
  }
}


```

## Usage

### Start the Pipeline

Ensure virtual environment is activated
```bash
source venv/bin/activate  
```

Run pipeline (requires root for packet capture)
```bash
sudo python3 pipeline_pcap.py
```

### Pipeline Workflow

1. **Capture**: tcpdump captures packets for 60 seconds
2. **Rotate**: New PCAP file created, previous file closed
3. **Wait**: 5-second buffer ensures file is fully written
4. **Convert**: Previous PCAP converted to CSV using CICFlowMeter
5. **Output**: CSV file ready for ML detection module
6. **Cleanup**: Old files removed based on retention policy

### Stop the Pipeline

Press `Ctrl+C` for graceful shutdown. The pipeline will:
- Stop tcpdump
- Complete pending conversions
- Clean up resources

## Output Files

### PCAP Files
- **Location**: `pcap/`
- **Naming**: `capture_YYYYMMDD_HHMMSS.pcap`
- **Retention**: 30 minutes (configurable)

### CSV Files
- **Location**: `csv/`
- **Naming**: `capture_YYYYMMDD_HHMMSS.pcap_Flow.csv`
- **Format**: 84 columns (CICFlowMeter output)
- **Retention**: 30 minutes (configurable)

### Logs
- **Pipeline log**: `log/pipeline_pcap.log`
- **CICFlowMeter logs**: `log/cicflowmeter_log/`

## Monitoring

### Performance Metrics

Logged in pipeline_pcap.log:
- Conversion time per PCAP
- Flow count per CSV
- Queue size
- Cleanup statistics

## Integration with ML Module

The pipeline outputs CSV files to `csv/` directory. The ML module monitors this directory for new files:

CSV files are automatically:
1. Detected by ML module's CSV monitor
2. Processed for SSH brute-force detection
3. Moved to `processed/` after analysis

## References

- CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- CICFlowMeter: https://github.com/ahlashkari/CICFlowMeter

## Credits

- **CICFlowMeter**: Canadian Institute for Cybersecurity
- **CICIDS2017 Dataset**: Used for ML training

## License

Part of Engineer's Thesis project - Network Security with ML
