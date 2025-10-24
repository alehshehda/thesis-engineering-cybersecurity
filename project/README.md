# PCAP Rotation and FlowMeter Conversion Pipeline

A robust Python pipeline that captures network traffic with tcpdump, automatically rotates PCAP files, converts them to CSV format using **CICFlowMeter** or **NexusFlowMeter**, and manages file retention policies. Specifically designed for ML-based network attack detection targeting LAN VM traffic (192.168.10.50).

## Features

- **Automated Network Capture**: Uses tcpdump to capture packets with BPF filtering
- **Time-based PCAP Rotation**: Creates new PCAP files every minute (60 seconds)
- **Dual FlowMeter Support**: Choose between CICFlowMeter (80 features) or NexusFlowMeter (34 features)
- **Real-time Processing**: Automatically converts PCAP files to CSV with parallel workers
- **File Management**: Automatic cleanup of old files based on retention policies
- **Disk Space Monitoring**: Continuous monitoring with low-space warnings
- **Robust Error Handling**: Retry logic, timeout control, and comprehensive error handling
- **Thread-safe Operations**: Multi-threaded processing with proper synchronization
- **Graceful Shutdown**: Handles interruption signals and processes final PCAP file

## Architecture

The pipeline consists of 6 concurrent components:

### Main Processing Flow
1. **tcpdump Capture**: Captures packets from network interface (enp1s0) with BPF filter
2. **Rotating PCAP Files**: Creates new file every 60 seconds using `-G` flag
3. **File Watcher**: Detects completed PCAP files via filesystem events (watchdog)
4. **Conversion Queue**: Thread-safe queue for pending conversions
5. **Conversion Workers (x2)**: Parallel processing of PCAP → CSV conversion
6. **CSV Output**: Network flow features extracted to CSV files

### Background Processes
- **Disk Space Monitor**: Checks every 60 seconds, warns if < 1GB free
- **Cleanup Manager**: Deletes old files every 30 seconds based on retention policy
- **Signal Handler**: Ensures graceful shutdown on Ctrl+C or SIGTERM

## Requirements

### System Requirements
- **Operating System**: Linux (tested on Ubuntu/Debian)
- **Python**: 3.8 or higher
- **Privileges**: Must run as root user for network capture
- **Network Interface**: Valid interface (e.g., enp1s0, eth0)

### Software Dependencies

```
# System packages
sudo apt update
sudo apt install tcpdump python3 python3-pip python3-venv

# Python packages
pip install watchdog
pip install cicflowmeter  # For CICFlowMeter
pip install nexusflowmeter  # For NexusFlowMeter
```

**Note**: Install only the flowmeter you plan to use, or install both for flexibility.

### Hardware Requirements
- Sufficient disk space for PCAP, CSV, and report files
- Network interface capable of promiscuous mode
- Recommended: 2+ CPU cores for parallel conversion

## Installation

1. **Clone or download the script**:
   ```
   git clone <repository-url>
   cd <project-directory>
   ```

2. **Set up Python virtual environment** (recommended):
   ```
   python3 -m venv venv
   source venv/bin/activate
   pip install watchdog cicflowmeter nexusflowmeter
   ```

3. **Configure the pipeline**:
   Edit the `Config` class in `pcap_pipeline.py` to match your environment:
   ```
   class Config:
       INTERFACE = "enp1s0"  # Your network interface
       BPF_FILTER = "host 192.168.10.50"  # Target IP address
       SNAPLEN = 128  # Capture length (matches CIC dataset standard)
       
       PCAP_DIR = "/root/Thesis/project/pcaps"  # PCAP storage directory
       CSV_DIR = "/root/Thesis/project/csv"     # CSV output directory
       LOG_DIR = "/root/Thesis/project/log"     # Log directory
       REPORTS_DIR = "/root/Thesis/project/reports"  # NexusFlowMeter reports
   ```

4. **Create necessary directories**:
   ```
   sudo mkdir -p /root/Thesis/project/{pcaps,csv,log,reports}
   ```

## Usage

### Basic Usage

**With CICFlowMeter** (80 features):
```
sudo python3 pcap_pipeline.py cicflowmeter
```

**With NexusFlowMeter** (34 features):
```
sudo python3 pcap_pipeline.py nexusflowmeter
```

### With Virtual Environment
```
sudo /path/to/venv/bin/python pcap_pipeline.py cicflowmeter
# or
sudo /path/to/venv/bin/python pcap_pipeline.py nexusflowmeter
```

### Command-Line Arguments

```
python3 pcap_pipeline.py <flowmeter>

Arguments:
  flowmeter    The flow meter to use for PCAP to CSV conversion
               Options: cicflowmeter, nexusflowmeter

Examples:
  python3 pcap_pipeline.py cicflowmeter
  python3 pcap_pipeline.py nexusflowmeter
```

## Configuration Options

The pipeline can be configured by modifying the `Config` class in `pcap_pipeline.py`:

### Network Capture Settings
- `INTERFACE`: Network interface to capture from (e.g., "eth0", "enp1s0")
- `BPF_FILTER`: Berkeley Packet Filter expression for traffic filtering
- `SNAPLEN`: Packet capture length in bytes (default: 128, matches CIC dataset standard)

### File Management
- `PCAP_DIR`: Directory to store PCAP files
- `CSV_DIR`: Directory to store converted CSV files
- `LOG_DIR`: Directory to store log files
- `REPORTS_DIR`: Directory for NexusFlowMeter reports (NexusFlowMeter only)

### Timing and Retention
- `ROTATION_SECONDS`: PCAP file rotation interval (default: 60 seconds)
  - **Note**: tcpdump `-G` rotation starts from first packet, not script start time
- `PCAP_RETENTION_MINUTES`: How long to keep PCAP files (default: 30 minutes)
- `CSV_RETENTION_MINUTES`: How long to keep CSV files (default: 30 minutes)
- `REPORTS_RETENTION_MINUTES`: How long to keep reports (default: 30 minutes, NexusFlowMeter only)

### Processing Settings
- `WORKER_THREADS`: Number of parallel conversion workers (default: 2)
- `MAX_CONVERSION_RETRIES`: Retry attempts for failed conversions (default: 3)
- `CONVERSION_RETRY_DELAY`: Delay between retry attempts in seconds (default: 5)
- `CONVERSION_TIMEOUT`: Maximum time for a single conversion in seconds (default: 300)
- `FILE_STABILITY_DELAY`: Wait time after tcpdump stop for file completion (default: 2 seconds)

### FlowMeter-Specific Settings

#### CICFlowMeter Options
- `CIC_VERBOSE`: Enable verbose logging (default: False)
- `CIC_FIELDS`: Comma-separated fields to include (default: None = all 80 features)

#### NexusFlowMeter Options
- `FLOW_TIMEOUT`: Flow timeout in seconds (default: 60)
- `MAX_WORKERS`: Max workers for chunk processing (default: 4)
- `OUTPUT_FORMAT`: Output format: csv, json, xlsx (default: "csv")
- `VERBOSE_NEXUS`: Enable verbose logging (default: False)

### Disk Space Monitoring
- `MIN_FREE_SPACE_MB`: Minimum free disk space threshold (default: 1000 MB = 1GB)
- `SPACE_CHECK_INTERVAL`: Disk space check interval in seconds (default: 60)

## File Structure

The pipeline creates the following directory structure:

```
/root/Thesis/project/
├── pcaps/              # Rotated PCAP files (60-second intervals)
├── csv/                # Converted CSV files with flow features
├── log/                # Pipeline log files
├── reports/            # NexusFlowMeter reports (NexusFlowMeter only)
└── pcap_pipeline.py    # Main pipeline script
```

### File Naming Convention
- **PCAP files**: `capture_YYYYMMDD_HHMMSS.pcap`
- **CSV files**: `capture_YYYYMMDD_HHMMSS.csv`
- **Log files**: `pipeline_YYYYMMDD_HHMMSS.log`
- **Report files**: `capture_YYYYMMDD_HHMMSS.txt` (NexusFlowMeter only)

## FlowMeter Comparison

| Feature | CICFlowMeter | NexusFlowMeter |
|---------|-------------|----------------|
| **Number of Features** | 80 | 34 |
| **Processing Speed** | Moderate | Fast |
| **Report Generation** | No | Yes (optional) |
| **Output Formats** | CSV only | CSV, JSON, XLSX |
| **Best For** | Comprehensive feature analysis | Real-time processing |
| **Memory Usage** | Higher | Lower |

## Monitoring and Logs

The pipeline provides comprehensive logging with the following levels:
- **INFO**: Normal operation status (startup, conversions, cleanup)
- **WARNING**: Non-critical issues (low disk space, slow conversions)
- **ERROR**: Critical errors (conversion failures, tcpdump crashes)
- **DEBUG**: Detailed diagnostics (enable with `LOG_LEVEL = logging.DEBUG`)

### Log Locations
- **Console**: Real-time output to terminal (stdout)
- **File**: Detailed logs in `/root/Thesis/project/log/pipeline_YYYYMMDD_HHMMSS.log`

### Key Log Messages

**Startup**:
```
[2025-10-19 15:00:00] INFO - PcapPipeline - Starting PCAP Rotation and CICFlowMeter Pipeline
[2025-10-19 15:00:00] INFO - PcapPipeline - Interface: enp1s0
[2025-10-19 15:00:00] INFO - PcapPipeline - BPF Filter: host 192.168.10.50
[2025-10-19 15:00:00] INFO - PcapPipeline - Pipeline started successfully
```

**File Processing**:
```
[2025-10-19 15:01:00] INFO - PcapFileHandler - Queuing PCAP for conversion: capture_20251019_150000.pcap
[2025-10-19 15:01:05] INFO - CICFlowMeterConverter - Converting capture_20251019_150000.pcap (attempt 1/3)
[2025-10-19 15:01:30] INFO - CICFlowMeterConverter - Successfully converted: capture_20251019_150000.pcap -> capture_20251019_150000.csv
```

**Cleanup**:
```
[2025-10-19 15:30:00] INFO - CleanupManager - Cleaned up 15 files from /root/Thesis/project/pcaps (older than 30 minutes)
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```
   ERROR: This script must be run as root user
   ```
   **Solution**: Run the script with sudo or as root user:
   ```
   sudo python3 pcap_pipeline.py cicflowmeter
   ```

2. **Interface Not Found**
   ```
   Error: Network interface 'enp1s0' not found or invalid
   ```
   **Solution**: 
   - List available interfaces: `ip link show`
   - Update `INTERFACE` in Config class to match your interface

3. **FlowMeter Not Found**
   ```
   Error: cicflowmeter not found. Please install: pip install cicflowmeter
   ```
   **Solution**: Install the required flowmeter:
   ```
   pip install cicflowmeter
   # or
   pip install nexusflowmeter
   ```

4. **Invalid FlowMeter Argument**
   ```
   Error: Invalid flowmeter type 'cic'
   ```
   **Solution**: Use the correct argument:
   ```
   sudo python3 pcap_pipeline.py cicflowmeter  # Not 'cic'
   ```

5. **Disk Space Issues**
   ```
   Warning: Low disk space: 500.00 MB free (minimum: 1000 MB)
   ```
   **Solution**: 
   - Free up disk space
   - Reduce retention times in Config
   - Adjust `MIN_FREE_SPACE_MB` threshold

6. **Conversion Timeout**
   ```
   Error: CICFlowMeter processing timeout (300s) for capture_20251019_150000.pcap. Process killed.
   ```
   **Solution**: 
   - Increase `CONVERSION_TIMEOUT` in Config
   - Check if PCAP files are too large
   - Verify system resources (CPU, memory)

7. **tcpdump Crashed**
   ```
   Error: tcpdump process died unexpectedly
   ```
   **Solution**:
   - Check interface status: `ip link show enp1s0`
   - Verify BPF filter syntax
   - Check system logs: `dmesg | grep tcpdump`

### Debugging Steps

1. **Enable Debug Logging**:
   ```
   # In Config class
   LOG_LEVEL = logging.DEBUG
   ```

2. **Check Process Status**:
   ```
   # Check if tcpdump is running
   ps aux | grep tcpdump
   
   # Check Python processes
   ps aux | grep python
   
   # Check open files
   lsof | grep capture
   ```

3. **Monitor File Creation**:
   ```
   # Watch PCAP directory
   watch -n 1 'ls -lh /root/Thesis/project/pcaps/'
   
   # Watch CSV directory
   watch -n 1 'ls -lh /root/Thesis/project/csv/'
   ```

4. **Test Network Interface**:
   ```
   # Test tcpdump manually
   sudo tcpdump -i enp1s0 -c 10 host 192.168.10.50
   ```

5. **Check Disk Space**:
   ```
   df -h /root/Thesis/project/
   ```

6. **Verify FlowMeter Installation**:
   ```
   # Test CICFlowMeter
   cicflowmeter --help
   
   # Test NexusFlowMeter
   nexusflowmeter --help
   ```

### Performance Optimization

1. **Adjust Worker Threads**: 
   - Increase `WORKER_THREADS` for faster CSV processing (requires more CPU)
   - Recommended: 1 worker per CPU core available

2. **Optimize Retention Policies**:
   - Balance storage needs with retention times
   - Monitor disk usage patterns
   - Adjust `*_RETENTION_MINUTES` values

3. **Reduce Capture Size**:
   - Use more specific BPF filters
   - Adjust `SNAPLEN` if full packets aren't needed
   - Consider using NexusFlowMeter for faster processing

4. **Monitor System Resources**:
   ```
   # CPU usage
   htop
   
   # I/O statistics
   iostat -x 1
   
   # Disk usage
   du -sh /root/Thesis/project/*
   ```

5. **Increase Conversion Timeout**:
   - For large PCAP files, increase `CONVERSION_TIMEOUT`
   - Default 300s (5 minutes) may be insufficient for busy networks

## Pipeline Behavior

### Rotation Timing
- tcpdump `-G` flag starts rotation from **first captured packet**, not script start
- With sparse traffic (e.g., idle VM), rotation times may drift from expected 60-second boundaries
- This is normal tcpdump behavior and documented in the code

### File Completion Detection
- **During runtime**: New file creation triggers processing of previous file
- **On startup**: Existing files checked for stability (size unchanged for 0.5s)
- **On shutdown**: Final PCAP file is queued after 2-second stability delay

### Graceful Shutdown
1. Receives Ctrl+C or SIGTERM signal
2. Stops tcpdump with SIGTERM (allows graceful exit)
3. Waits for file stability
4. Queues final PCAP file for conversion
5. Stops file watcher
6. Waits for pending conversions (60-second timeout)
7. Stops all workers and cleanup processes
8. Reports any failed conversions

## Security Considerations

- **Root Privileges**: Required for packet capture (tcpdump)
- **Network Interface Validation**: Regex check prevents injection attacks
- **Subprocess Safety**: All commands use `shell=False` and validated inputs
- **Timeout Protection**: All subprocess calls have timeouts to prevent hanging
- **Process Cleanup**: Timed-out processes are explicitly killed

## License

This project is provided as-is for educational and research purposes.

## Contributing

For bug reports, feature requests, or contributions, please contact the project maintainer.

## References

- **CICFlowMeter**: https://pypi.org/project/cicflowmeter/
- **NexusFlowMeter**: https://github.com/Collgamer0008/NexusFlowMeter
- **tcpdump**: https://www.tcpdump.org/
- **Python Watchdog**: https://pypi.org/project/watchdog/