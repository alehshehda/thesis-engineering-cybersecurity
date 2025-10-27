#!/bin/bash

# CICFlowMeter Wrapper Script
# Converts PCAP to CSV using Java CICFlowMeter

set -e

# Usage validation
if [ $# -lt 2 ]; then
    echo "Error: Invalid number of arguments" >&2
    echo "Usage: $0 <input_pcap> <output_dir> [log_directory]" >&2
    exit 1
fi

INPUT_PCAP="$1"
OUTPUT_DIR="$2"
LOG_DIR="${3:-/root/Thesis/pipeline_pcap/log/cicflowmeter_log}"

# Convert to absolute paths
INPUT_PCAP=$(realpath "$INPUT_PCAP")
OUTPUT_DIR=$(realpath "$OUTPUT_DIR")
LOG_DIR=$(realpath "$LOG_DIR")

# Validate input PCAP exists
if [ ! -f "$INPUT_PCAP" ]; then
    echo "Error: Input PCAP file not found: $INPUT_PCAP" >&2
    exit 1
fi

# Create directories
mkdir -p "$OUTPUT_DIR"
mkdir -p "$LOG_DIR"

# Java CICFlowMeter configuration
CLASSPATH="/root/CICFlowMeter/build/distributions/CICFlowMeter-4.0/lib/*"
LIBRARY_PATH="/root/CICFlowMeter/jnetpcap/linux/jnetpcap-1.4.r1425/"
MAIN_CLASS="cic.cs.unb.ca.ifm.Cmd"

# Create timestamped log file for this script
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_BASENAME=$(basename "$INPUT_PCAP" .pcap)
SCRIPT_LOG="${LOG_DIR}/${PCAP_BASENAME}_${TIMESTAMP}.log"

# Change to log directory before running Java
# This makes CICFlowMeter create its logs/ folder inside LOG_DIR
cd "$LOG_DIR"

# Execute Java CICFlowMeter with log redirection
{
    echo "==================================="
    echo "CICFlowMeter Conversion"
    echo "==================================="
    echo "Start time: $(date)"
    echo "Input PCAP: $INPUT_PCAP"
    echo "Output DIR: $OUTPUT_DIR"
    echo "Working DIR: $LOG_DIR"
    echo "-----------------------------------"

    java -cp "$CLASSPATH" \
        -Djava.library.path="$LIBRARY_PATH" \
        "$MAIN_CLASS" \
        "$INPUT_PCAP" \
        "$OUTPUT_DIR"

    EXIT_CODE=$?

    echo "-----------------------------------"
    echo "End time: $(date)"
    echo "Exit code: $EXIT_CODE"
    echo "==================================="

    exit $EXIT_CODE

} >> "$SCRIPT_LOG" 2>&1

EXIT_CODE=$?

# Verify output was created
if [ $EXIT_CODE -eq 0 ]; then
    PCAP_NAME=$(basename "$INPUT_PCAP")
    EXPECTED_CSV="${OUTPUT_DIR}/${PCAP_NAME}_Flow.csv"

    if [ -f "$EXPECTED_CSV" ]; then
        echo "Success: CSV created at $EXPECTED_CSV"
        exit 0
    else
        echo "Error: Expected output not found: $EXPECTED_CSV" >&2
        exit 1
    fi
else
    echo "Error: CICFlowMeter failed with exit code $EXIT_CODE" >&2
    echo "Check log: $SCRIPT_LOG" >&2
    exit $EXIT_CODE
fi
