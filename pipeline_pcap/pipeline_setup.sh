#!/bin/bash

# Pipeline Module Setup Script
# Sets up Python environment and validates configuration for PCAP pipeline

set -e

echo "=== Pipeline Module Setup ==="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check Python version
echo "Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_VERSION="3.8"

if [[ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]]; then
    echo -e "${RED}ERROR: Python 3.8 or higher is required (found $PYTHON_VERSION)${NC}"
    exit 1
fi
echo -e "${GREEN}Python version: $PYTHON_VERSION${NC}"
echo ""

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment already exists${NC}"
    read -p "Do you want to recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing existing virtual environment..."
        rm -rf venv
    fi
fi

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo -e "${GREEN}Virtual environment created${NC}"
fi
echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1

# Install requirements
if [ -f "requirements.txt" ]; then
    echo "Installing requirements from requirements.txt..."
    pip install -r requirements.txt
    echo -e "${GREEN}Requirements installed${NC}"
else
    echo -e "${RED}ERROR: requirements.txt not found${NC}"
    exit 1
fi
echo ""

# Verify directories
echo "Verifying directory structure..."
REQUIRED_DIRS=("pcap" "csv" "log" "log/cicflowmeter_log")

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        echo "Creating directory: $dir"
        mkdir -p "$dir"
    fi
done
echo -e "${GREEN}Directory structure verified${NC}"
echo ""

# Verify pipeline_config.json
echo "Checking configuration file..."
if [ ! -f "pipeline_config.json" ]; then
    echo -e "${RED}ERROR: pipeline_config.json not found${NC}"
    echo "Please create pipeline_config.json before running setup"
    exit 1
fi

# Validate JSON syntax
python3 -c "import json; json.load(open('pipeline_config.json'))" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}pipeline_config.json is valid${NC}"
else
    echo -e "${RED}ERROR: pipeline_config.json has invalid JSON syntax${NC}"
    exit 1
fi
echo ""

# Check for cic_cmd.sh
echo "Checking CICFlowMeter wrapper script..."
if [ ! -f "cic_cmd.sh" ]; then
    echo -e "${RED}ERROR: cic_cmd.sh not found${NC}"
    echo "Please ensure cic_cmd.sh exists in the pipeline directory"
    exit 1
fi

# Make cic_cmd.sh executable
chmod +x cic_cmd.sh 2>/dev/null || true
if [ -x "cic_cmd.sh" ]; then
    echo -e "${GREEN}cic_cmd.sh is executable${NC}"
else
    echo -e "${YELLOW}WARNING: Could not make cic_cmd.sh executable${NC}"
    echo "You may need to run: chmod +x cic_cmd.sh"
fi
echo ""

# Check Java installation
echo "Checking Java installation..."
if command -v java &> /dev/null; then
    JAVA_VERSION=$(java -version 2>&1 | head -n 1)
    echo -e "${GREEN}Java found: $JAVA_VERSION${NC}"
else
    echo -e "${RED}ERROR: Java not found${NC}"
    echo "CICFlowMeter requires Java to be installed"
    exit 1
fi
echo ""

# Check CICFlowMeter installation
echo "Checking CICFlowMeter installation..."
CONFIG_CIC_PATH=$(python3 -c "import json; print(json.load(open('pipeline_config.json'))['java_cicflowmeter']['cic_cmd_script'])" 2>/dev/null)

if [ -z "$CONFIG_CIC_PATH" ]; then
    echo -e "${YELLOW}WARNING: Could not read CICFlowMeter path from config${NC}"
else
    if [ -f "$CONFIG_CIC_PATH" ]; then
        echo -e "${GREEN}CICFlowMeter script found: $CONFIG_CIC_PATH${NC}"
    else
        echo -e "${YELLOW}WARNING: CICFlowMeter script not found: $CONFIG_CIC_PATH${NC}"
        echo "Pipeline may fail if CICFlowMeter is not properly installed"
    fi
fi
echo ""

# Check network interface
echo "Checking network interface..."
CONFIG_INTERFACE=$(python3 -c "import json; print(json.load(open('pipeline_config.json'))['capture']['interface'])" 2>/dev/null)

if [ -z "$CONFIG_INTERFACE" ]; then
    echo -e "${YELLOW}WARNING: Could not read interface from config${NC}"
else
    if ip link show "$CONFIG_INTERFACE" &> /dev/null; then
        echo -e "${GREEN}Network interface found: $CONFIG_INTERFACE${NC}"
    else
        echo -e "${RED}ERROR: Network interface not found: $CONFIG_INTERFACE${NC}"
        echo "Available interfaces:"
        ip -brief link show | awk '{print "  - " $1}'
        echo ""
        echo "Please update pipeline_config.json with a valid interface"
        exit 1
    fi
fi
echo ""

# Check for root privileges requirement
echo "Checking privileges..."
if [ "$EUID" -eq 0 ]; then
    echo -e "${GREEN}Running as root (required for packet capture)${NC}"
else
    echo -e "${YELLOW}WARNING: Not running as root${NC}"
    echo "The pipeline requires root privileges to capture packets"
    echo "Run the pipeline with: sudo python3 pipeline_pcap.py"
fi
echo ""

# Check tcpdump
echo "Checking tcpdump installation..."
if command -v tcpdump &> /dev/null; then
    TCPDUMP_VERSION=$(tcpdump --version 2>&1 | head -n 1)
    echo -e "${GREEN}tcpdump found: $TCPDUMP_VERSION${NC}"
else
    echo -e "${RED}ERROR: tcpdump not found${NC}"
    echo "Install with: sudo apt-get install tcpdump"
    exit 1
fi
echo ""

# Summary
echo "=== Setup Complete ==="
echo ""
echo "To activate the environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "To start the pipeline, run:"
echo "  sudo python3 pipeline_pcap.py"
echo ""
echo "Pipeline will:"
echo "  1. Capture packets on interface: $CONFIG_INTERFACE"
echo "  2. Rotate PCAP files every 60 seconds"
echo "  3. Convert completed PCAPs to CSV using CICFlowMeter"
echo "  4. Clean up old files based on retention policy"
echo ""
echo "Logs will be written to: log/pipeline_pcap.log"
echo "PCAPs will be stored in: pcap/"
echo "CSVs will be stored in: csv/"
echo ""
