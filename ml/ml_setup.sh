#!/bin/bash

# ML Module Setup Script
# Sets up Python environment and validates configuration

set -e

echo "=== ML Module Setup ==="
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
REQUIRED_DIRS=("alerts" "log" "model" "statistics" "src")

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        echo "Creating directory: $dir"
        mkdir -p "$dir"
    fi
done
echo -e "${GREEN}Directory structure verified${NC}"
echo ""

# Verify ml_config.json
echo "Checking configuration file..."
if [ ! -f "ml_config.json" ]; then
    echo -e "${RED}ERROR: ml_config.json not found${NC}"
    echo "Please create ml_config.json before running setup"
    exit 1
fi

# Validate JSON syntax
python3 -c "import json; json.load(open('ml_config.json'))" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}ml_config.json is valid${NC}"
else
    echo -e "${RED}ERROR: ml_config.json has invalid JSON syntax${NC}"
    exit 1
fi
echo ""

# Check CICIDS2017 dataset
echo "Checking CICIDS2017 dataset..."
CONFIG_DATASET_PATH=$(python3 -c "import json; print(json.load(open('ml_config.json'))['paths']['dataset'])")

if [ ! -d "$CONFIG_DATASET_PATH" ]; then
    echo -e "${RED}ERROR: Dataset directory not found: $CONFIG_DATASET_PATH${NC}"
    exit 1
fi

# Check for required CSV files
REQUIRED_FILES=(
    "Monday-WorkingHours.pcap_ISCX.csv"
    "Tuesday-WorkingHours.pcap_ISCX.csv"
)

MISSING_FILES=0
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$CONFIG_DATASET_PATH/$file" ]; then
        echo -e "${RED}Missing dataset file: $file${NC}"
        MISSING_FILES=$((MISSING_FILES + 1))
    fi
done

if [ $MISSING_FILES -eq 0 ]; then
    echo -e "${GREEN}CICIDS2017 dataset files found${NC}"
else
    echo -e "${YELLOW}WARNING: $MISSING_FILES dataset file(s) missing${NC}"
    echo "Training may fail if required files are not available"
fi
echo ""

# Summary
echo "=== Setup Complete ==="
echo ""
echo "To activate the environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "To train the model, run:"
echo "  python3 src/train_model.py"
echo ""
echo "To start the ML service, run:"
echo "  python3 ml_service.py start"
echo ""
