#!/bin/bash

#==============================================================================
# Pipeline Module Setup Script
# Description: Sets up Python environment and validates PCAP pipeline configuration
# Requirements: Python 3.8+, Java, tcpdump, root privileges
#==============================================================================

set -o pipefail

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------
readonly THESIS_ROOT="/root/Thesis"
readonly MODULE_DIR="${THESIS_ROOT}/pipeline_pcap"
readonly VENV_DIR="${MODULE_DIR}/venv"
readonly CONFIG_FILE="pipeline_config.json"
readonly REQUIREMENTS_FILE="requirements.txt"
readonly REQUIRED_PYTHON_VERSION="3.8"

readonly REQUIRED_DIRS=(
    "pcap"
    "csv"
    "log"
    "log/cicflowmeter_log"
)

#------------------------------------------------------------------------------
# Logging Functions
#------------------------------------------------------------------------------
log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "[OK] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
}

log_warn() {
    echo "[WARN] $1" >&2
}

#------------------------------------------------------------------------------
# Validation Functions
#------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run with root privileges"
        exit 1
    fi
    log_success "Running with root privileges"
}

check_python_version() {
    log_info "Checking Python version"

    if ! command -v python3 &>/dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi

    local python_version
    python_version=$(python3 --version 2>&1 | awk '{print $2}')

    if [[ "$(printf '%s\n' "${REQUIRED_PYTHON_VERSION}" "${python_version}" | sort -V | head -n1)" != "${REQUIRED_PYTHON_VERSION}" ]]; then
        log_error "Python ${REQUIRED_PYTHON_VERSION}+ is required (found ${python_version})"
        exit 1
    fi

    log_success "Python version: ${python_version}"
}

check_java() {
    log_info "Checking Java installation"

    if ! command -v java &>/dev/null; then
        log_error "Java is not installed (required for CICFlowMeter)"
        exit 1
    fi

    local java_version
    java_version=$(java -version 2>&1 | head -n 1)
    log_success "Java found: ${java_version}"
}

check_tcpdump() {
    log_info "Checking tcpdump installation"

    if ! command -v tcpdump &>/dev/null; then
        log_error "tcpdump is not installed"
        log_error "Install with: sudo apt-get install tcpdump"
        exit 1
    fi

    local tcpdump_version
    tcpdump_version=$(tcpdump --version 2>&1 | head -n 1)
    log_success "tcpdump found: ${tcpdump_version}"
}

#------------------------------------------------------------------------------
# Setup Functions
#------------------------------------------------------------------------------
setup_virtual_environment() {
    log_info "Setting up Python virtual environment"

    if [[ -d "${VENV_DIR}" ]]; then
        log_warn "Virtual environment already exists"
        read -p "Do you want to recreate it? (y/N): " -n 1 -r
        echo

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Removing existing virtual environment"
            rm -rf "${VENV_DIR}"
        else
            log_info "Using existing virtual environment"
            return 0
        fi
    fi

    if ! python3 -m venv "${VENV_DIR}"; then
        log_error "Failed to create virtual environment"
        exit 1
    fi

    log_success "Virtual environment created"
}

install_dependencies() {
    log_info "Installing Python dependencies"

    if [[ ! -f "${REQUIREMENTS_FILE}" ]]; then
        log_error "${REQUIREMENTS_FILE} not found"
        exit 1
    fi

    source "${VENV_DIR}/bin/activate"

    if ! pip install --upgrade pip setuptools wheel >/dev/null 2>&1; then
        log_error "Failed to upgrade pip"
        exit 1
    fi

    if ! pip install -r "${REQUIREMENTS_FILE}" >/dev/null 2>&1; then
        log_error "Failed to install requirements"
        exit 1
    fi

    log_success "Dependencies installed"
}

create_directory_structure() {
    log_info "Creating directory structure"

    for dir in "${REQUIRED_DIRS[@]}"; do
        if ! mkdir -p "${dir}"; then
            log_error "Failed to create directory: ${dir}"
            exit 1
        fi
    done

    log_success "Directory structure created"
}

validate_config_file() {
    log_info "Validating configuration file"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_error "${CONFIG_FILE} not found"
        exit 1
    fi

    if ! python3 -c "import json; json.load(open('${CONFIG_FILE}'))" 2>/dev/null; then
        log_error "${CONFIG_FILE} has invalid JSON syntax"
        exit 1
    fi

    log_success "Configuration file is valid"
}

check_cic_wrapper() {
    log_info "Checking CICFlowMeter wrapper script"

    if [[ ! -f "cic_cmd.sh" ]]; then
        log_error "cic_cmd.sh not found"
        exit 1
    fi

    if ! chmod +x cic_cmd.sh 2>/dev/null; then
        log_warn "Could not make cic_cmd.sh executable"
    else
        log_success "cic_cmd.sh is executable"
    fi
}

check_network_interface() {
    log_info "Checking network interface"

    local interface
    interface=$(python3 -c "import json; print(json.load(open('${CONFIG_FILE}'))['capture']['interface'])" 2>/dev/null)

    if [[ -z "${interface}" ]]; then
        log_warn "Could not read interface from config"
        return 0
    fi

    if ! ip link show "${interface}" &>/dev/null; then
        log_error "Network interface not found: ${interface}"
        log_error "Available interfaces:"
        ip -brief link show | awk '{print "  - " $1}'
        exit 1
    fi

    log_success "Network interface found: ${interface}"
}

#------------------------------------------------------------------------------
# Main Logic
#------------------------------------------------------------------------------
main() {
    echo "=============================================="
    echo "  Pipeline Module Setup"
    echo "=============================================="
    echo ""

    check_root
    check_python_version
    check_java
    check_tcpdump
    echo ""

    create_directory_structure
    setup_virtual_environment
    install_dependencies
    echo ""

    validate_config_file
    check_cic_wrapper
    check_network_interface
    echo ""

    echo "=============================================="
    echo "  Setup Summary"
    echo "=============================================="
    echo "Module:               Pipeline PCAP"
    echo "Status:               Ready"
    echo "Virtual Environment:  ${VENV_DIR}"
    echo "Configuration:        ${CONFIG_FILE}"
    echo ""
    echo "Next Steps:"
    echo "  1. Activate environment:"
    echo "     source ${VENV_DIR}/bin/activate"
    echo "  2. Start pipeline:"
    echo "     python3 pipeline_pcap.py"
    echo ""

    log_success "Pipeline module setup complete"
}

main "$@"
