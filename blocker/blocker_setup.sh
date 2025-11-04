#!/bin/bash

#==============================================================================
# Blocker Module Setup Script
# Description: Sets up Python environment and validates blocker configuration
# Requirements: Python 3.8+, OPNsense API access, root privileges
#==============================================================================

set -o pipefail

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------
readonly THESIS_ROOT="/root/Thesis"
readonly MODULE_DIR="${THESIS_ROOT}/blocker"
readonly VENV_DIR="${MODULE_DIR}/venv"
readonly CONFIG_FILE="${MODULE_DIR}/blocker_config.json"
readonly WHITELIST_FILE="${MODULE_DIR}/whitelist.json"
readonly REQUIREMENTS_FILE="${MODULE_DIR}/requirements.txt"
readonly REQUIRED_PYTHON_VERSION="3.8"

readonly REQUIRED_DIRS=(
    "${MODULE_DIR}/state"
    "${MODULE_DIR}/queue"
    "${MODULE_DIR}/statistics"
    "${MODULE_DIR}/log"
    "${THESIS_ROOT}/ml/alerts/processed"
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

validate_config_files() {
    log_info "Validating configuration files"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_error "blocker_config.json not found at ${CONFIG_FILE}"
        exit 1
    fi

    if ! python3 -c "import json; json.load(open('${CONFIG_FILE}'))" 2>/dev/null; then
        log_error "blocker_config.json has invalid JSON syntax"
        exit 1
    fi

    log_success "blocker_config.json is valid"

    if [[ ! -f "${WHITELIST_FILE}" ]]; then
        log_warn "whitelist.json not found at ${WHITELIST_FILE}"
    else
        if ! python3 -c "import json; json.load(open('${WHITELIST_FILE}'))" 2>/dev/null; then
            log_error "whitelist.json has invalid JSON syntax"
            exit 1
        fi
        log_success "whitelist.json is valid"
    fi
}

set_permissions() {
    log_info "Setting permissions"

    if [[ -f "${MODULE_DIR}/blocker.py" ]]; then
        chmod +x "${MODULE_DIR}/blocker.py" 2>/dev/null
    fi

    chmod -R 755 "${MODULE_DIR}" 2>/dev/null

    log_success "Permissions set"
}

#------------------------------------------------------------------------------
# Main Logic
#------------------------------------------------------------------------------
main() {
    echo "=============================================="
    echo "  Blocker Module Setup"
    echo "=============================================="
    echo ""

    check_root
    check_python_version
    echo ""

    create_directory_structure
    setup_virtual_environment
    install_dependencies
    echo ""

    validate_config_files
    set_permissions
    echo ""

    echo "=============================================="
    echo "  Setup Summary"
    echo "=============================================="
    echo "Module:               Blocker"
    echo "Status:               Ready"
    echo "Virtual Environment:  ${VENV_DIR}"
    echo "Configuration:        ${CONFIG_FILE}"
    echo ""
    echo "Next Steps:"
    echo "  1. Verify OPNsense API credentials in config"
    echo "  2. Activate environment:"
    echo "  source ${VENV_DIR}/bin/activate"
    echo "  3. Start blocker: python3 blocker.py"
    echo "  python3 blocker.py"
    echo ""

    log_success "Blocker module setup complete"
}

main "$@"
