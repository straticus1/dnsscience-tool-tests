#!/bin/bash
# DNS Science Ansible Deployment Script
# Production-grade deployment automation

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ANSIBLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INVENTORY="${ANSIBLE_DIR}/inventory/production.yml"
PLAYBOOK="${ANSIBLE_DIR}/deploy-dnsscience.yml"
LOG_FILE="${ANSIBLE_DIR}/logs/deployment_$(date +%Y%m%d_%H%M%S).log"
VAULT_PASSWORD_FILE="${ANSIBLE_DIR}/.vault_pass"

# Functions
print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE} DNS Science Deployment System${NC}"
    echo -e "${BLUE} Version: 1.0.0${NC}"
    echo -e "${BLUE}================================================${NC}"
}

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_prerequisites() {
    echo -e "\n${BLUE}Checking prerequisites...${NC}"

    # Check for Ansible
    if ! command -v ansible &> /dev/null; then
        print_error "Ansible is not installed"
        echo "Install with: pip install ansible"
        exit 1
    fi
    print_status "Ansible installed ($(ansible --version | head -1))"

    # Check for AWS CLI
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed"
        echo "Install with: pip install awscli"
        exit 1
    fi
    print_status "AWS CLI installed"

    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured"
        echo "Run: aws configure"
        exit 1
    fi
    print_status "AWS credentials configured"

    # Check for inventory file
    if [ ! -f "$INVENTORY" ]; then
        print_error "Inventory file not found: $INVENTORY"
        exit 1
    fi
    print_status "Inventory file found"

    # Check for playbook
    if [ ! -f "$PLAYBOOK" ]; then
        print_error "Playbook not found: $PLAYBOOK"
        exit 1
    fi
    print_status "Playbook found"

    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    print_status "Log directory ready"
}

install_requirements() {
    echo -e "\n${BLUE}Installing Ansible requirements...${NC}"

    # Install Python requirements
    if [ -f "${ANSIBLE_DIR}/requirements.txt" ]; then
        pip install -q -r "${ANSIBLE_DIR}/requirements.txt"
        print_status "Python requirements installed"
    fi

    # Install Ansible collections
    if [ -f "${ANSIBLE_DIR}/requirements.yml" ]; then
        ansible-galaxy collection install -r "${ANSIBLE_DIR}/requirements.yml" --force
        print_status "Ansible collections installed"
    fi
}

validate_inventory() {
    echo -e "\n${BLUE}Validating inventory...${NC}"
    ansible-inventory -i "$INVENTORY" --list > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_status "Inventory is valid"
        ansible-inventory -i "$INVENTORY" --graph
    else
        print_error "Inventory validation failed"
        exit 1
    fi
}

run_deployment() {
    echo -e "\n${BLUE}Starting deployment...${NC}"
    echo "Logging to: $LOG_FILE"

    # Build ansible-playbook command
    ANSIBLE_CMD="ansible-playbook"
    ANSIBLE_CMD="$ANSIBLE_CMD -i $INVENTORY"
    ANSIBLE_CMD="$ANSIBLE_CMD $PLAYBOOK"

    # Add vault password if available
    if [ -f "$VAULT_PASSWORD_FILE" ]; then
        ANSIBLE_CMD="$ANSIBLE_CMD --vault-password-file=$VAULT_PASSWORD_FILE"
    fi

    # Add extra vars if provided
    if [ -n "${EXTRA_VARS:-}" ]; then
        ANSIBLE_CMD="$ANSIBLE_CMD -e '$EXTRA_VARS'"
    fi

    # Add tags if provided
    if [ -n "${TAGS:-}" ]; then
        ANSIBLE_CMD="$ANSIBLE_CMD --tags '$TAGS'"
    fi

    # Add skip tags if provided
    if [ -n "${SKIP_TAGS:-}" ]; then
        ANSIBLE_CMD="$ANSIBLE_CMD --skip-tags '$SKIP_TAGS'"
    fi

    # Add verbosity if requested
    if [ "${VERBOSE:-0}" -eq 1 ]; then
        ANSIBLE_CMD="$ANSIBLE_CMD -vvv"
    fi

    # Check mode if requested
    if [ "${CHECK_MODE:-0}" -eq 1 ]; then
        ANSIBLE_CMD="$ANSIBLE_CMD --check"
        print_warning "Running in CHECK MODE (no changes will be made)"
    fi

    # Execute deployment
    echo -e "\nExecuting: $ANSIBLE_CMD"

    if eval "$ANSIBLE_CMD" 2>&1 | tee "$LOG_FILE"; then
        print_status "Deployment completed successfully"
        return 0
    else
        print_error "Deployment failed"
        return 1
    fi
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

DNS Science Ansible Deployment Script

OPTIONS:
    -h, --help           Show this help message
    -c, --check          Run in check mode (dry run)
    -v, --verbose        Enable verbose output
    -t, --tags TAGS      Only run plays and tasks tagged with these values
    -s, --skip TAGS      Skip plays and tasks tagged with these values
    -e, --extra VARS     Set additional variables
    -i, --inventory FILE Use alternate inventory file
    -r, --rollback       Rollback to previous version

EXAMPLES:
    # Standard deployment
    $0

    # Dry run to see what would change
    $0 --check

    # Deploy only templates
    $0 --tags templates

    # Skip database migrations
    $0 --skip database

    # Deploy with extra variables
    $0 --extra "deploy_flask_app=true deploy_templates=false"

    # Rollback deployment
    $0 --rollback

EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -c|--check)
                CHECK_MODE=1
                shift
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -t|--tags)
                TAGS="$2"
                shift 2
                ;;
            -s|--skip)
                SKIP_TAGS="$2"
                shift 2
                ;;
            -e|--extra)
                EXTRA_VARS="$2"
                shift 2
                ;;
            -i|--inventory)
                INVENTORY="$2"
                shift 2
                ;;
            -r|--rollback)
                TAGS="rollback"
                EXTRA_VARS="rollback=true"
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

main() {
    print_header

    # Parse command line arguments
    parse_arguments "$@"

    # Run pre-flight checks
    check_prerequisites

    # Install requirements
    install_requirements

    # Validate inventory
    validate_inventory

    # Confirmation prompt
    if [ "${CHECK_MODE:-0}" -eq 0 ]; then
        echo -e "\n${YELLOW}You are about to deploy to PRODUCTION${NC}"
        read -p "Are you sure you want to continue? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            print_warning "Deployment cancelled"
            exit 0
        fi
    fi

    # Run deployment
    if run_deployment; then
        echo -e "\n${GREEN}========================================${NC}"
        echo -e "${GREEN} DEPLOYMENT SUCCESSFUL${NC}"
        echo -e "${GREEN}========================================${NC}"
        echo -e "Log file: $LOG_FILE"
        echo -e "Timestamp: $(date)"
        exit 0
    else
        echo -e "\n${RED}========================================${NC}"
        echo -e "${RED} DEPLOYMENT FAILED${NC}"
        echo -e "${RED}========================================${NC}"
        echo -e "Check log file: $LOG_FILE"
        echo -e "Timestamp: $(date)"
        exit 1
    fi
}

# Run main function
main "$@"