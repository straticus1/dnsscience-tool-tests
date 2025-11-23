#!/bin/bash
# Test Ansible Setup for DNS Science

set -e

echo "==================================="
echo " DNS Science Ansible Setup Test"
echo "==================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Test function
test_component() {
    local test_name=$1
    local test_cmd=$2

    echo -n "Testing $test_name... "
    if eval "$test_cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        return 1
    fi
}

# Track failures
FAILURES=0

# Test prerequisites
test_component "Python 3" "python3 --version" || ((FAILURES++))
test_component "Ansible" "ansible --version" || ((FAILURES++))
test_component "AWS CLI" "aws --version" || ((FAILURES++))
test_component "Boto3" "python3 -c 'import boto3'" || ((FAILURES++))

# Test file structure
test_component "Main playbook" "[ -f deploy-dnsscience.yml ]" || ((FAILURES++))
test_component "Deployment script" "[ -x deploy.sh ]" || ((FAILURES++))
test_component "Inventory file" "[ -f inventory/production.yml ]" || ((FAILURES++))
test_component "Global variables" "[ -f group_vars/all.yml ]" || ((FAILURES++))

# Test Ansible components
test_component "Inventory syntax" "ansible-inventory -i inventory/production.yml --list > /dev/null" || ((FAILURES++))
test_component "Playbook syntax" "ansible-playbook deploy-dnsscience.yml --syntax-check" || ((FAILURES++))

# Test AWS connectivity (if configured)
echo -n "Testing AWS credentials... "
if aws sts get-caller-identity > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"

    # Test SSM availability
    echo -n "Testing SSM access... "
    if aws ssm describe-instance-information > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ (SSM not accessible)${NC}"
        ((FAILURES++))
    fi
else
    echo -e "${RED}✗ (AWS not configured)${NC}"
    echo "  Run: aws configure"
fi

# Test roles
echo ""
echo "Checking roles..."
for role in python-deps database flask-app templates static-files apache health-check; do
    test_component "Role: $role" "[ -d roles/$role/tasks ]" || ((FAILURES++))
done

# Summary
echo ""
echo "==================================="
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    echo ""
    echo "Ready to deploy with:"
    echo "  ./deploy.sh"
    echo ""
    echo "Or test with:"
    echo "  ./deploy.sh --check"
else
    echo -e "${RED}$FAILURES test(s) failed${NC}"
    echo ""
    echo "Please fix the issues above before deploying."
fi
echo "==================================="

exit $FAILURES