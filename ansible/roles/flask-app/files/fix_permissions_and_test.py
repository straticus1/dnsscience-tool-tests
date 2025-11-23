#!/usr/bin/env python3
"""
Fix permissions and run comprehensive tests
"""

import boto3
import time

NEW_INSTANCE = 'i-0c3327f79e1d0791c'
REGION = 'us-east-1'
REMOTE_APP_DIR = '/var/www/dnsscience'

def execute_command(command_text, description):
    """Execute a command via SSM and wait for results"""
    ssm = boto3.client('ssm', region_name=REGION)

    print(f"\n{description}")
    print("-" * 60)

    response = ssm.send_command(
        InstanceIds=[NEW_INSTANCE],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': [command_text]},
        TimeoutSeconds=120
    )

    command_id = response['Command']['CommandId']

    # Wait for command to complete
    for i in range(60):
        time.sleep(2)
        try:
            result = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=NEW_INSTANCE
            )
            status = result['Status']

            if status in ['Success', 'Failed', 'TimedOut', 'Cancelled']:
                stdout = result.get('StandardOutputContent', '')
                stderr = result.get('StandardErrorContent', '')

                if stdout:
                    print(stdout)

                if stderr and 'warning' not in stderr.lower():
                    print(f"Errors: {stderr}")

                return status == 'Success', stdout

            if i % 5 == 0:
                print(f"  Waiting... ({status})")

        except Exception as e:
            continue

    return False, ""

def main():
    print("="*80)
    print("FIX PERMISSIONS AND RUN COMPREHENSIVE TESTS")
    print("="*80)

    # Fix permissions for www-data
    execute_command(
        f"chown -R www-data:www-data {REMOTE_APP_DIR}/templates/ && chmod -R 755 {REMOTE_APP_DIR}/templates/",
        "Fixing permissions for www-data"
    )

    # Reload web server (try both apache2 and nginx)
    execute_command(
        "systemctl reload apache2 2>/dev/null || systemctl reload nginx 2>/dev/null && echo 'Web server reloaded'",
        "Reloading web server"
    )

    # Comprehensive route tests
    print("\n" + "="*80)
    print("COMPREHENSIVE ROUTE TESTING")
    print("="*80)

    test_script = """
#!/bin/bash
BASE_URL="https://www.dnsscience.io"

declare -i PASSED=0
declare -i FAILED=0

test_url() {
    local url="$1"
    local name="$2"
    local expect_content="$3"

    status=$(curl -s -o /tmp/test.html -w "%{http_code}" -L "$BASE_URL$url" 2>/dev/null)

    if [[ "$status" == "200" ]]; then
        if [ -n "$expect_content" ]; then
            if grep -qi "$expect_content" /tmp/test.html 2>/dev/null; then
                echo "✓ $name ($url) - HTTP $status - Content OK"
                PASSED=$((PASSED + 1))
            else
                echo "✗ $name ($url) - HTTP $status - CONTENT MISMATCH"
                FAILED=$((FAILED + 1))
            fi
        else
            echo "✓ $name ($url) - HTTP $status"
            PASSED=$((PASSED + 1))
        fi
    elif [[ "$status" == "302" ]] || [[ "$status" == "301" ]] || [[ "$status" == "401" ]]; then
        echo "~ $name ($url) - HTTP $status (redirect/auth - OK)"
        PASSED=$((PASSED + 1))
    else
        echo "✗ $name ($url) - HTTP $status"
        FAILED=$((FAILED + 1))
    fi
}

echo "Testing critical pages..."
test_url "/" "Homepage" "DNS Science"
test_url "/explorer" "Data Explorer" "Data Explorer"
test_url "/about" "About Page" "About DNS Science"
test_url "/docs/api" "API Documentation" "API"
test_url "/docs/cli" "CLI Documentation" "CLI"
test_url "/login" "Login Page" ""
test_url "/signup" "Signup Page" ""
test_url "/pricing" "Pricing Page" ""
test_url "/services" "Services Page" ""
test_url "/registrar" "Registrar Page" ""
test_url "/acquisition" "Acquisition Page" ""

echo ""
echo "Testing authenticated pages (may redirect)..."
test_url "/browse" "Browse Page" ""
test_url "/settings" "Settings Page" ""
test_url "/scanners" "Scanners Page" ""
test_url "/dashboard/domains" "Dashboard Domains" ""
test_url "/marketplace" "Marketplace" ""

echo ""
echo "Testing tools pages..."
test_url "/tools/darkweb" "Dark Web Lookup" ""
test_url "/tools/dns-config-validator" "DNS Config Validator" ""
test_url "/tools/cert-chain-resolver" "Cert Chain Resolver" ""

echo ""
echo "Testing API endpoints..."
test_url "/api/stats/live" "Live Stats API" ""
test_url "/api/domains?limit=1" "Domains API" ""

echo ""
echo "========================================"
echo "SUMMARY"
echo "========================================"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "Total: $((PASSED + FAILED))"
if [ $FAILED -eq 0 ]; then
    echo "Status: ✓ ALL TESTS PASSED"
else
    echo "Status: ✗ SOME TESTS FAILED"
fi
echo "========================================"
"""

    execute_command(test_script, "Running comprehensive route tests")

    # Check daemons
    print("\n" + "="*80)
    print("DAEMON STATUS")
    print("="*80)

    execute_command(
        """
        echo "Running daemons:"
        systemctl list-units --type=service --state=running | grep -E '(daemon|trial|email|rdap|enrichment|arpad|web3d)' || echo 'No custom daemons found (may be normal for new instance)'
        echo ""
        echo "All running services:"
        systemctl list-units --type=service --state=running --no-pager | wc -l
        """,
        "Checking daemon status"
    )

    print("\n" + "="*80)
    print("VERIFICATION COMPLETE")
    print("="*80)

if __name__ == '__main__':
    import sys
    try:
        sys.exit(main())
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
