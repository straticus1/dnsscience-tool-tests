#!/usr/bin/env python3
"""
Deploy templates to the new production instance
"""

import boto3
import time
import json

NEW_INSTANCE = 'i-0c3327f79e1d0791c'
REGION = 'us-east-1'
S3_BUCKET = 'dnsscience-deployment'
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
    print(f"Command ID: {command_id}")

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
                print(f"Status: {status}")

                stdout = result.get('StandardOutputContent', '')
                stderr = result.get('StandardErrorContent', '')

                if stdout:
                    print("\nOutput:")
                    print(stdout)

                if stderr:
                    print("\nErrors:")
                    print(stderr)

                return status == 'Success', stdout

            if i % 5 == 0:
                print(f"  Waiting... ({status})")

        except Exception as e:
            print(f"  Waiting... (checking)")
            continue

    print("Status: Timed out")
    return False, ""

def main():
    print("="*80)
    print("DEPLOYING TO NEW PRODUCTION INSTANCE")
    print("="*80)
    print(f"Instance ID: {NEW_INSTANCE}")
    print(f"S3 Bucket: {S3_BUCKET}")
    print(f"App Directory: {REMOTE_APP_DIR}")
    print("="*80)

    # Step 1: Sync templates from S3
    success, output = execute_command(
        f"""
        cd {REMOTE_APP_DIR}
        mkdir -p templates/dashboard templates/marketplace templates/tools
        aws s3 sync s3://{S3_BUCKET}/templates/ {REMOTE_APP_DIR}/templates/
        """,
        "Step 1: Sync templates from S3"
    )

    if not success:
        print("\nERROR: Failed to sync templates from S3")
        return 1

    # Step 2: Set permissions
    success, output = execute_command(
        f"""
        chown -R apache:apache {REMOTE_APP_DIR}/templates/
        chmod -R 755 {REMOTE_APP_DIR}/templates/
        """,
        "Step 2: Set permissions"
    )

    # Step 3: Verify deployment
    success, output = execute_command(
        f"""
        echo "=== Template Counts ==="
        echo "HTML templates: $(ls -1 {REMOTE_APP_DIR}/templates/*.html 2>/dev/null | wc -l)"
        echo "PHP templates: $(ls -1 {REMOTE_APP_DIR}/templates/*.php 2>/dev/null | wc -l)"
        echo ""
        echo "=== Critical Templates ==="
        ls -lh {REMOTE_APP_DIR}/templates/explorer.html 2>/dev/null || echo "MISSING: explorer.html"
        ls -lh {REMOTE_APP_DIR}/templates/about.html 2>/dev/null || echo "MISSING: about.html"
        ls -lh {REMOTE_APP_DIR}/templates/api_docs.html 2>/dev/null || echo "MISSING: api_docs.html"
        ls -lh {REMOTE_APP_DIR}/templates/index.php 2>/dev/null || echo "MISSING: index.php"
        """,
        "Step 3: Verify deployment"
    )

    # Step 4: Reload Apache
    success, output = execute_command(
        "systemctl reload httpd && systemctl status httpd --no-pager | head -20",
        "Step 4: Reload Apache"
    )

    # Step 5: Check daemons
    success, output = execute_command(
        "systemctl list-units --type=service --state=running | grep -E '(daemon|trial|email|rdap)' | wc -l",
        "Step 5: Check running daemons"
    )

    # Step 6: Test the site
    success, output = execute_command(
        """
        echo "=== Testing Production Site ==="
        curl -s -o /dev/null -w "Explorer page: HTTP %{http_code}\\n" https://www.dnsscience.io/explorer
        curl -s -o /dev/null -w "About page: HTTP %{http_code}\\n" https://www.dnsscience.io/about
        curl -s -o /dev/null -w "API docs: HTTP %{http_code}\\n" https://www.dnsscience.io/docs/api
        curl -s -o /dev/null -w "Homepage: HTTP %{http_code}\\n" https://www.dnsscience.io/
        echo ""
        echo "=== Content Verification ==="
        curl -s https://www.dnsscience.io/explorer | grep -q "Data Explorer" && echo "✓ Explorer page has correct content" || echo "✗ Explorer page content issue"
        curl -s https://www.dnsscience.io/about | grep -q "About DNS Science" && echo "✓ About page has correct content" || echo "✗ About page content issue"
        """,
        "Step 6: Test production site"
    )

    print("\n" + "="*80)
    print("DEPLOYMENT COMPLETE")
    print("="*80)
    print("\nNext steps:")
    print("1. Run comprehensive route tests: python3 test_all_routes.py")
    print("2. Manually verify: https://www.dnsscience.io/explorer")
    print("3. Manually verify: https://www.dnsscience.io/about")

    return 0

if __name__ == '__main__':
    import sys
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nAborted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
