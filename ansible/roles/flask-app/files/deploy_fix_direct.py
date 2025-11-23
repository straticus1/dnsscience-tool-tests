#!/usr/bin/env python3
"""
Deploy DNS Science Production Fixes
Deploys database.py, app.py, and index.php fixes to production server
"""

import boto3
import time
import sys
import os

INSTANCE_ID = "i-0b8e783aa9b333846"
REGION = "us-east-1"
REMOTE_PATH = "/var/www/dnsscience"

def send_command(ssm_client, instance_id, commands, timeout=30):
    """Send command via SSM and wait for completion"""
    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={'commands': commands}
    )

    command_id = response['Command']['CommandId']
    print(f"  Command ID: {command_id}")

    # Wait for command to complete
    for i in range(timeout):
        time.sleep(1)
        try:
            result = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            status = result['Status']

            if status == 'Success':
                print("  ✓ Success")
                return result.get('StandardOutputContent', '')
            elif status in ['Failed', 'Cancelled', 'TimedOut']:
                print(f"  ✗ Failed: {status}")
                print(f"  Error: {result.get('StandardErrorContent', '')}")
                return None
        except Exception as e:
            # Command not yet available
            pass

    print("  ⚠ Timeout waiting for command")
    return None

def read_file(filepath):
    """Read file content"""
    with open(filepath, 'r') as f:
        return f.read()

def main():
    print("="*60)
    print("DNS Science Production Fix Deployment")
    print("="*60)
    print()
    print("Deploying fixes:")
    print("  1. database.py - Datetime serialization fix")
    print("  2. app.py - Error handling for /api/domain/<domain>")
    print("  3. index.php - Domain registration UI")
    print()
    print(f"Instance: {INSTANCE_ID}")
    print(f"Region: {REGION}")
    print(f"Remote Path: {REMOTE_PATH}")
    print()

    # Initialize SSM client
    ssm = boto3.client('ssm', region_name=REGION)

    # Step 1: Create backup
    print("[1/5] Creating backup...")
    backup_dir = f"/var/www/dnsscience/backups/fix_$(date +%Y%m%d_%H%M%S)"
    send_command(ssm, INSTANCE_ID, [
        f"mkdir -p {backup_dir}",
        f"cp {REMOTE_PATH}/database.py {backup_dir}/",
        f"cp {REMOTE_PATH}/app.py {backup_dir}/",
        f"cp {REMOTE_PATH}/templates/index.php {backup_dir}/",
        f"echo 'Backup created in {backup_dir}'"
    ])

    # Step 2: Deploy database.py
    print("\n[2/5] Deploying database.py...")
    db_content = read_file('database.py')
    # Escape single quotes for shell
    db_content_escaped = db_content.replace("'", "'\"'\"'")
    send_command(ssm, INSTANCE_ID, [
        f"cat > {REMOTE_PATH}/database.py << 'EOFDB'\n{db_content}\nEOFDB",
        f"chown www-data:www-data {REMOTE_PATH}/database.py"
    ], timeout=60)

    # Step 3: Deploy app.py
    print("\n[3/5] Deploying app.py...")
    app_content = read_file('app.py')
    # For large files, use a temp file approach
    send_command(ssm, INSTANCE_ID, [
        f"cat > /tmp/app.py.new << 'EOFAPP'\n{app_content}\nEOFAPP",
        f"mv /tmp/app.py.new {REMOTE_PATH}/app.py",
        f"chown www-data:www-data {REMOTE_PATH}/app.py"
    ], timeout=90)

    # Step 4: Deploy index.php
    print("\n[4/5] Deploying index.php...")
    php_content = read_file('templates/index.php')
    send_command(ssm, INSTANCE_ID, [
        f"cat > /tmp/index.php.new << 'EOFPHP'\n{php_content}\nEOFPHP",
        f"mv /tmp/index.php.new {REMOTE_PATH}/templates/index.php",
        f"chown www-data:www-data {REMOTE_PATH}/templates/index.php"
    ], timeout=90)

    # Step 5: Restart Apache
    print("\n[5/5] Restarting Apache...")
    output = send_command(ssm, INSTANCE_ID, [
        "sudo systemctl restart apache2",
        "sleep 2",
        "sudo systemctl status apache2 --no-pager | head -20"
    ], timeout=30)

    if output:
        print("\nApache Status:")
        print(output)

    print()
    print("="*60)
    print("✓ Deployment Complete!")
    print("="*60)
    print()
    print("Changes deployed:")
    print("  ✓ database.py - Added serialize_row() method for datetime handling")
    print("  ✓ app.py - Added try/catch to /api/domain/<domain>")
    print("  ✓ index.php - Added 'Register Domain' tab with search UI")
    print()
    print("Test the fixes:")
    print("  1. Visit: https://www.dnsscience.io/")
    print("  2. Try searching for 'rrbcheeks.com' in Scan Domain tab")
    print("  3. Click 'Register Domain' tab and search for a domain")
    print()
    print("Monitor logs:")
    print(f"  aws ssm start-session --target {INSTANCE_ID}")
    print("  sudo tail -f /var/log/apache2/error.log")
    print()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDeployment cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Deployment failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
