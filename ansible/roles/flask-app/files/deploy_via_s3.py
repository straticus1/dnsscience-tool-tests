#!/usr/bin/env python3
"""
Deploy DNS Science Production Fixes via S3
Uses S3 as intermediate storage for large files
"""

import boto3
import time
import sys
import os
from datetime import datetime

INSTANCE_ID = "i-0b8e783aa9b333846"
REGION = "us-east-1"
REMOTE_PATH = "/var/www/dnsscience"
S3_BUCKET = "dnsscience-deployments"  # Will create if doesn't exist
S3_PREFIX = f"fixes/{datetime.now().strftime('%Y%m%d_%H%M%S')}"

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
                output = result.get('StandardOutputContent', '')
                if output.strip():
                    print(f"  Output: {output[:200]}")
                return output
            elif status in ['Failed', 'Cancelled', 'TimedOut']:
                print(f"  ✗ Failed: {status}")
                error = result.get('StandardErrorContent', '')
                if error:
                    print(f"  Error: {error}")
                return None
        except Exception as e:
            # Command not yet available
            pass

    print("  ⚠ Timeout waiting for command")
    return None

def upload_to_s3(s3_client, bucket, key, filepath):
    """Upload file to S3"""
    try:
        s3_client.upload_file(filepath, bucket, key)
        print(f"  ✓ Uploaded to s3://{bucket}/{key}")
        return True
    except Exception as e:
        print(f"  ✗ Upload failed: {e}")
        return False

def main():
    print("="*60)
    print("DNS Science Production Fix Deployment (via S3)")
    print("="*60)
    print()
    print("Deploying fixes:")
    print("  1. database.py - Datetime serialization fix")
    print("  2. app.py - Error handling for /api/domain/<domain>")
    print("  3. index.php - Domain registration UI")
    print()
    print(f"Instance: {INSTANCE_ID}")
    print(f"Region: {REGION}")
    print(f"S3 Bucket: {S3_BUCKET}")
    print(f"S3 Prefix: {S3_PREFIX}")
    print()

    # Initialize AWS clients
    ssm = boto3.client('ssm', region_name=REGION)
    s3 = boto3.client('s3', region_name=REGION)

    # Ensure bucket exists
    try:
        s3.head_bucket(Bucket=S3_BUCKET)
        print(f"✓ S3 bucket {S3_BUCKET} exists")
    except:
        print(f"Creating S3 bucket {S3_BUCKET}...")
        s3.create_bucket(Bucket=S3_BUCKET)

    # Upload files to S3
    print("\n[1/6] Uploading files to S3...")
    files_to_deploy = [
        ('database.py', f'{S3_PREFIX}/database.py'),
        ('app.py', f'{S3_PREFIX}/app.py'),
        ('templates/index.php', f'{S3_PREFIX}/index.php'),
    ]

    for local_path, s3_key in files_to_deploy:
        print(f"  Uploading {local_path}...")
        if not upload_to_s3(s3, S3_BUCKET, s3_key, local_path):
            print("Deployment aborted due to upload failure")
            return 1

    # Step 2: Create backup
    print("\n[2/6] Creating backup on server...")
    backup_dir = f"/var/www/dnsscience/backups/fix_$(date +%Y%m%d_%H%M%S)"
    send_command(ssm, INSTANCE_ID, [
        f"mkdir -p {backup_dir}",
        f"cp {REMOTE_PATH}/database.py {backup_dir}/ 2>/dev/null || true",
        f"cp {REMOTE_PATH}/app.py {backup_dir}/ 2>/dev/null || true",
        f"cp {REMOTE_PATH}/templates/index.php {backup_dir}/ 2>/dev/null || true",
        f"echo 'Backup created in {backup_dir}'"
    ])

    # Step 3: Download and deploy database.py
    print("\n[3/6] Deploying database.py...")
    send_command(ssm, INSTANCE_ID, [
        f"aws s3 cp s3://{S3_BUCKET}/{S3_PREFIX}/database.py {REMOTE_PATH}/database.py",
        f"chown www-data:www-data {REMOTE_PATH}/database.py",
        f"chmod 644 {REMOTE_PATH}/database.py"
    ], timeout=60)

    # Step 4: Download and deploy app.py
    print("\n[4/6] Deploying app.py...")
    send_command(ssm, INSTANCE_ID, [
        f"aws s3 cp s3://{S3_BUCKET}/{S3_PREFIX}/app.py {REMOTE_PATH}/app.py",
        f"chown www-data:www-data {REMOTE_PATH}/app.py",
        f"chmod 644 {REMOTE_PATH}/app.py"
    ], timeout=60)

    # Step 5: Download and deploy index.php
    print("\n[5/6] Deploying index.php...")
    send_command(ssm, INSTANCE_ID, [
        f"aws s3 cp s3://{S3_BUCKET}/{S3_PREFIX}/index.php {REMOTE_PATH}/templates/index.php",
        f"chown www-data:www-data {REMOTE_PATH}/templates/index.php",
        f"chmod 644 {REMOTE_PATH}/templates/index.php"
    ], timeout=60)

    # Step 6: Restart Apache
    print("\n[6/6] Restarting Apache...")
    output = send_command(ssm, INSTANCE_ID, [
        "sudo systemctl restart apache2",
        "sleep 2",
        "sudo systemctl status apache2 --no-pager | head -20"
    ], timeout=30)

    if output:
        print("\nApache Status:")
        print(output)

    # Cleanup S3 files (optional)
    print("\n[Cleanup] Removing S3 deployment files...")
    for _, s3_key in files_to_deploy:
        try:
            s3.delete_object(Bucket=S3_BUCKET, Key=s3_key)
            print(f"  ✓ Deleted s3://{S3_BUCKET}/{s3_key}")
        except Exception as e:
            print(f"  ⚠ Could not delete {s3_key}: {e}")

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

    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nDeployment cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Deployment failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
