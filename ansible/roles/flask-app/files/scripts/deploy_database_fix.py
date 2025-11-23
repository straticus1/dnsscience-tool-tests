#!/usr/bin/env python3
"""Deploy fixed database.py to EC2 instances"""

import boto3
import time
import sys
from pathlib import Path
import base64

REGION = 'us-east-1'
INSTANCES = ['i-05add94e8603bd5b3', 'i-0f730a50a9d1723fd']
DB_FILE = Path(__file__).parent.parent / 'database.py'

def deploy_to_instance(ssm_client, instance_id, db_content):
    """Deploy database.py to an instance"""
    print(f"\n{'='*70}")
    print(f"Deploying database.py to: {instance_id}")
    print(f"{'='*70}")

    # Base64 encode to safely transfer
    db_content_b64 = base64.b64encode(db_content.encode()).decode()

    script = f'''#!/bin/bash
set -e

# Decode and save database.py
echo "{db_content_b64}" | base64 -d > /tmp/database.py

# Backup old file
sudo cp /var/www/dnsscience/database.py /var/www/dnsscience/database.py.backup

# Deploy new file
sudo mv /tmp/database.py /var/www/dnsscience/database.py
sudo chown www-data:www-data /var/www/dnsscience/database.py
sudo chmod 644 /var/www/dnsscience/database.py

echo "✓ database.py deployed"

# Kill all Apache/WSGI processes to force reload
sudo pkill -9 apache2 || true
sudo pkill -9 wsgi || true

# Restart Apache
sudo systemctl start apache2
sleep 3

echo ""
echo "Testing application..."
curl -s http://localhost/health

echo ""
echo "Testing dashboard stats..."
curl -s http://localhost/api/stats/dashboard | python3 -m json.tool || echo "Failed to get dashboard stats"

echo ""
echo "✓ Deployment complete"
'''

    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': [script]},
        TimeoutSeconds=60
    )

    command_id = response['Command']['CommandId']
    print(f"Command ID: {command_id}")
    print("Waiting for deployment...")

    for i in range(20):
        time.sleep(3)
        try:
            result = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            status = result['Status']

            if status in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                print(f"\n{'='*70}")
                print(f"Status: {status}")
                print(f"{'='*70}")

                if result.get('StandardOutputContent'):
                    print("\nOutput:")
                    print(result['StandardOutputContent'])

                if result.get('StandardErrorContent'):
                    print("\nErrors:")
                    print(result['StandardErrorContent'])

                return status == 'Success'

        except ssm_client.exceptions.InvocationDoesNotExist:
            pass

    print("✗ Timeout")
    return False


def main():
    """Main function"""
    print("="*70)
    print("DNS Science - Deploy database.py Fix")
    print("="*70)

    if not DB_FILE.exists():
        print(f"✗ Error: database.py not found at {DB_FILE}")
        sys.exit(1)

    db_content = DB_FILE.read_text()
    print(f"\n✓ Loaded database.py ({len(db_content)} bytes)")

    ssm_client = boto3.client('ssm', region_name=REGION)

    success_count = 0
    for instance_id in INSTANCES:
        if deploy_to_instance(ssm_client, instance_id, db_content):
            success_count += 1

    print(f"\n{'='*70}")
    print(f"Deployment Summary")
    print(f"{'='*70}")
    print(f"Total: {len(INSTANCES)}, Successful: {success_count}, Failed: {len(INSTANCES) - success_count}")

    if success_count == len(INSTANCES):
        print(f"\n✓ All deployments successful!")
        return 0
    else:
        print(f"\n✗ Some deployments failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
