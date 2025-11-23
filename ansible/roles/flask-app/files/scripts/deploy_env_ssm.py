#!/usr/bin/env python3
"""Deploy .env file to EC2 instances via AWS Systems Manager"""

import boto3
import time
import sys
from pathlib import Path

# Configuration
REGION = 'us-east-1'
INSTANCES = ['i-05add94e8603bd5b3', 'i-0f730a50a9d1723fd']
ENV_FILE = Path(__file__).parent.parent / '.env.production'

def deploy_to_instance(ssm_client, instance_id, env_content):
    """Deploy .env file to a single instance"""
    print(f"\n{'='*70}")
    print(f"Deploying to instance: {instance_id}")
    print(f"{'='*70}")

    # Create the deployment script
    script = f'''#!/bin/bash
set -e

# Create .env file
cat > /tmp/.env.production << 'EOFENVFILE'
{env_content}
EOFENVFILE

# Move to correct location
sudo mkdir -p /var/www/dnsscience
sudo cp /tmp/.env.production /var/www/dnsscience/.env
sudo chown www-data:www-data /var/www/dnsscience/.env
sudo chmod 600 /var/www/dnsscience/.env

# Verify
echo "✓ Environment file deployed successfully"
ls -la /var/www/dnsscience/.env
echo ""
echo "First 5 lines of .env file:"
sudo head -5 /var/www/dnsscience/.env

# Cleanup
rm -f /tmp/.env.production
'''

    # Send command
    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': [script]},
        TimeoutSeconds=30
    )

    command_id = response['Command']['CommandId']
    print(f"Command ID: {command_id}")
    print("Waiting for command to complete...")

    # Wait for completion
    for i in range(10):
        time.sleep(2)
        try:
            result = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            status = result['Status']
            print(f"  Status: {status}")

            if status in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                if status == 'Success':
                    print(f"\n✓ Deployment successful!")
                    print(f"\nOutput:")
                    print(result['StandardOutputContent'])
                else:
                    print(f"\n✗ Deployment failed with status: {status}")
                    if result.get('StandardErrorContent'):
                        print(f"\nError output:")
                        print(result['StandardErrorContent'])
                return status == 'Success'

        except ssm_client.exceptions.InvocationDoesNotExist:
            pass  # Command not yet available

    print("✗ Timeout waiting for command to complete")
    return False


def main():
    """Main deployment function"""
    print("="*70)
    print("DNS Science - Deploy Environment Configuration via SSM")
    print("="*70)

    # Read .env file
    if not ENV_FILE.exists():
        print(f"✗ Error: .env file not found at {ENV_FILE}")
        sys.exit(1)

    env_content = ENV_FILE.read_text()
    print(f"\n✓ Loaded .env file ({len(env_content)} bytes)")
    print(f"  File: {ENV_FILE}")

    # Initialize SSM client
    ssm_client = boto3.client('ssm', region_name=REGION)

    # Deploy to all instances
    success_count = 0
    for instance_id in INSTANCES:
        if deploy_to_instance(ssm_client, instance_id, env_content):
            success_count += 1

    # Summary
    print(f"\n{'='*70}")
    print(f"Deployment Summary")
    print(f"{'='*70}")
    print(f"Total instances: {len(INSTANCES)}")
    print(f"Successful: {success_count}")
    print(f"Failed: {len(INSTANCES) - success_count}")

    if success_count == len(INSTANCES):
        print(f"\n✓ All deployments successful!")
        return 0
    else:
        print(f"\n✗ Some deployments failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
