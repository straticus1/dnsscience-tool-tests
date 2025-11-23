#!/usr/bin/env python3
"""
Deploy Stripe Integration Files to Production
Uses AWS SSM to create files directly on EC2 instance
"""

import boto3
import time
import sys

INSTANCE_ID = "i-01a2c826c9cbd9218"

# File mappings
FILES_TO_DEPLOY = {
    'stripe_integration.py': '/var/www/dnsscience/stripe_integration.py',
    'trial_manager.py': '/var/www/dnsscience/trial_manager.py',
    'sql-files/migrations/010_stripe_and_trials.sql': '/var/www/dnsscience/sql-files/migrations/010_stripe_and_trials.sql'
}

def send_command(ssm_client, commands, comment):
    """Send SSM command and wait for result"""
    response = ssm_client.send_command(
        InstanceIds=[INSTANCE_ID],
        DocumentName='AWS-RunShellScript',
        Comment=comment,
        Parameters={'commands': commands}
    )

    command_id = response['Command']['CommandId']
    print(f"  Command ID: {command_id}")

    # Wait for command to complete
    for i in range(30):
        time.sleep(2)
        try:
            result = ssm_client.get_command_invocation(
                InstanceId=INSTANCE_ID,
                CommandId=command_id
            )

            status = result['Status']
            if status in ['Success', 'Failed', 'TimedOut', 'Cancelled']:
                if status == 'Success':
                    print(f"  ✓ {comment}")
                    return result['StandardOutputContent']
                else:
                    print(f"  ✗ {comment} - {status}")
                    print(f"  Error: {result.get('StandardErrorContent', '')}")
                    return None
        except:
            continue

    print(f"  ⏱ {comment} - Timeout")
    return None

def deploy_file_chunked(ssm_client, local_path, remote_path):
    """Deploy a file in chunks using printf to avoid quote issues"""
    print(f"\n📤 Deploying {local_path}...")

    with open(local_path, 'r') as f:
        content = f.read()

    # Escape special characters for printf
    content_escaped = content.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')

    # Split into chunks (SSM has 4KB limit per command parameter)
    chunk_size = 3000  # Leave room for command overhead
    chunks = [content_escaped[i:i+chunk_size] for i in range(0, len(content_escaped), chunk_size)]

    print(f"  File size: {len(content)} bytes, {len(chunks)} chunks")

    # Clear/create file
    commands = [f'> {remote_path}']
    send_command(ssm_client, commands, f"Create {remote_path}")

    # Append each chunk
    for idx, chunk in enumerate(chunks, 1):
        commands = [f'printf "%s" "{chunk}" >> {remote_path}']
        result = send_command(ssm_client, commands, f"Upload chunk {idx}/{len(chunks)}")
        if result is None:
            print(f"  ✗ Failed to upload chunk {idx}")
            return False

    # Set permissions
    commands = [
        f'sudo chown www-data:www-data {remote_path}',
        f'sudo chmod 644 {remote_path}',
        f'ls -lh {remote_path}'
    ]
    send_command(ssm_client, commands, f"Set permissions on {remote_path}")

    return True

def main():
    print("🚀 DNS Science - Stripe Integration Deployment")
    print("=" * 60)

    ssm_client = boto3.client('ssm', region_name='us-east-1')

    # Deploy each file
    for local_path, remote_path in FILES_TO_DEPLOY.items():
        if not deploy_file_chunked(ssm_client, local_path, remote_path):
            print(f"\n✗ Deployment failed for {local_path}")
            sys.exit(1)

    print("\n" + "=" * 60)
    print("✅ All files deployed successfully!")
    print("\n📋 Next steps:")
    print("  1. Run migration 010")
    print("  2. Configure Stripe API keys in .env.production")
    print("  3. Add API routes to app.py")
    print("  4. Set up trial reminder daemon")

if __name__ == '__main__':
    main()
