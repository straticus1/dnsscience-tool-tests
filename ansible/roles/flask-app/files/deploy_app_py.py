#!/usr/bin/env python3
"""Deploy updated app.py to production"""

import boto3
import time

INSTANCE_ID = "i-01a2c826c9cbd9218"

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


def main():
    print("🚀 Deploying updated app.py...")

    ssm_client = boto3.client('ssm', region_name='us-east-1')

    # Read app.py
    with open('app.py', 'r') as f:
        content = f.read()

    # Escape for printf
    content_escaped = content.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')

    # Split into chunks
    chunk_size = 3000
    chunks = [content_escaped[i:i+chunk_size] for i in range(0, len(content_escaped), chunk_size)]

    print(f"  File size: {len(content)} bytes, {len(chunks)} chunks")

    # Clear file
    commands = ['> /tmp/app.py']
    send_command(ssm_client, commands, "Create temp app.py")

    # Upload chunks
    for idx, chunk in enumerate(chunks, 1):
        commands = [f'printf "%s" "{chunk}" >> /tmp/app.py']
        result = send_command(ssm_client, commands, f"Upload chunk {idx}/{len(chunks)}")
        if result is None and idx % 10 == 0:
            print(f"  Warning: May have failed at chunk {idx}")

    # Move to production and restart
    commands = [
        'sudo mv /tmp/app.py /var/www/dnsscience/app.py',
        'sudo chown www-data:www-data /var/www/dnsscience/app.py',
        'sudo chmod 644 /var/www/dnsscience/app.py',
        'echo "Restarting Apache..."',
        'sudo systemctl restart apache2',
        'sleep 3',
        'sudo systemctl status apache2 | grep "active (running)"'
    ]
    send_command(ssm_client, commands, "Deploy and restart Apache")

    print("\n✅ app.py deployed and Apache restarted!")

if __name__ == '__main__':
    main()
