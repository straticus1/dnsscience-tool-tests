#!/usr/bin/env python3
"""Deploy fixed auth.py"""

import boto3
import time

INSTANCE_ID = "i-01a2c826c9cbd9218"

def send_command(ssm_client, commands, comment):
    """Send SSM command"""
    response = ssm_client.send_command(
        InstanceIds=[INSTANCE_ID],
        DocumentName='AWS-RunShellScript',
        Comment=comment,
        Parameters={'commands': commands}
    )

    command_id = response['Command']['CommandId']
    time.sleep(3)

    result = ssm_client.get_command_invocation(
        InstanceId=INSTANCE_ID,
        CommandId=command_id
    )

    return result['Status']


def main():
    print("🚀 Deploying fixed auth.py...")

    ssm_client = boto3.client('ssm', region_name='us-east-1')

    # Read file
    with open('auth.py', 'r') as f:
        content = f.read()

    content_escaped = content.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
    chunk_size = 3000
    chunks = [content_escaped[i:i+chunk_size] for i in range(0, len(content_escaped), chunk_size)]

    print(f"  Uploading {len(chunks)} chunks...")

    # Upload
    send_command(ssm_client, ['> /tmp/auth.py'], "Create temp file")

    for idx, chunk in enumerate(chunks, 1):
        send_command(ssm_client, [f'printf "%s" "{chunk}" >> /tmp/auth.py'], f"Chunk {idx}")
        if idx % 5 == 0:
            print(f"    {idx}/{len(chunks)} chunks uploaded")

    # Deploy
    commands = [
        'sudo mv /tmp/auth.py /var/www/dnsscience/auth.py',
        'sudo chown www-data:www-data /var/www/dnsscience/auth.py',
        'sudo chmod 644 /var/www/dnsscience/auth.py',
        'sudo systemctl restart apache2',
        'sleep 2',
        'echo "Apache restarted"'
    ]
    status = send_command(ssm_client, commands, "Deploy and restart")

    print(f"\n✅ auth.py deployed! Status: {status}")


if __name__ == '__main__':
    main()
