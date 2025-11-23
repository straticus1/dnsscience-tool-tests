#!/usr/bin/env python3
"""
Deploy DNS Auto Lookup Feature to Production
Deploys HTML, CSS, JS, and API endpoints to DNS Science production server
"""

import boto3
import sys
import os
from datetime import datetime

# AWS Configuration
INSTANCE_ID = 'i-09a4c4b10763e3d39'
REGION = 'us-east-1'

# File paths
FILES_TO_DEPLOY = {
    'autolookup.html': '/var/www/dnsscience/templates/autolookup.html',
    'autolookup.css': '/var/www/dnsscience/static/css/autolookup.css',
    'autolookup.js': '/var/www/dnsscience/static/js/autolookup.js',
    'autolookup_api.py': '/var/www/dnsscience/autolookup_api.py',
}

def read_file(filepath):
    """Read file contents"""
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        return None

def deploy_file(ssm, instance_id, local_path, remote_path):
    """Deploy a single file to the server"""
    print(f"Deploying {local_path} -> {remote_path}")

    content = read_file(local_path)
    if content is None:
        return False

    # Escape single quotes in content
    content_escaped = content.replace("'", "'\\''")

    # Create directory if needed
    dir_path = os.path.dirname(remote_path)
    commands = [
        f"sudo mkdir -p {dir_path}",
        f"sudo tee {remote_path} > /dev/null << 'EOFMARKER'\n{content}\nEOFMARKER",
        f"sudo chown www-data:www-data {remote_path}",
        f"sudo chmod 644 {remote_path}"
    ]

    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': commands},
            TimeoutSeconds=60
        )

        command_id = response['Command']['CommandId']
        print(f"  Command ID: {command_id}")

        # Wait for command to complete
        import time
        time.sleep(2)

        # Get command result
        output = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )

        if output['Status'] == 'Success':
            print(f"  ✓ Successfully deployed {local_path}")
            return True
        else:
            print(f"  ✗ Failed to deploy {local_path}")
            print(f"  Error: {output.get('StandardErrorContent', 'Unknown error')}")
            return False

    except Exception as e:
        print(f"  ✗ Error deploying {local_path}: {str(e)}")
        return False

def update_app_py(ssm, instance_id):
    """Add autolookup integration to app.py"""
    print("\nUpdating app.py to include autolookup routes...")

    # Python code to add to app.py
    integration_code = """
# Import autolookup routes
try:
    from autolookup_api import register_autolookup_routes
    register_autolookup_routes(app)
    print("DNS Auto Lookup routes registered successfully")
except ImportError as e:
    print(f"Warning: Could not import autolookup_api: {e}")
"""

    commands = [
        # Backup app.py
        "sudo cp /var/www/dnsscience/app.py /var/www/dnsscience/app.py.backup_$(date +%Y%m%d_%H%M%S)",

        # Check if autolookup is already integrated
        "if ! grep -q 'autolookup_api' /var/www/dnsscience/app.py; then " +
        "sudo bash -c 'echo \"\" >> /var/www/dnsscience/app.py'; " +
        "sudo bash -c 'echo \"# DNS Auto Lookup Integration\" >> /var/www/dnsscience/app.py'; " +
        "sudo bash -c 'echo \"try:\" >> /var/www/dnsscience/app.py'; " +
        "sudo bash -c 'echo \"    from autolookup_api import register_autolookup_routes\" >> /var/www/dnsscience/app.py'; " +
        "sudo bash -c 'echo \"    register_autolookup_routes(app)\" >> /var/www/dnsscience/app.py'; " +
        "sudo bash -c 'echo \"    print(\\\"DNS Auto Lookup routes registered successfully\\\")\" >> /var/www/dnsscience/app.py'; " +
        "sudo bash -c 'echo \"except ImportError as e:\" >> /var/www/dnsscience/app.py'; " +
        "sudo bash -c 'echo \"    print(f\\\"Warning: Could not import autolookup_api: {e}\\\")\" >> /var/www/dnsscience/app.py'; " +
        "echo 'Added autolookup integration'; " +
        "else echo 'Autolookup already integrated'; fi",

        # Set ownership
        "sudo chown www-data:www-data /var/www/dnsscience/app.py"
    ]

    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': commands},
            TimeoutSeconds=60
        )

        command_id = response['Command']['CommandId']
        print(f"  Command ID: {command_id}")

        import time
        time.sleep(2)

        output = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )

        if output['Status'] == 'Success':
            print(f"  ✓ Successfully updated app.py")
            print(f"  Output: {output.get('StandardOutputContent', '')}")
            return True
        else:
            print(f"  ✗ Failed to update app.py")
            print(f"  Error: {output.get('StandardErrorContent', 'Unknown error')}")
            return False

    except Exception as e:
        print(f"  ✗ Error updating app.py: {str(e)}")
        return False

def restart_apache(ssm, instance_id):
    """Restart Apache to load new routes"""
    print("\nRestarting Apache web server...")

    commands = [
        "sudo systemctl restart apache2",
        "sudo systemctl status apache2 --no-pager"
    ]

    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': commands},
            TimeoutSeconds=60
        )

        command_id = response['Command']['CommandId']
        print(f"  Command ID: {command_id}")

        import time
        time.sleep(3)

        output = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )

        if output['Status'] == 'Success':
            print(f"  ✓ Apache restarted successfully")
            return True
        else:
            print(f"  ✗ Failed to restart Apache")
            print(f"  Error: {output.get('StandardErrorContent', 'Unknown error')}")
            return False

    except Exception as e:
        print(f"  ✗ Error restarting Apache: {str(e)}")
        return False

def verify_deployment(ssm, instance_id):
    """Verify that files were deployed correctly"""
    print("\nVerifying deployment...")

    commands = [
        "echo '=== Checking deployed files ==='",
        "ls -lh /var/www/dnsscience/templates/autolookup.html 2>&1",
        "ls -lh /var/www/dnsscience/static/css/autolookup.css 2>&1",
        "ls -lh /var/www/dnsscience/static/js/autolookup.js 2>&1",
        "ls -lh /var/www/dnsscience/autolookup_api.py 2>&1",
        "echo ''",
        "echo '=== Checking app.py integration ==='",
        "grep -n 'autolookup_api' /var/www/dnsscience/app.py || echo 'Not found in app.py'",
        "echo ''",
        "echo '=== Apache status ==='",
        "sudo systemctl is-active apache2"
    ]

    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': commands},
            TimeoutSeconds=60
        )

        command_id = response['Command']['CommandId']

        import time
        time.sleep(2)

        output = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )

        print("\n" + output.get('StandardOutputContent', ''))

        if output.get('StandardErrorContent'):
            print("Errors:\n" + output.get('StandardErrorContent', ''))

        return output['Status'] == 'Success'

    except Exception as e:
        print(f"  ✗ Error verifying deployment: {str(e)}")
        return False

def main():
    """Main deployment function"""
    print("=" * 60)
    print("DNS Auto Lookup Deployment")
    print("=" * 60)
    print(f"Instance: {INSTANCE_ID}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Initialize AWS SSM client
    try:
        ssm = boto3.client('ssm', region_name=REGION)
        print("✓ Connected to AWS SSM")
    except Exception as e:
        print(f"✗ Failed to connect to AWS: {str(e)}")
        return False

    # Deploy files
    print("\n" + "=" * 60)
    print("Deploying Files")
    print("=" * 60)

    all_success = True
    for local_file, remote_file in FILES_TO_DEPLOY.items():
        if not deploy_file(ssm, INSTANCE_ID, local_file, remote_file):
            all_success = False

    if not all_success:
        print("\n⚠ Some files failed to deploy")
        return False

    # Update app.py
    print("\n" + "=" * 60)
    print("Integrating with Flask App")
    print("=" * 60)

    if not update_app_py(ssm, INSTANCE_ID):
        print("\n⚠ Failed to update app.py")
        return False

    # Restart Apache
    print("\n" + "=" * 60)
    print("Restarting Web Server")
    print("=" * 60)

    if not restart_apache(ssm, INSTANCE_ID):
        print("\n⚠ Failed to restart Apache")
        return False

    # Verify deployment
    verify_deployment(ssm, INSTANCE_ID)

    # Success message
    print("\n" + "=" * 60)
    print("DEPLOYMENT COMPLETE")
    print("=" * 60)
    print("\nDNS Auto Lookup is now available at:")
    print("  https://www.dnsscience.io/autolookup")
    print("\nAPI Endpoints:")
    print("  https://www.dnsscience.io/api/autolookup/ip")
    print("  https://www.dnsscience.io/api/autolookup/resolver")
    print("  https://www.dnsscience.io/api/autolookup/edns")
    print("  https://www.dnsscience.io/api/autolookup/security")
    print("  https://www.dnsscience.io/api/autolookup/all")
    print("\n" + "=" * 60)

    return True

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
