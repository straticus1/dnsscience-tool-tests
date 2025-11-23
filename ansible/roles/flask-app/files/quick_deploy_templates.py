#!/usr/bin/env python3
"""
Quick Template Deployment - Deploy templates one at a time
"""

import boto3
import time
import sys

INSTANCE_ID = 'i-02cb7ce3ba8b66a67'
REGION = 'us-east-1'
S3_BUCKET = 'dnsscience-deployment'
REMOTE_APP_DIR = '/var/www/dnsscience'

def execute_command(command_text, description, timeout=60):
    """Execute a command via SSM and wait for results"""
    ssm = boto3.client('ssm', region_name=REGION)

    print(f"  {description}...", end=' ', flush=True)
    response = ssm.send_command(
        InstanceIds=[INSTANCE_ID],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': [command_text]},
        TimeoutSeconds=timeout
    )

    command_id = response['Command']['CommandId']

    # Wait for command to complete
    for _ in range(timeout // 2):
        time.sleep(2)
        try:
            result = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=INSTANCE_ID
            )
            status = result['Status']
            if status in ['Success', 'Failed', 'TimedOut', 'Cancelled']:
                if status == 'Success':
                    print("✓")
                    return True, result.get('StandardOutputContent', '')
                else:
                    print(f"✗ ({status})")
                    return False, result.get('StandardErrorContent', '')
        except:
            continue

    print("✗ (timeout)")
    return False, "Command timed out"

def main():
    print("\n" + "="*80)
    print("  Quick Template Deployment to Production")
    print("="*80 + "\n")

    # Step 1: Create directories
    print("Step 1: Creating directories")
    success, _ = execute_command(
        f"mkdir -p {REMOTE_APP_DIR}/templates/dashboard {REMOTE_APP_DIR}/templates/marketplace {REMOTE_APP_DIR}/templates/tools",
        "Create template directories"
    )

    # Step 2: Deploy main HTML templates
    print("\nStep 2: Deploying main HTML templates")
    templates = [
        'explorer.html', 'about.html', 'api_docs.html', 'cli_docs.html',
        'login.html', 'signup.html', 'services.html', 'acquisition.html',
        'registrar.html', 'pricing.html'
    ]

    for template in templates:
        execute_command(
            f"aws s3 cp s3://{S3_BUCKET}/templates/{template} {REMOTE_APP_DIR}/templates/{template}",
            f"Deploy {template}",
            timeout=30
        )

    # Step 3: Deploy PHP templates
    print("\nStep 3: Deploying PHP templates")
    php_templates = [
        'index.php', 'browse.php', 'settings.php', 'scanners.php',
        'domain-profile.php', 'login.php', 'signup.php', 'reset-password.php'
    ]

    for template in php_templates:
        execute_command(
            f"aws s3 cp s3://{S3_BUCKET}/templates/{template} {REMOTE_APP_DIR}/templates/{template}",
            f"Deploy {template}",
            timeout=30
        )

    # Step 4: Deploy subdirectory templates
    print("\nStep 4: Deploying subdirectory templates")
    execute_command(
        f"aws s3 cp s3://{S3_BUCKET}/templates/dashboard/domains.html {REMOTE_APP_DIR}/templates/dashboard/domains.html",
        "Deploy dashboard/domains.html"
    )
    execute_command(
        f"aws s3 cp s3://{S3_BUCKET}/templates/marketplace/browse.html {REMOTE_APP_DIR}/templates/marketplace/browse.html",
        "Deploy marketplace/browse.html"
    )
    execute_command(
        f"aws s3 cp s3://{S3_BUCKET}/templates/tools/darkweb_lookup.html {REMOTE_APP_DIR}/templates/tools/darkweb_lookup.html",
        "Deploy tools/darkweb_lookup.html"
    )

    # Step 5: Set permissions
    print("\nStep 5: Setting permissions")
    execute_command(
        f"chown -R apache:apache {REMOTE_APP_DIR}/templates/ && chmod -R 755 {REMOTE_APP_DIR}/templates/",
        "Set ownership and permissions"
    )

    # Step 6: Reload Apache
    print("\nStep 6: Reloading Apache")
    success, output = execute_command(
        "systemctl reload httpd",
        "Reload Apache"
    )

    # Step 7: Verify deployment
    print("\nStep 7: Verifying deployment")
    success, output = execute_command(
        f"ls -lh {REMOTE_APP_DIR}/templates/*.html | wc -l",
        "Count HTML templates"
    )
    if success:
        print(f"  HTML templates: {output.strip()}")

    success, output = execute_command(
        f"ls -lh {REMOTE_APP_DIR}/templates/*.php | wc -l",
        "Count PHP templates"
    )
    if success:
        print(f"  PHP templates: {output.strip()}")

    # Step 8: Quick test
    print("\nStep 8: Quick smoke test")
    success, output = execute_command(
        'curl -s -o /dev/null -w "%{http_code}" https://www.dnsscience.io/explorer',
        "Test /explorer",
        timeout=15
    )
    if success:
        print(f"  Explorer page HTTP status: {output.strip()}")

    success, output = execute_command(
        'curl -s -o /dev/null -w "%{http_code}" https://www.dnsscience.io/about',
        "Test /about",
        timeout=15
    )
    if success:
        print(f"  About page HTTP status: {output.strip()}")

    print("\n" + "="*80)
    print("  Deployment Complete")
    print("="*80 + "\n")

    print("Templates have been deployed. Now run comprehensive tests with:")
    print("  python3 test_all_routes.py")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAborted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
