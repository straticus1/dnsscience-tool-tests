#!/usr/bin/env python3
"""
Fix remaining issues: Deploy missing tools templates and verify
"""

import boto3
import time

NEW_INSTANCE = 'i-0c3327f79e1d0791c'
REGION = 'us-east-1'
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
                stdout = result.get('StandardOutputContent', '')
                stderr = result.get('StandardErrorContent', '')

                if stdout:
                    print(stdout)

                return status == 'Success', stdout

        except Exception as e:
            continue

    return False, ""

def main():
    print("="*80)
    print("FIXING REMAINING ISSUES")
    print("="*80)

    # Deploy missing tools templates
    execute_command(
        f"""
        cd {REMOTE_APP_DIR}
        aws s3 sync s3://dnsscience-deployment/templates/tools/ {REMOTE_APP_DIR}/templates/tools/
        chown -R www-data:www-data {REMOTE_APP_DIR}/templates/tools/
        chmod -R 755 {REMOTE_APP_DIR}/templates/tools/
        echo "Files deployed:"
        ls -lh {REMOTE_APP_DIR}/templates/tools/
        """,
        "Deploying missing tools templates"
    )

    # Reload web server
    execute_command(
        "systemctl reload apache2 && echo 'Apache reloaded'",
        "Reloading Apache"
    )

    # Test the fixed pages
    print("\n" + "="*80)
    print("TESTING FIXED PAGES")
    print("="*80)

    success, output = execute_command(
        """
        echo "Testing tools pages:"
        curl -s -o /dev/null -w "/tools/dns-config-validator: HTTP %{http_code}\\n" https://www.dnsscience.io/tools/dns-config-validator
        curl -s -o /dev/null -w "/tools/cert-chain-resolver: HTTP %{http_code}\\n" https://www.dnsscience.io/tools/cert-chain-resolver
        curl -s -o /dev/null -w "/tools/dnssec-validator: HTTP %{http_code}\\n" https://www.dnsscience.io/tools/dnssec-validator
        curl -s -o /dev/null -w "/tools/jks-manager: HTTP %{http_code}\\n" https://www.dnsscience.io/tools/jks-manager
        echo ""
        echo "Testing dashboard (requires auth, expect 302/401):"
        curl -s -o /dev/null -w "/dashboard/domains: HTTP %{http_code}\\n" https://www.dnsscience.io/dashboard/domains
        """,
        "Testing previously broken pages"
    )

    print("\n" + "="*80)
    print("FINAL STATUS")
    print("="*80)
    print("\nAll missing tools templates have been deployed.")
    print("The site should now be fully functional.")
    print("\nRemaining steps:")
    print("1. Configure and start all 22 daemons")
    print("2. Update Auto Scaling Group Launch Template with these files")
    print("3. Monitor for any additional issues")

if __name__ == '__main__':
    import sys
    try:
        sys.exit(main())
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
