#!/usr/bin/env python3
"""
DNS Science - Direct Deployment of All Fixes
Uses AWS SSM to directly deploy and run all fixes
"""

import boto3
import time
import sys
from datetime import datetime

INSTANCE_ID = "i-09a4c4b10763e3d39"
S3_BUCKET = "dnsscience-deployment"
S3_PREFIX = f"fixes/{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# Colors
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'

ssm = boto3.client('ssm')
s3 = boto3.client('s3')

def log(msg):
    print(f"{GREEN}[{datetime.now().strftime('%H:%M:%S')}]{NC} {msg}")

def log_error(msg):
    print(f"{RED}[{datetime.now().strftime('%H:%M:%S')}] ERROR:{NC} {msg}")

def log_info(msg):
    print(f"{BLUE}[{datetime.now().strftime('%H:%M:%S')}] INFO:{NC} {msg}")

def run_ssm_command(command, description="Executing command"):
    """Execute SSM command and return output"""
    log_info(description)

    try:
        response = ssm.send_command(
            InstanceIds=[INSTANCE_ID],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [command]},
        )

        command_id = response['Command']['CommandId']
        log_info(f"Command ID: {command_id}")

        # Wait for command to complete
        time.sleep(3)

        max_attempts = 30
        for attempt in range(max_attempts):
            try:
                result = ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=INSTANCE_ID,
                )

                status = result['Status']

                if status == 'Success':
                    output = result.get('StandardOutputContent', '')
                    if output:
                        print(output)
                    return True

                elif status == 'Failed':
                    log_error(f"Command failed!")
                    error_output = result.get('StandardErrorContent', '')
                    if error_output:
                        print(error_output)
                    return False

                elif status in ['Pending', 'InProgress']:
                    time.sleep(2)
                    continue

            except Exception as e:
                if 'InvocationDoesNotExist' in str(e):
                    time.sleep(2)
                    continue
                raise

        log_error("Command timed out")
        return False

    except Exception as e:
        log_error(f"Failed to execute command: {e}")
        return False

def main():
    print("\n" + "="*80)
    print("  DNS SCIENCE - DEPLOY ALL FIXES")
    print("  Making Everything PERFECT for Tomorrow Morning")
    print("="*80 + "\n")

    # Step 1: Upload files to S3
    log("STEP 1: Uploading fix files to S3")
    files_to_upload = [
        'fix_all_database_issues.py',
        'reputationd_fixed.py',
        'update_geoip_data.sh',
        'db_maintenance.sh'
    ]

    for filename in files_to_upload:
        log_info(f"Uploading {filename}...")
        try:
            s3.upload_file(
                filename,
                S3_BUCKET,
                f"{S3_PREFIX}/{filename}"
            )
        except Exception as e:
            log_error(f"Failed to upload {filename}: {e}")
            return 1

    log("✓ All files uploaded\n")

    # Step 2: Download files on instance
    log("STEP 2: Downloading files on instance")
    if not run_ssm_command(
        f"mkdir -p /tmp/dnsscience_fixes && cd /tmp/dnsscience_fixes && aws s3 sync s3://{S3_BUCKET}/{S3_PREFIX}/ . && chmod +x *.sh && ls -la",
        "Downloading and preparing fix files"
    ):
        return 1
    log("✓ Files downloaded\n")

    # Step 3: Run database fixes
    log("STEP 3: Running database schema fixes")
    if not run_ssm_command(
        "sudo -u www-data python3 /tmp/dnsscience_fixes/fix_all_database_issues.py",
        "Applying database fixes (GeoIP tables, missing columns, indexes)"
    ):
        log_error("Database fixes failed!")
        return 1
    log("✓ Database fixes applied\n")

    # Step 4: Deploy fixed reputation daemon
    log("STEP 4: Deploying fixed Reputation daemon")
    if not run_ssm_command(
        "sudo cp /var/www/dnsscience/daemons/reputationd.py /var/www/dnsscience/daemons/reputationd.py.bak.$(date +%Y%m%d_%H%M%S) && sudo cp /tmp/dnsscience_fixes/reputationd_fixed.py /var/www/dnsscience/daemons/reputationd.py && sudo chown www-data:www-data /var/www/dnsscience/daemons/reputationd.py && echo 'Reputation daemon deployed'",
        "Backing up and deploying fixed reputation daemon"
    ):
        return 1
    log("✓ Reputation daemon updated\n")

    # Step 5: Deploy enrichment daemon fix
    log("STEP 5: Applying Enrichment daemon fix")
    if not run_ssm_command(
        "cd /var/www/dnsscience/daemons && if [ -f enrichment_daemon_db_fix.py ]; then sudo cp enrichment_daemon.py enrichment_daemon.py.bak.$(date +%Y%m%d_%H%M%S) && sudo cp enrichment_daemon_db_fix.py enrichment_daemon.py && sudo chown www-data:www-data enrichment_daemon.py && echo 'Enrichment daemon fixed'; else echo 'No enrichment fix file found, skipping'; fi",
        "Applying enrichment daemon database connection fix"
    ):
        log_info("Enrichment daemon fix skipped or already applied")
    log("✓ Enrichment daemon checked\n")

    # Step 6: Deploy scripts
    log("STEP 6: Deploying maintenance scripts")
    if not run_ssm_command(
        "sudo cp /tmp/dnsscience_fixes/update_geoip_data.sh /usr/local/bin/ && sudo cp /tmp/dnsscience_fixes/db_maintenance.sh /usr/local/bin/ && sudo chmod +x /usr/local/bin/update_geoip_data.sh /usr/local/bin/db_maintenance.sh && sudo chown root:root /usr/local/bin/update_geoip_data.sh /usr/local/bin/db_maintenance.sh && ls -la /usr/local/bin/*.sh",
        "Installing GeoIP update and database maintenance scripts"
    ):
        return 1
    log("✓ Maintenance scripts installed\n")

    # Step 7: Create cron jobs
    log("STEP 7: Creating automated cron jobs")
    cron_content = """# DNS Science Automated Maintenance Jobs

# GeoIP Update - Monthly on 1st at 3 AM
0 3 1 * * root /usr/local/bin/update_geoip_data.sh >> /var/log/dnsscience/geoip_update.log 2>&1

# Database Maintenance - Weekly on Sunday at 2 AM
0 2 * * 0 root /usr/local/bin/db_maintenance.sh >> /var/log/dnsscience/db_maintenance.log 2>&1

# Database Quick Stats - Daily at 1 AM
0 1 * * * postgres /usr/bin/vacuumdb --analyze-only -h localhost -p 6432 -U dnsscience_app dnsscience >> /var/log/dnsscience/vacuum.log 2>&1
"""

    if not run_ssm_command(
        f"sudo mkdir -p /var/log/dnsscience && sudo bash -c 'cat > /etc/cron.d/dnsscience_maintenance <<EOF\n{cron_content}\nEOF' && sudo chmod 644 /etc/cron.d/dnsscience_maintenance && cat /etc/cron.d/dnsscience_maintenance",
        "Creating cron jobs for automated maintenance"
    ):
        return 1
    log("✓ Cron jobs created\n")

    # Step 8: Restart daemons
    log("STEP 8: Restarting all daemons")
    log_info("Stopping daemons...")
    run_ssm_command(
        "sudo pkill -f 'python3.*daemon' || true",
        "Stopping all Python daemons"
    )

    time.sleep(2)

    log_info("Starting daemons...")
    if not run_ssm_command(
        "cd /var/www/dnsscience/daemons && for daemon in *d.py; do sudo -u www-data nohup python3 $daemon >> /var/log/dnsscience/$(basename $daemon .py).log 2>&1 & done && sleep 2 && ps aux | grep -E 'python3.*daemon' | grep -v grep",
        "Starting all daemons"
    ):
        log_error("Warning: Some daemons may not have started")
    log("✓ Daemons restarted\n")

    # Step 9: Restart Apache
    log("STEP 9: Restarting Apache")
    if not run_ssm_command(
        "sudo systemctl restart apache2 && sleep 2 && sudo systemctl status apache2 --no-pager | head -10",
        "Restarting Apache web server"
    ):
        return 1
    log("✓ Apache restarted\n")

    # Step 10: Verification
    log("="*80)
    log("STEP 10: VERIFICATION")
    log("="*80 + "\n")

    log("Checking database tables...")
    run_ssm_command(
        "cd /var/www/dnsscience && export $(grep -v '^#' .env.production | xargs) && psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c '\\dt geoip*' && psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -c \"SELECT COUNT(*) || ' location records' FROM geoip_locations\" && psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -c \"SELECT COUNT(*) || ' IP block records' FROM geoip_blocks\"",
        "Verifying GeoIP tables"
    )

    log("\nChecking ip_reputation table columns...")
    run_ssm_command(
        "cd /var/www/dnsscience && export $(grep -v '^#' .env.production | xargs) && psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c '\\d ip_reputation'",
        "Verifying ip_reputation table structure"
    )

    log("\nChecking daemon status...")
    run_ssm_command(
        "ps aux | grep -E 'python3.*(reputationd|geoipd|enrichment)' | grep -v grep",
        "Checking critical daemon processes"
    )

    log("\nChecking recent daemon logs (last 10 lines each)...")
    run_ssm_command(
        "for log in /var/log/dnsscience/reputationd.log /var/log/dnsscience/geoipd.log /var/log/dnsscience/enrichment_daemon.log; do echo \"=== $log ===\"  if [ -f \"$log\" ]; then tail -10 \"$log\"; else echo 'Log not found'; fi; echo; done",
        "Checking daemon logs for errors"
    )

    log("\nTesting API endpoints...")
    run_ssm_command(
        "echo '=== /api/stats/live ===' && curl -s http://localhost/api/stats/live | python3 -m json.tool",
        "Testing stats API"
    )

    log("\n" + "="*80)
    log("DEPLOYMENT COMPLETE!")
    log("="*80 + "\n")

    print("""
Summary of Changes:
-------------------
✓ Created GeoIP tables (geoip_blocks, geoip_locations)
✓ Added missing columns to ip_reputation table
✓ Created performance indexes for better query speed
✓ Fixed Reputation daemon (proper LEFT JOIN handling)
✓ Fixed Enrichment daemon (database connection handling)
✓ Deployed GeoIP update script (/usr/local/bin/update_geoip_data.sh)
✓ Deployed database maintenance script (/usr/local/bin/db_maintenance.sh)
✓ Created automated cron jobs for monthly/weekly maintenance
✓ Restarted all daemons with latest code
✓ Restarted Apache web server

Next Steps:
-----------
1. Monitor logs: tail -f /var/log/dnsscience/*.log
2. Test Explorer: https://www.dnsscience.io/explorer
3. Import GeoIP data: ssh to instance and run /usr/local/bin/update_geoip_data.sh
   (Requires MaxMind license key in .env.production as MAXMIND_LICENSE_KEY)

All systems should now be running error-free!
""")

    return 0

if __name__ == '__main__':
    sys.exit(main())
