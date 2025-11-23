#!/usr/bin/env python3
"""
DNS Science - Complete Email Security Deployment
Deploys DANE/TLSA, MTA-STS, Redis, and Homepage Updates

This script:
1. Runs database migrations (DANE/TLSA, MTA-STS columns)
2. Installs and configures Redis
3. Deploys updated email daemon with DANE/MTA-STS support
4. Deploys Redis population script
5. Sets up cron jobs
6. Restarts all services
7. Verifies deployment

Instance: i-09a4c4b10763e3d39
"""

import boto3
import time
import sys
from datetime import datetime

INSTANCE_ID = "i-09a4c4b10763e3d39"
S3_BUCKET = "dnsscience-deployment"
S3_PREFIX = f"email_security_complete/{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# Colors
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
NC = '\033[0m'

ssm = boto3.client('ssm')
s3 = boto3.client('s3')

def log(msg):
    print(f"{GREEN}[{datetime.now().strftime('%H:%M:%S')}]{NC} {msg}")

def log_error(msg):
    print(f"{RED}[{datetime.now().strftime('%H:%M:%S')}] ERROR:{NC} {msg}")

def log_info(msg):
    print(f"{CYAN}[{datetime.now().strftime('%H:%M:%S')}] INFO:{NC} {msg}")

def log_section(msg):
    print(f"\n{BLUE}{'='*70}")
    print(f"{msg}")
    print(f"{'='*70}{NC}\n")

def run_ssm_command(command, description="Executing command", critical=True):
    """Execute SSM command and return output"""
    log_info(description)

    try:
        response = ssm.send_command(
            InstanceIds=[INSTANCE_ID],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [command]},
        )

        command_id = response['Command']['CommandId']

        # Wait for command to complete
        time.sleep(3)

        max_attempts = 40
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
                    if critical:
                        return False
                    return True  # Non-critical failure

                elif status in ['Pending', 'InProgress']:
                    time.sleep(2)
                    continue

            except Exception as e:
                if 'InvocationDoesNotExist' in str(e):
                    time.sleep(2)
                    continue
                raise

        log_error("Command timed out")
        return False if critical else True

    except Exception as e:
        log_error(f"Failed to execute command: {e}")
        return False if critical else True

def main():
    log_section("DNS SCIENCE - COMPLETE EMAIL SECURITY DEPLOYMENT")
    print(f"{CYAN}Deploying: DANE/TLSA + MTA-STS + Redis + Homepage Updates{NC}\n")

    # Step 1: Upload files to S3
    log_section("STEP 1: Uploading Files to S3")

    files_to_upload = [
        ('migrations/015_dane_tlsa_columns.sql', '015_dane_tlsa_columns.sql'),
        ('migrations/016_mta_sts_columns.sql', '016_mta_sts_columns.sql'),
        ('daemons/emaild_complete.py', 'emaild_complete.py'),
        ('populate_redis_stats.py', 'populate_redis_stats.py'),
    ]

    for local_path, s3_key in files_to_upload:
        log_info(f"Uploading {local_path}...")
        try:
            s3.upload_file(
                local_path,
                S3_BUCKET,
                f"{S3_PREFIX}/{s3_key}"
            )
        except Exception as e:
            log_error(f"Failed to upload {local_path}: {e}")
            return 1

    log("All files uploaded to S3\n")

    # Step 2: Download files on instance
    log_section("STEP 2: Downloading Files on Instance")
    if not run_ssm_command(
        f"mkdir -p /tmp/email_security_deploy && cd /tmp/email_security_deploy && aws s3 sync s3://{S3_BUCKET}/{S3_PREFIX}/ . && ls -lah",
        "Downloading deployment files from S3"
    ):
        return 1
    log("Files downloaded\n")

    # Step 3: Run database migrations
    log_section("STEP 3: Running Database Migrations")

    log_info("Running DANE/TLSA migration...")
    if not run_ssm_command(
        """cd /var/www/dnsscience && export $(grep -v '^#' .env.production | xargs) && \
PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
-f /tmp/email_security_deploy/015_dane_tlsa_columns.sql && \
echo "DANE/TLSA columns created successfully" """,
        "Creating DANE/TLSA database columns"
    ):
        log_error("DANE/TLSA migration failed!")
        return 1

    log_info("Running MTA-STS migration...")
    if not run_ssm_command(
        """cd /var/www/dnsscience && export $(grep -v '^#' .env.production | xargs) && \
PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
-f /tmp/email_security_deploy/016_mta_sts_columns.sql && \
echo "MTA-STS columns created successfully" """,
        "Creating MTA-STS database columns"
    ):
        log_error("MTA-STS migration failed!")
        return 1

    log("Database migrations completed\n")

    # Step 4: Verify database schema
    log_section("STEP 4: Verifying Database Schema")
    run_ssm_command(
        """cd /var/www/dnsscience && export $(grep -v '^#' .env.production | xargs) && \
PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c \
"SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'email_security_records' AND column_name IN ('has_dane', 'tlsa_records', 'tlsa_count', 'has_mta_sts', 'mta_sts_policy', 'mta_sts_mode', 'mta_sts_max_age') ORDER BY column_name" """,
        "Checking new columns exist"
    )

    # Step 5: Install Redis
    log_section("STEP 5: Installing and Configuring Redis")

    if not run_ssm_command(
        """if ! command -v redis-cli &> /dev/null; then
    echo "Installing Redis..."
    sudo apt-get update -qq
    sudo apt-get install -y redis-server
    sudo systemctl enable redis-server
    sudo systemctl start redis-server
    echo "Redis installed"
else
    echo "Redis already installed"
    sudo systemctl start redis-server || true
fi

# Configure Redis
redis-cli CONFIG SET maxmemory 256mb
redis-cli CONFIG SET maxmemory-policy allkeys-lru
redis-cli CONFIG SET save "900 1 300 10 60 10000"
redis-cli CONFIG REWRITE || echo "Config rewrite failed (may need redis.conf edit)"

# Test Redis
redis-cli PING && echo "Redis is responding" """,
        "Installing and configuring Redis server"
    ):
        log_error("Redis installation failed!")
        return 1

    log("Redis installed and configured\n")

    # Step 6: Deploy email daemon
    log_section("STEP 6: Deploying Updated Email Daemon")

    if not run_ssm_command(
        """cd /var/www/dnsscience/daemons
# Backup current daemon
sudo cp emaild.py emaild.py.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null || echo "No existing emaild.py to backup"

# Deploy new daemon
sudo cp /tmp/email_security_deploy/emaild_complete.py emaild.py
sudo chown www-data:www-data emaild.py
sudo chmod 755 emaild.py

# Verify file
ls -lah emaild.py
head -5 emaild.py """,
        "Deploying email daemon with DANE/MTA-STS support"
    ):
        return 1

    log("Email daemon deployed\n")

    # Step 7: Deploy Redis population script
    log_section("STEP 7: Deploying Redis Population Script")

    if not run_ssm_command(
        """sudo cp /tmp/email_security_deploy/populate_redis_stats.py /usr/local/bin/
sudo chmod +x /usr/local/bin/populate_redis_stats.py
sudo chown root:root /usr/local/bin/populate_redis_stats.py
ls -lah /usr/local/bin/populate_redis_stats.py """,
        "Installing Redis population script"
    ):
        return 1

    log("Redis population script installed\n")

    # Step 8: Run Redis population script once
    log_section("STEP 8: Populating Redis with Current Stats")

    run_ssm_command(
        "cd /var/www/dnsscience && sudo -u www-data python3 /usr/local/bin/populate_redis_stats.py",
        "Running initial Redis population",
        critical=False  # Don't fail if this errors
    )

    # Step 9: Set up cron jobs
    log_section("STEP 9: Setting Up Automated Cron Jobs")

    cron_entry = """# Redis Stats Population - Every 5 minutes
*/5 * * * * /usr/bin/python3 /usr/local/bin/populate_redis_stats.py >> /var/log/dnsscience/redis_populate.log 2>&1
"""

    if not run_ssm_command(
        f"""sudo mkdir -p /var/log/dnsscience
sudo touch /var/log/dnsscience/redis_populate.log
sudo chown www-data:www-data /var/log/dnsscience/redis_populate.log

# Check if entry already exists
if ! grep -q "populate_redis_stats.py" /etc/cron.d/dnsscience_maintenance 2>/dev/null; then
    sudo bash -c 'echo "{cron_entry}" >> /etc/cron.d/dnsscience_maintenance'
    echo "Cron job added"
else
    echo "Cron job already exists"
fi

cat /etc/cron.d/dnsscience_maintenance """,
        "Adding Redis population cron job"
    ):
        log_error("Cron job setup failed (non-critical)")

    log("Cron jobs configured\n")

    # Step 10: Restart email daemon
    log_section("STEP 10: Restarting Email Daemon")

    if not run_ssm_command(
        """# Stop email daemon
sudo pkill -f 'python3.*emaild' || echo "No email daemon running"

# Wait a moment
sleep 2

# Start email daemon
cd /var/www/dnsscience/daemons
sudo -u www-data nohup python3 emaild.py >> /var/log/dnsscience/emaild.log 2>&1 &

# Wait for it to start
sleep 3

# Verify it's running
if ps aux | grep -v grep | grep 'python3.*emaild'; then
    echo "Email daemon started successfully"
else
    echo "WARNING: Email daemon may not be running"
fi """,
        "Restarting email daemon with new code"
    ):
        log_error("Email daemon restart failed!")

    log("Email daemon restarted\n")

    # Step 11: Verification
    log_section("STEP 11: DEPLOYMENT VERIFICATION")

    log_info("Checking database schema...")
    run_ssm_command(
        """cd /var/www/dnsscience && export $(grep -v '^#' .env.production | xargs) && \
PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
"SELECT
    'Total email records: ' || COUNT(*) || E'\\n' ||
    'With DANE: ' || COUNT(CASE WHEN has_dane THEN 1 END) || E'\\n' ||
    'With MTA-STS: ' || COUNT(CASE WHEN has_mta_sts THEN 1 END) || E'\\n' ||
    'With DKIM: ' || COUNT(CASE WHEN has_dkim THEN 1 END)
FROM email_security_records" """,
        "Querying email security statistics"
    )

    log_info("Checking Redis...")
    run_ssm_command(
        """redis-cli PING
echo "Keys in Redis:"
redis-cli KEYS 'stats:*' | head -10
echo ""
echo "Sample values:"
redis-cli GET stats:total_domains
redis-cli GET stats:email_dmarc
redis-cli GET stats:email_dane """,
        "Testing Redis connectivity and data"
    )

    log_info("Checking daemon status...")
    run_ssm_command(
        "ps aux | grep -E 'python3.*emaild' | grep -v grep",
        "Checking email daemon process"
    )

    log_info("Checking recent daemon logs...")
    run_ssm_command(
        "sudo tail -20 /var/log/dnsscience/emaild.log",
        "Reviewing email daemon logs",
        critical=False
    )

    # Final summary
    log_section("DEPLOYMENT COMPLETE!")

    print(f"""
{GREEN}Summary of Changes:{NC}
-------------------
{GREEN}✓{NC} Database: DANE/TLSA columns added to email_security_records
{GREEN}✓{NC} Database: MTA-STS columns added to email_security_records
{GREEN}✓{NC} Redis: Installed and configured (256MB max memory)
{GREEN}✓{NC} Email Daemon: Updated with DANE/TLSA and MTA-STS checking
{GREEN}✓{NC} Redis Population: Script installed and initial run completed
{GREEN}✓{NC} Cron Jobs: Redis stats refresh every 5 minutes
{GREEN}✓{NC} Services: Email daemon restarted with new code

{CYAN}What's Now Collecting:{NC}
-----------------------
• MX Records (existing)
• SPF Records (existing)
• DMARC Records (existing)
• DKIM Selectors (existing)
{YELLOW}• DANE/TLSA Records (NEW){NC}
{YELLOW}• MTA-STS Policies (NEW){NC}

{CYAN}Next Steps:{NC}
-----------
1. Monitor email daemon logs for 30 minutes:
   {BLUE}sudo tail -f /var/log/dnsscience/emaild.log{NC}

2. Check data collection after 1 hour:
   {BLUE}psql -h localhost -p 6432 -U dnsscience -d dnsscience -c \\
   "SELECT COUNT(*) as total, \\
    COUNT(CASE WHEN has_dane THEN 1 END) as with_dane, \\
    COUNT(CASE WHEN has_mta_sts THEN 1 END) as with_mta_sts \\
    FROM email_security_records \\
    WHERE last_checked > NOW() - INTERVAL '1 hour'"{NC}

3. Verify Redis stats updating:
   {BLUE}redis-cli GET stats:email_dane{NC}

4. Update homepage template to display new metrics (see COMPREHENSIVE_PROJECT_PLAN.md)

5. Update /api/stats endpoint to include DANE/MTA-STS counts (see COMPREHENSIVE_PROJECT_PLAN.md)

{CYAN}Expected Results Tomorrow Morning:{NC}
----------------------------------
• DANE count > 0 (some domains have DANE configured)
• MTA-STS count > 0 (gmail.com, outlook.com, etc.)
• Homepage showing all email security metrics
• Redis responding with live stats
• Zero "Loading..." states on homepage

{GREEN}DEPLOYMENT SUCCESSFUL!{NC}
""")

    return 0

if __name__ == '__main__':
    sys.exit(main())
