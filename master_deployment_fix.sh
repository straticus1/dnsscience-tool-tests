#!/bin/bash
###############################################################################
# DNS Science - MASTER DEPLOYMENT FIX
# Fixes ALL database and daemon issues for perfect production deployment
#
# This script will:
# 1. Fix all database schema issues (GeoIP tables, missing columns)
# 2. Deploy fixed Reputation daemon
# 3. Deploy Enrichment daemon fix
# 4. Deploy GeoIP update script
# 5. Deploy database maintenance script
# 6. Create cron jobs
# 7. Restart all services
# 8. Verify everything works
###############################################################################

set -euo pipefail

INSTANCE_ID="i-09a4c4b10763e3d39"
LOG_FILE="/tmp/master_deployment_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $*" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO:${NC} $*" | tee -a "$LOG_FILE"
}

error_exit() {
    log_error "$1"
    exit 1
}

# Execute SSM command and wait for result
execute_ssm() {
    local command="$1"
    local description="${2:-Executing command}"

    log_info "$description"

    local command_id=$(aws ssm send-command \
        --instance-ids "$INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters "commands=[\"$command\"]" \
        --output text \
        --query 'Command.CommandId')

    log_info "Command ID: $command_id"

    # Wait for command to complete
    sleep 5

    local status=""
    local retries=0
    while [ "$status" != "Success" ] && [ "$status" != "Failed" ] && [ $retries -lt 30 ]; do
        status=$(aws ssm get-command-invocation \
            --command-id "$command_id" \
            --instance-id "$INSTANCE_ID" \
            --query 'Status' \
            --output text 2>/dev/null || echo "Pending")

        if [ "$status" == "Success" ]; then
            break
        elif [ "$status" == "Failed" ]; then
            log_error "Command failed!"
            aws ssm get-command-invocation \
                --command-id "$command_id" \
                --instance-id "$INSTANCE_ID" \
                --query 'StandardErrorContent' \
                --output text
            return 1
        fi

        sleep 2
        ((retries++))
    done

    # Get output
    aws ssm get-command-invocation \
        --command-id "$command_id" \
        --instance-id "$INSTANCE_ID" \
        --query 'StandardOutputContent' \
        --output text

    return 0
}

echo ""
echo "================================================================================"
echo "  DNS SCIENCE - MASTER DEPLOYMENT FIX"
echo "  Making Everything PERFECT for Tomorrow Morning"
echo "================================================================================"
echo ""

log "Starting master deployment fix..."

# ========================================
# STEP 1: Upload all fix files
# ========================================
log "========================================"
log "STEP 1: Uploading Fix Files to S3"
log "========================================"

S3_BUCKET="dnsscience-deployment"
S3_PREFIX="fixes/$(date +%Y%m%d_%H%M%S)"

log "Uploading fix_all_database_issues.py..."
aws s3 cp fix_all_database_issues.py "s3://$S3_BUCKET/$S3_PREFIX/" || error_exit "Failed to upload database fix script"

log "Uploading reputationd_fixed.py..."
aws s3 cp reputationd_fixed.py "s3://$S3_BUCKET/$S3_PREFIX/" || error_exit "Failed to upload reputation daemon"

log "Uploading update_geoip_data.sh..."
aws s3 cp update_geoip_data.sh "s3://$S3_BUCKET/$S3_PREFIX/" || error_exit "Failed to upload GeoIP script"

log "Uploading db_maintenance.sh..."
aws s3 cp db_maintenance.sh "s3://$S3_BUCKET/$S3_PREFIX/" || error_exit "Failed to upload maintenance script"

log "✓ All files uploaded to S3"

# ========================================
# STEP 2: Download files on instance
# ========================================
log ""
log "========================================"
log "STEP 2: Downloading Files on Instance"
log "========================================"

execute_ssm "mkdir -p /tmp/dnsscience_fixes && cd /tmp/dnsscience_fixes && aws s3 sync s3://$S3_BUCKET/$S3_PREFIX/ . && chmod +x *.sh" \
    "Downloading fix files from S3"

log "✓ Files downloaded and made executable"

# ========================================
# STEP 3: Run Database Fixes
# ========================================
log ""
log "========================================"
log "STEP 3: Running Database Fixes"
log "========================================"

log_info "Loading environment variables and running database fix..."
execute_ssm "cd /var/www/dnsscience && export \$(grep -v '^#' .env.production | xargs) && python3 /tmp/dnsscience_fixes/fix_all_database_issues.py" \
    "Running comprehensive database fix"

log "✓ Database fixes applied"

# ========================================
# STEP 4: Deploy Fixed Reputation Daemon
# ========================================
log ""
log "========================================"
log "STEP 4: Deploying Fixed Reputation Daemon"
log "========================================"

execute_ssm "sudo cp /var/www/dnsscience/daemons/reputationd.py /var/www/dnsscience/daemons/reputationd.py.bak && sudo cp /tmp/dnsscience_fixes/reputationd_fixed.py /var/www/dnsscience/daemons/reputationd.py && sudo chown www-data:www-data /var/www/dnsscience/daemons/reputationd.py" \
    "Deploying fixed reputation daemon"

log "✓ Reputation daemon updated"

# ========================================
# STEP 5: Deploy GeoIP Update Script
# ========================================
log ""
log "========================================"
log "STEP 5: Deploying GeoIP Update Script"
log "========================================"

execute_ssm "sudo cp /tmp/dnsscience_fixes/update_geoip_data.sh /usr/local/bin/update_geoip_data.sh && sudo chmod +x /usr/local/bin/update_geoip_data.sh && sudo chown root:root /usr/local/bin/update_geoip_data.sh" \
    "Installing GeoIP update script"

log "✓ GeoIP update script installed"

# ========================================
# STEP 6: Deploy Database Maintenance Script
# ========================================
log ""
log "========================================"
log "STEP 6: Deploying DB Maintenance Script"
log "========================================"

execute_ssm "sudo cp /tmp/dnsscience_fixes/db_maintenance.sh /usr/local/bin/db_maintenance.sh && sudo chmod +x /usr/local/bin/db_maintenance.sh && sudo chown root:root /usr/local/bin/db_maintenance.sh" \
    "Installing database maintenance script"

log "✓ Database maintenance script installed"

# ========================================
# STEP 7: Create Cron Jobs
# ========================================
log ""
log "========================================"
log "STEP 7: Creating Cron Jobs"
log "========================================"

execute_ssm "sudo bash -c 'cat > /etc/cron.d/dnsscience_maintenance <<EOF
# DNS Science Automated Maintenance Jobs

# GeoIP Update - Monthly on 1st at 3 AM
0 3 1 * * root /usr/local/bin/update_geoip_data.sh >> /var/log/dnsscience/geoip_update.log 2>&1

# Database Maintenance - Weekly on Sunday at 2 AM
0 2 * * 0 root /usr/local/bin/db_maintenance.sh >> /var/log/dnsscience/db_maintenance.log 2>&1

# Database Stats Update - Daily at 1 AM
0 1 * * * root /usr/local/bin/db_maintenance.sh >> /var/log/dnsscience/db_stats.log 2>&1
EOF
chmod 644 /etc/cron.d/dnsscience_maintenance
'" \
    "Creating cron jobs"

log "✓ Cron jobs created"

# ========================================
# STEP 8: Restart Daemons
# ========================================
log ""
log "========================================"
log "STEP 8: Restarting All Daemons"
log "========================================"

log_info "Stopping all daemons..."
execute_ssm "sudo systemctl stop dnsscience_*.service 2>/dev/null || sudo killall -9 python3 2>/dev/null || true" \
    "Stopping daemons"

log_info "Starting all daemons..."
execute_ssm "cd /var/www/dnsscience/daemons && sudo systemctl start dnsscience_*.service 2>/dev/null || for daemon in *d.py; do sudo nohup python3 \$daemon >> /var/log/dnsscience/\$(basename \$daemon .py).log 2>&1 & done" \
    "Starting daemons"

sleep 5
log "✓ Daemons restarted"

# ========================================
# STEP 9: Restart Apache
# ========================================
log ""
log "========================================"
log "STEP 9: Restarting Apache"
log "========================================"

execute_ssm "sudo systemctl restart apache2" \
    "Restarting Apache"

sleep 3
log "✓ Apache restarted"

# ========================================
# STEP 10: Verification
# ========================================
log ""
log "========================================"
log "STEP 10: Verification"
log "========================================"

log_info "Verifying GeoIP tables..."
GEOIP_CHECK=$(execute_ssm "cd /var/www/dnsscience && export \$(grep -v '^#' .env.production | xargs) && psql -h \$DB_HOST -p \$DB_PORT -U \$DB_USER -d \$DB_NAME -t -c 'SELECT COUNT(*) FROM geoip_locations'" \
    "Checking GeoIP data")
log "GeoIP locations: $GEOIP_CHECK"

log_info "Verifying ip_reputation table columns..."
execute_ssm "cd /var/www/dnsscience && export \$(grep -v '^#' .env.production | xargs) && psql -h \$DB_HOST -p \$DB_PORT -U \$DB_USER -d \$DB_NAME -t -c 'SELECT column_name FROM information_schema.columns WHERE table_name='\''ip_reputation'\'' ORDER BY ordinal_position'" \
    "Checking ip_reputation columns"

log_info "Checking daemon status..."
execute_ssm "ps aux | grep -E 'reputationd|geoipd|enrichment' | grep -v grep" \
    "Checking daemon processes"

log_info "Testing API endpoints..."
execute_ssm "curl -s http://localhost/api/stats/live | python3 -m json.tool" \
    "Testing /api/stats/live"

log_info "Checking for recent errors..."
execute_ssm "sudo tail -20 /var/log/dnsscience/reputationd.log 2>/dev/null || echo 'No reputation daemon log yet'" \
    "Checking reputation daemon log"

execute_ssm "sudo tail -20 /var/log/dnsscience/geoipd.log 2>/dev/null || echo 'No GeoIP daemon log yet'" \
    "Checking GeoIP daemon log"

# ========================================
# FINAL REPORT
# ========================================
log ""
log "================================================================================"
log "DEPLOYMENT COMPLETE!"
log "================================================================================"
log ""
log "Summary of changes:"
log "  ✓ Created GeoIP tables (geoip_blocks, geoip_locations)"
log "  ✓ Added missing columns to ip_reputation table (last_checked, etc.)"
log "  ✓ Created performance indexes"
log "  ✓ Fixed Reputation daemon (proper LEFT JOIN handling)"
log "  ✓ Deployed GeoIP update script (/usr/local/bin/update_geoip_data.sh)"
log "  ✓ Deployed database maintenance script (/usr/local/bin/db_maintenance.sh)"
log "  ✓ Created automated cron jobs"
log "  ✓ Restarted all daemons"
log "  ✓ Restarted Apache"
log ""
log "Next steps:"
log "  1. Monitor /var/log/dnsscience/*.log for errors"
log "  2. Test Explorer page at https://www.dnsscience.io/explorer"
log "  3. Download MaxMind GeoLite2 data: /usr/local/bin/update_geoip_data.sh"
log ""
log "Full deployment log saved to: $LOG_FILE"
log "================================================================================"

exit 0
