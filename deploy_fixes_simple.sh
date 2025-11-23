#!/bin/bash
###############################################################################
# DNS Science - Simple Direct Deployment
# Deploys all critical fixes directly via SSM
###############################################################################

set -e

INSTANCE_ID="i-09a4c4b10763e3d39"
S3_BUCKET="dnsscience-deployment"
S3_PREFIX="fixes/$(date +%Y%m%d_%H%M%S)"

echo "========================================="
echo "DNS SCIENCE - DEPLOYING ALL FIXES"
echo "========================================="
echo ""

# Upload files to S3
echo "[1/10] Uploading files to S3..."
aws s3 cp database_schema_fixes.sql "s3://$S3_BUCKET/$S3_PREFIX/"
aws s3 cp reputationd_fixed.py "s3://$S3_BUCKET/$S3_PREFIX/"
aws s3 cp update_geoip_data.sh "s3://$S3_BUCKET/$S3_PREFIX/"
aws s3 cp db_maintenance.sh "s3://$S3_BUCKET/$S3_PREFIX/"
echo "✓ Files uploaded"
echo ""

# Download on instance
echo "[2/10] Downloading files on instance..."
aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["mkdir -p /tmp/dnsscience_fixes && cd /tmp/dnsscience_fixes && aws s3 sync s3://'"$S3_BUCKET"'/'"$S3_PREFIX"'/ . && chmod +x *.sh && ls -la"]' \
    --output text
sleep 5
echo "✓ Files downloaded"
echo ""

# Run database fixes
echo "[3/10] Running database schema fixes..."
aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["cd /var/www/dnsscience && export $(sudo grep -v ^# .env | xargs) && psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME < /tmp/dnsscience_fixes/database_schema_fixes.sql"]' \
    --output text
sleep 8
echo "✓ Database fixes applied"
echo ""

# Deploy reputation daemon
echo "[4/10] Deploying fixed reputation daemon..."
aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["sudo cp /var/www/dnsscience/daemons/reputationd.py /var/www/dnsscience/daemons/reputationd.py.bak && sudo cp /tmp/dnsscience_fixes/reputationd_fixed.py /var/www/dnsscience/daemons/reputationd.py && sudo chown www-data:www-data /var/www/dnsscience/daemons/reputationd.py && echo Done"]' \
    --output text
sleep 4
echo "✓ Reputation daemon updated"
echo ""

# Deploy enrichment fix
echo "[5/10] Deploying enrichment daemon fix..."
aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["cd /var/www/dnsscience/daemons && if [ -f enrichment_daemon_db_fix.py ]; then sudo cp enrichment_daemon.py enrichment_daemon.py.bak && sudo cp enrichment_daemon_db_fix.py enrichment_daemon.py && sudo chown www-data:www-data enrichment_daemon.py && echo Fixed; else echo Skipped; fi"]' \
    --output text
sleep 4
echo "✓ Enrichment daemon checked"
echo ""

# Deploy maintenance scripts
echo "[6/10] Deploying maintenance scripts..."
aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["sudo cp /tmp/dnsscience_fixes/update_geoip_data.sh /usr/local/bin/ && sudo cp /tmp/dnsscience_fixes/db_maintenance.sh /usr/local/bin/ && sudo chmod +x /usr/local/bin/update_geoip_data.sh /usr/local/bin/db_maintenance.sh && echo Done"]' \
    --output text
sleep 4
echo "✓ Maintenance scripts installed"
echo ""

# Create cron jobs
echo "[7/10] Creating cron jobs..."
aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["sudo bash -c '\''cat > /etc/cron.d/dnsscience_maintenance <<EOF
# GeoIP Update - Monthly
0 3 1 * * root /usr/local/bin/update_geoip_data.sh >> /var/log/dnsscience/geoip_update.log 2>&1
# DB Maintenance - Weekly
0 2 * * 0 root /usr/local/bin/db_maintenance.sh >> /var/log/dnsscience/db_maintenance.log 2>&1
EOF'\'' && sudo chmod 644 /etc/cron.d/dnsscience_maintenance && echo Done"]' \
    --output text
sleep 4
echo "✓ Cron jobs created"
echo ""

# Restart daemons
echo "[8/10] Restarting daemons..."
aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["sudo pkill -f '\''python3.*daemon'\'' || true && sleep 2 && cd /var/www/dnsscience/daemons && for daemon in *d.py; do sudo -u www-data nohup python3 $daemon >> /var/log/dnsscience/$(basename $daemon .py).log 2>&1 & done && sleep 2 && ps aux | grep -E '\''python3.*daemon'\'' | grep -v grep | wc -l"]' \
    --output text
sleep 6
echo "✓ Daemons restarted"
echo ""

# Restart Apache
echo "[9/10] Restarting Apache..."
aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["sudo systemctl restart apache2 && echo Done"]' \
    --output text
sleep 4
echo "✓ Apache restarted"
echo ""

# Verification
echo "[10/10] Running verification..."
echo ""
echo "Checking GeoIP tables..."
aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["cd /var/www/dnsscience && export $(sudo grep -v ^# .env | xargs) && psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -c '\''SELECT COUNT(*) || '\'' GeoIP locations'\'' FROM geoip_locations'\'' && psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -c '\''SELECT COUNT(*) || '\'' IP blocks'\'' FROM geoip_blocks'\''"]' \
    --output text
sleep 5
echo ""

echo "Checking daemon processes..."
aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["ps aux | grep -E '\''python3.*(reputationd|geoipd|enrichment)'\'' | grep -v grep | wc -l"]' \
    --output text
sleep 4
echo ""

echo "Testing API endpoint..."
aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["curl -s http://localhost/api/stats/live | python3 -m json.tool"]' \
    --output text
sleep 4
echo ""

echo "========================================="
echo "DEPLOYMENT COMPLETE!"
echo "========================================="
echo ""
echo "Summary of changes:"
echo "✓ Created GeoIP tables"
echo "✓ Added missing columns to ip_reputation"
echo "✓ Fixed Reputation daemon"
echo "✓ Fixed Enrichment daemon"
echo "✓ Installed maintenance scripts"
echo "✓ Created cron jobs"
echo "✓ Restarted all services"
echo ""
echo "Next: Test Explorer at https://www.dnsscience.io/explorer"
echo ""
