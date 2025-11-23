#!/bin/bash
#
# Sync Production Configuration to Ansible Build System
# ======================================================
# This script downloads the current production configuration from:
# - Running EC2 instance
# - S3 deployment bucket
# And updates the Ansible build system for disaster recovery
#

set -e

INSTANCE_ID="i-0609352c5884a48ee"
S3_BUCKET="dnsscience-deployment"
ANSIBLE_DIR="ansible"

echo "=========================================="
echo "SYNCING PRODUCTION TO ANSIBLE BUILD"
echo "=========================================="
echo ""
echo "Instance: $INSTANCE_ID"
echo "S3 Bucket: $S3_BUCKET"
echo "Ansible Dir: $ANSIBLE_DIR"
echo ""

# 1. Download templates from S3
echo "[1/6] Downloading templates from S3..."
mkdir -p "$ANSIBLE_DIR/roles/templates/files"
aws s3 sync "s3://$S3_BUCKET/templates/" "$ANSIBLE_DIR/roles/templates/files/" --exclude "*.backup*"
echo "✓ Templates synced"
echo ""

# 2. Download static files from S3
echo "[2/6] Downloading static files from S3..."
mkdir -p "$ANSIBLE_DIR/roles/static-files/files"
aws s3 sync "s3://$S3_BUCKET/static/" "$ANSIBLE_DIR/roles/static-files/files/" --exclude "*.backup*"
echo "✓ Static files synced"
echo ""

# 3. Download Python app files from instance via SSM
echo "[3/6] Downloading Python app files from instance..."
mkdir -p "$ANSIBLE_DIR/roles/flask-app/files"

# Download app.py
CMD_ID=$(aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=[
"cd /var/www/dnsscience",
"tar czf /tmp/python_apps.tar.gz app.py auth.py database.py config.py checkers.py *.py --exclude=test_*.py --exclude=deploy_*.py 2>/dev/null || true",
"aws s3 cp /tmp/python_apps.tar.gz s3://'"$S3_BUCKET"'/ansible-sync/python_apps.tar.gz",
"echo Done"
]' \
  --query 'Command.CommandId' \
  --output text)

sleep 8
aws s3 cp "s3://$S3_BUCKET/ansible-sync/python_apps.tar.gz" /tmp/python_apps.tar.gz
cd "$ANSIBLE_DIR/roles/flask-app/files"
tar xzf /tmp/python_apps.tar.gz
cd - > /dev/null
echo "✓ Python apps synced"
echo ""

# 4. Download database migrations
echo "[4/6] Syncing database migrations..."
mkdir -p "$ANSIBLE_DIR/roles/database/files/migrations"
cp migrations/*.sql "$ANSIBLE_DIR/roles/database/files/migrations/" 2>/dev/null || true
echo "✓ Migrations synced"
echo ""

# 5. Download Apache config
echo "[5/6] Downloading Apache config..."
mkdir -p "$ANSIBLE_DIR/roles/apache/files"
CMD_ID=$(aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=[
"tar czf /tmp/apache_conf.tar.gz /etc/apache2/sites-available/*.conf /etc/apache2/apache2.conf 2>/dev/null || true",
"aws s3 cp /tmp/apache_conf.tar.gz s3://'"$S3_BUCKET"'/ansible-sync/apache_conf.tar.gz",
"echo Done"
]' \
  --query 'Command.CommandId' \
  --output text)

sleep 8
aws s3 cp "s3://$S3_BUCKET/ansible-sync/apache_conf.tar.gz" /tmp/apache_conf.tar.gz 2>/dev/null || echo "Apache config not found, skipping"
echo "✓ Apache config synced"
echo ""

# 6. Update group_vars with current database credentials
echo "[6/6] Updating Ansible variables..."
mkdir -p "$ANSIBLE_DIR/group_vars/all"
cat > "$ANSIBLE_DIR/group_vars/all/database.yml" << 'EOF'
---
# Database Configuration
db_host: "dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com"
db_name: "dnsscience"
db_user: "dnsscience"
db_password: "{{ vault_db_password }}"
db_port: 5432

# S3 Deployment Bucket
s3_deployment_bucket: "dnsscience-deployment"

# Application Settings
app_domain: "www.dnsscience.io"
app_environment: "production"
EOF

echo "✓ Variables updated"
echo ""

echo "=========================================="
echo "SYNC COMPLETE!"
echo "=========================================="
echo ""
echo "Summary:"
echo "  - Templates: $(find $ANSIBLE_DIR/roles/templates/files -type f 2>/dev/null | wc -l | tr -d ' ') files"
echo "  - Static files: $(find $ANSIBLE_DIR/roles/static-files/files -type f 2>/dev/null | wc -l | tr -d ' ') files"
echo "  - Python apps: $(find $ANSIBLE_DIR/roles/flask-app/files -name '*.py' 2>/dev/null | wc -l | tr -d ' ') files"
echo "  - Migrations: $(find $ANSIBLE_DIR/roles/database/files -name '*.sql' 2>/dev/null | wc -l | tr -d ' ') files"
echo ""
echo "The Ansible build system is now up-to-date with production!"
echo "You can deploy to a new environment with:"
echo "  cd ansible && ./deploy.sh"
echo ""
