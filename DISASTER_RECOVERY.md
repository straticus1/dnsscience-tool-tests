# DNS Science - Disaster Recovery Guide

**Last Updated:** 2025-11-15
**Version:** 2.0
**Status:** PRODUCTION-READY

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Recovery Scenarios](#recovery-scenarios)
4. [Full Site Deployment](#full-site-deployment)
5. [Database Recovery](#database-recovery)
6. [Verification](#verification)
7. [Rollback Procedures](#rollback-procedures)

---

## Overview

This guide provides step-by-step instructions for recovering the DNS Science platform in case of:
- AWS region outage
- Complete infrastructure failure
- Database corruption
- Auto-scaling group issues
- Accidental deletions

### Recovery Time Objectives (RTO)
- **Full Site Recovery**: 30-45 minutes
- **Database Only**: 15-20 minutes
- **Single Component**: 5-10 minutes

### Recovery Point Objectives (RPO)
- **Database**: Last hourly backup (max 1 hour data loss)
- **Application Code**: Current production state (zero loss)
- **User Data**: Last database backup

---

## Prerequisites

### Required Access
- AWS CLI configured with admin credentials
- SSH access to EC2 instances (optional, SSM preferred)
- Access to S3 buckets:
  - `dnsscience-deployment` - Primary deployment artifacts
  - `dnsscience-deployments` - Application files
- RDS database credentials
- GitHub repository access (optional)

### Required Tools
```bash
# Install Ansible
pip3 install ansible boto3 psycopg2-binary

# Verify AWS CLI
aws sts get-caller-identity

# Clone repository
git clone https://github.com/your-org/dnsscience-tool-tests.git
cd dnsscience-tool-tests
```

---

## Recovery Scenarios

### Scenario 1: AWS Region Outage

**Situation**: Entire us-east-1 region is unavailable

**Recovery Steps**:

1. **Launch new infrastructure in us-west-2**:
```bash
# Update region in ansible/group_vars/all/aws.yml
sed -i '' 's/us-east-1/us-west-2/g' ansible/group_vars/all/aws.yml

# Deploy using Terraform (if available)
cd superdeploy/terraform
terraform init
terraform plan -var="region=us-west-2"
terraform apply
```

2. **Restore database from snapshot**:
```bash
# Find latest snapshot
aws rds describe-db-snapshots \
  --db-instance-identifier dnsscience-db \
  --query 'DBSnapshots[0].DBSnapshotIdentifier' \
  --output text

# Restore in new region
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier dnsscience-db-west \
  --db-snapshot-identifier <snapshot-id> \
  --region us-west-2
```

3. **Deploy application**:
```bash
cd ansible
./deploy.sh --region us-west-2
```

4. **Update DNS**:
```bash
# Point www.dnsscience.io to new load balancer
# (Manual Route53 update or automated failover)
```

---

### Scenario 2: Complete Infrastructure Failure

**Situation**: All EC2 instances terminated, Auto Scaling Group broken

**Recovery Steps**:

1. **Check current state**:
```bash
# List all instances
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=dns-science-web-server" \
  --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PublicIpAddress]' \
  --output table

# Check Auto Scaling Group
aws autoscaling describe-auto-scaling-groups \
  --query 'AutoScalingGroups[?contains(AutoScalingGroupName, `dns-science`)]'
```

2. **Fix Auto Scaling Group**:
```bash
# Update Launch Template with working configuration
aws ec2 describe-launch-templates \
  --query 'LaunchTemplates[?LaunchTemplateName==`dns-science-web-server-template`]'

# Get the latest working version
LATEST_VERSION=$(aws ec2 describe-launch-template-versions \
  --launch-template-name dns-science-web-server-template \
  --query 'LaunchTemplateVersions[0].VersionNumber' \
  --output text)

# Update ASG
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name dns-science-asg \
  --launch-template LaunchTemplateName=dns-science-web-server-template,Version=$LATEST_VERSION \
  --min-size 2 \
  --max-size 10 \
  --desired-capacity 3
```

3. **Force new instance creation**:
```bash
# Set desired capacity to 0, then back to 3 to force recreation
aws autoscaling set-desired-capacity \
  --auto-scaling-group-name dns-science-asg \
  --desired-capacity 0

sleep 60

aws autoscaling set-desired-capacity \
  --auto-scaling-group-name dns-science-asg \
  --desired-capacity 3
```

4. **Verify health**:
```bash
# Wait for instances to be healthy
watch -n 5 'aws autoscaling describe-auto-scaling-groups \
  --query "AutoScalingGroups[?AutoScalingGroupName==\`dns-science-asg\`].Instances[*].[InstanceId,HealthStatus]" \
  --output table'
```

---

### Scenario 3: Database Corruption

**Situation**: Database tables corrupted or schema broken

**Recovery Steps**:

1. **Stop application servers** (prevent further corruption):
```bash
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name dns-science-asg \
  --min-size 0 \
  --max-size 0 \
  --desired-capacity 0
```

2. **Take current snapshot** (for forensics):
```bash
aws rds create-db-snapshot \
  --db-instance-identifier dnsscience-db \
  --db-snapshot-identifier dnsscience-db-corrupt-$(date +%Y%m%d-%H%M%S)
```

3. **Restore from last good backup**:
```bash
# Find last good backup
aws rds describe-db-snapshots \
  --db-instance-identifier dnsscience-db \
  --query 'DBSnapshots[*].[DBSnapshotIdentifier,SnapshotCreateTime]' \
  --output table

# Restore (this creates new instance)
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier dnsscience-db-restored \
  --db-snapshot-identifier <good-snapshot-id>

# Wait for restoration
aws rds wait db-instance-available \
  --db-instance-identifier dnsscience-db-restored
```

4. **Apply recent migrations**:
```bash
# Download migrations
cd migrations

# Connect to restored database
export PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK'
RESTORED_ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier dnsscience-db-restored \
  --query 'DBInstances[0].Endpoint.Address' \
  --output text)

# Apply migrations
for migration in *.sql; do
  echo "Applying $migration..."
  psql -h $RESTORED_ENDPOINT -U dnsscience -d dnsscience < $migration
done
```

5. **Point application to restored database**:
```bash
# Update launch template with new endpoint
# Then recreate instances
```

---

## Full Site Deployment

### Using Ansible (Recommended)

1. **Sync production configuration**:
```bash
./sync_production_to_ansible.sh
```

2. **Configure deployment**:
```bash
cd ansible

# Edit inventory
vim inventory/production/hosts

# Edit variables
vim group_vars/all/database.yml
vim group_vars/all/app.yml
```

3. **Run deployment**:
```bash
# Dry run first
./deploy.sh --check

# Full deployment
./deploy.sh

# Deploy specific role only
ansible-playbook deploy-dnsscience.yml --tags=flask-app
```

### Manual Deployment (Legacy)

If Ansible is unavailable:

1. **Launch EC2 instance**:
```bash
# Use AWS Console or CLI
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.medium \
  --key-name dnsscience-prod \
  --security-group-ids sg-xxxxx \
  --subnet-id subnet-xxxxx \
  --iam-instance-profile Name=DNSScienceInstanceProfile \
  --user-data file://userdata.sh
```

2. **Download application code**:
```bash
INSTANCE_ID="i-xxxxx"

aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=[
"cd /var/www",
"sudo mkdir -p dnsscience",
"sudo aws s3 sync s3://dnsscience-deployments/app-files/ /var/www/dnsscience/",
"sudo aws s3 sync s3://dnsscience-deployment/templates/ /var/www/dnsscience/templates/",
"sudo aws s3 sync s3://dnsscience-deployment/static/ /var/www/dnsscience/static/",
"sudo chown -R www-data:www-data /var/www/dnsscience",
"sudo chmod -R 755 /var/www/dnsscience"
]'
```

3. **Install dependencies**:
```bash
aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=[
"sudo apt-get update",
"sudo apt-get install -y python3-pip apache2 libapache2-mod-wsgi-py3 postgresql-client",
"cd /var/www/dnsscience",
"sudo pip3 install -r requirements.txt",
"sudo systemctl restart apache2"
]'
```

---

## Database Recovery

### Quick Schema Restore

If you only need to restore schema (not data):

```bash
# Download schema files
aws s3 sync s3://dnsscience-deployment/schema/ ./schema/

# Apply schema
export PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK'
psql -h dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com \
  -U dnsscience -d dnsscience < schema/full_schema.sql

# Apply all migrations
cd migrations
for f in *.sql; do
  echo "Applying $f..."
  psql -h dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com \
    -U dnsscience -d dnsscience < "$f"
done
```

### Important Migrations

#### Migration 017: Corporate User Support (Latest)
```bash
psql -h dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com \
  -U dnsscience -d dnsscience < migrations/017_corporate_user_support.sql
```

This adds:
- `full_name`, `company`, `job_title`, `department` columns
- `industry`, `company_size`, `country` for enterprise users
- `email_verified`, `phone` columns
- Corporate user view for reporting

---

## Verification

### Health Checks

1. **Instance Health**:
```bash
# Check instance status
INSTANCE_ID="i-xxxxx"
aws ec2 describe-instance-status --instance-ids $INSTANCE_ID

# Check via SSM
aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=[
"systemctl status apache2",
"curl -s http://localhost/health",
"ps aux | grep python"
]'
```

2. **Application Endpoints**:
```bash
# Test all critical endpoints
for endpoint in / /health /tools /explorer /visualtrace /api/auth/login; do
  echo -n "Testing $endpoint... "
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://www.dnsscience.io$endpoint")
  if [ "$status" = "200" ] || [ "$status" = "302" ]; then
    echo "✓ OK ($status)"
  else
    echo "✗ FAILED ($status)"
  fi
done
```

3. **Database Connectivity**:
```bash
export PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK'
psql -h dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com \
  -U dnsscience -d dnsscience \
  -c "SELECT COUNT(*) FROM users;"
```

4. **Load Balancer Health**:
```bash
# Check target group health
aws elbv2 describe-target-health \
  --target-group-arn <target-group-arn> \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State]' \
  --output table
```

---

## Rollback Procedures

### Rolling Back Code Deployment

1. **Identify previous version**:
```bash
# List recent S3 deployments
aws s3 ls s3://dnsscience-deployment/deployments/ | tail -20

# Or check instance backups
INSTANCE_ID="i-xxxxx"
aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["ls -lah /var/www/dnsscience/app.py.backup.*"]'
```

2. **Restore previous version**:
```bash
aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=[
"cd /var/www/dnsscience",
"sudo cp app.py app.py.failed",
"sudo cp app.py.backup.20251115_110000 app.py",
"sudo systemctl restart apache2"
]'
```

### Rolling Back Database Changes

**WARNING**: Database rollbacks can cause data loss!

```bash
# If migration failed, rollback transaction automatically happens
# If migration succeeded but caused issues:

# 1. Check schema_migrations table
psql -c "SELECT * FROM schema_migrations ORDER BY applied_at DESC LIMIT 5;"

# 2. Manually revert (example for migration 017)
psql << 'SQL'
BEGIN;
-- Remove columns added in migration 017
ALTER TABLE users DROP COLUMN IF EXISTS job_title;
ALTER TABLE users DROP COLUMN IF EXISTS department;
ALTER TABLE users DROP COLUMN IF EXISTS industry;
-- etc...
DELETE FROM schema_migrations WHERE version = '017';
COMMIT;
SQL
```

---

## Emergency Contacts

- **Primary**: Ryan (Developer)
- **AWS Support**: Premium Support Plan
- **Database**: RDS PostgreSQL 13.x
- **CDN**: CloudFront Distribution

## Backup Locations

1. **S3 Buckets**:
   - `s3://dnsscience-deployment/` - Templates, static files
   - `s3://dnsscience-deployments/` - Application code
   - `s3://dnsscience-backups/` - Database dumps (if configured)

2. **RDS Automated Backups**:
   - Retention: 7 days
   - Backup window: 03:00-04:00 UTC
   - Latest snapshot age: Check with `aws rds describe-db-snapshots`

3. **Local Repository**:
   - `/Users/ryan/development/dnsscience-tool-tests/`
   - `ansible/` directory contains complete build system

---

## Post-Recovery Checklist

- [ ] All health checks passing
- [ ] Load balancer showing healthy targets
- [ ] Database queries succeeding
- [ ] User login/signup working
- [ ] Domain scanning functional
- [ ] Email sending operational
- [ ] Stripe payments working (if applicable)
- [ ] Monitoring alerts configured
- [ ] SSL certificates valid
- [ ] DNS propagated correctly
- [ ] Backups resumed

---

**Last Verified:** 2025-11-15
**Next Review:** 2025-12-15
