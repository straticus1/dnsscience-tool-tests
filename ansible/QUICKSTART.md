# DNS Science Ansible - Quick Start Guide

## 🚀 Deploy in 5 Minutes

### 1. Prerequisites Check
```bash
# Install requirements
pip install ansible boto3 awscli

# Configure AWS
aws configure

# Verify connection to EC2 instance
aws ssm describe-instance-information --filters "Key=InstanceIds,Values=i-0609352c5884a48ee"
```

### 2. First Deployment
```bash
# Navigate to Ansible directory
cd /Users/ryan/development/dnsscience-tool-tests/ansible

# Run deployment
./deploy.sh
```

## 📋 Common Tasks

### Deploy Specific Components
```bash
# Deploy only templates (fast)
./deploy.sh --tags templates

# Deploy Flask application
./deploy.sh --tags flask-app

# Deploy static files
./deploy.sh --tags static-files

# Full deployment except database
./deploy.sh --skip database
```

### Testing & Validation
```bash
# Dry run - see what would change
./deploy.sh --check

# Validate current deployment
ansible-playbook -i inventory/production.yml playbooks/validate-deployment.yml

# Run smoke tests only
ansible-playbook -i inventory/production.yml playbooks/smoke-tests.yml
```

### Emergency Procedures
```bash
# Rollback to previous version
./deploy.sh --rollback

# Create manual backup
ansible-playbook -i inventory/production.yml playbooks/backup-current.yml

# Force restart services
ansible -i inventory/production.yml dnsscience_production -m systemd -a "name=httpd state=restarted"
```

## 🔧 Configuration

### Update Environment Variables
Edit `group_vars/production.yml`:
```yaml
# Database
db_host: your-rds-endpoint.amazonaws.com
db_password: your-secure-password

# API Keys
stripe_secret_key: sk_live_xxxxx
opensrs_api_key: your-opensrs-key
```

### Change Deployment Behavior
```bash
# Skip backup creation
./deploy.sh --extra "create_backup=false"

# Increase workers
./deploy.sh --extra "flask_workers=8"

# Deploy with debug mode
./deploy.sh --extra "flask_debug=true" --tags flask-app
```

## 📊 Monitoring Deployment

### Watch Logs in Real-Time
```bash
# In another terminal
tail -f logs/ansible.log

# On the server
ssh ec2-user@54.221.150.32 "sudo tail -f /var/log/dnsscience/app.log"
```

### Check Deployment Status
```bash
# View last deployment
cat logs/deployment_*.log | tail -50

# Check service health
curl http://54.221.150.32/health
```

## ❓ Troubleshooting

### Connection Issues
```bash
# Test AWS SSM connection
aws ssm start-session --target i-0609352c5884a48ee

# If SSM fails, check IAM permissions
aws iam get-role --role-name YourEC2Role
```

### Deployment Failures
```bash
# Check what failed
grep -A5 -B5 "FAILED" logs/ansible.log

# Get detailed error
./deploy.sh --verbose --tags <failed-component>

# Manual recovery
./deploy.sh --rollback
```

### Service Not Working
```bash
# Check Apache
ansible -i inventory/production.yml dnsscience_production -m shell -a "systemctl status httpd"

# Check logs
ansible -i inventory/production.yml dnsscience_production -m shell -a "tail -50 /var/log/httpd/error.log"

# Restart everything
ansible -i inventory/production.yml dnsscience_production -m shell -a "systemctl restart httpd"
```

## 📚 Key Files

| File | Purpose |
|------|---------|
| `deploy.sh` | Main deployment script |
| `deploy-dnsscience.yml` | Main playbook |
| `inventory/production.yml` | Server configuration |
| `group_vars/all.yml` | Global variables |
| `group_vars/production.yml` | Production settings |
| `logs/ansible.log` | Deployment logs |

## 🎯 Best Practices

1. **Always test first**: Use `--check` for dry runs
2. **Deploy incrementally**: Use tags for specific components
3. **Monitor logs**: Keep an eye on `/var/log/dnsscience/`
4. **Backup before major changes**: Automatic but verify
5. **Document changes**: Update this guide as needed

## 🆘 Getting Help

```bash
# Show help
./deploy.sh --help

# Check documentation
less README.md

# Validate setup
ansible-playbook -i inventory/production.yml playbooks/validate-prerequisites.yml
```

## 🚦 Deployment Checklist

- [ ] AWS credentials configured
- [ ] SSM plugin installed
- [ ] Inventory file updated
- [ ] Variables configured
- [ ] Dry run successful
- [ ] Backup verified
- [ ] Monitoring ready
- [ ] Team notified

---

**Quick Deploy Command:**
```bash
cd /Users/ryan/development/dnsscience-tool-tests/ansible && ./deploy.sh
```

**Emergency Rollback:**
```bash
./deploy.sh --rollback
```