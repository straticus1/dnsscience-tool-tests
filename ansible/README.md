# DNS Science Ansible Deployment System

## Overview

Production-grade Ansible automation for deploying and managing the DNS Science platform. This system provides idempotent, repeatable deployments with comprehensive error handling, rollback capabilities, and AWS SSM integration.

## Features

- ✅ **Idempotent Operations** - Safe to run multiple times
- ✅ **AWS SSM Integration** - No SSH keys required
- ✅ **Comprehensive Testing** - Pre-flight checks and smoke tests
- ✅ **Rollback Support** - Quick recovery from failed deployments
- ✅ **Modular Design** - Organized into reusable roles
- ✅ **Full Automation** - Complete deployment with single command
- ✅ **Health Monitoring** - Built-in health checks and validation
- ✅ **Backup & Recovery** - Automatic backups before changes

## Quick Start

### Prerequisites

1. **Install Ansible and AWS CLI:**
```bash
pip install -r requirements.txt
ansible-galaxy collection install -r requirements.yml
```

2. **Configure AWS Credentials:**
```bash
aws configure
# Or use IAM role if running from EC2
```

3. **Install Session Manager Plugin:**
```bash
# macOS
brew install --cask session-manager-plugin

# Linux
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/linux_64bit/session-manager-plugin.rpm" -o "session-manager-plugin.rpm"
sudo yum install -y session-manager-plugin.rpm
```

### Basic Deployment

```bash
# Standard deployment
./deploy.sh

# Dry run (check mode)
./deploy.sh --check

# Verbose output
./deploy.sh --verbose
```

## Directory Structure

```
ansible/
├── deploy-dnsscience.yml    # Main playbook
├── deploy.sh                 # Deployment script
├── requirements.txt          # Python dependencies
├── requirements.yml          # Ansible collections
├── inventory/
│   └── production.yml        # Production inventory
├── group_vars/
│   ├── all.yml              # Global variables
│   └── production.yml       # Production-specific vars
├── roles/
│   ├── python-deps/         # Python dependencies
│   ├── database/            # Database setup
│   ├── flask-app/           # Flask application
│   ├── templates/           # HTML templates
│   ├── static-files/        # Static assets
│   ├── apache/              # Apache configuration
│   └── health-check/        # Health monitoring
└── playbooks/
    ├── validate-prerequisites.yml
    ├── smoke-tests.yml
    └── rollback.yml
```

## Deployment Options

### Deploy Specific Components

```bash
# Deploy only templates
./deploy.sh --tags templates

# Deploy Flask app and Apache
./deploy.sh --tags flask,apache

# Skip database migrations
./deploy.sh --skip database
```

### Advanced Options

```bash
# Deploy with custom variables
./deploy.sh --extra "flask_workers=8 enable_debug_mode=false"

# Use alternate inventory
./deploy.sh --inventory inventory/staging.yml

# Rollback to previous version
./deploy.sh --rollback
```

## Configuration

### Key Variables (group_vars/all.yml)

| Variable | Description | Default |
|----------|-------------|---------|
| `app_name` | Application name | dnsscience |
| `flask_workers` | Number of Flask workers | 4 |
| `db_pool_size` | Database connection pool size | 20 |
| `enable_ssl` | Enable HTTPS | true |
| `create_backup` | Backup before deployment | true |

### Environment-Specific Settings

Edit `group_vars/production.yml` for production-specific configurations:
- Database credentials
- API keys
- SSL certificates
- Performance settings

## Roles Documentation

### python-deps
Installs Python packages and creates virtual environment.
- Creates venv at `/var/www/dnsscience/venv`
- Installs from requirements.txt
- Validates package imports

### database
Manages database setup and migrations.
- Runs SQL migrations in order
- Creates backup before changes
- Tracks migration history

### flask-app
Deploys Flask application and WSGI configuration.
- Copies app.py and related files
- Configures environment variables
- Sets up WSGI for Apache

### templates
Deploys HTML/PHP templates.
- Syncs from local or S3
- Fixes paths and permissions
- Validates PHP syntax

### static-files
Manages CSS, JS, and images.
- Optimizes images
- Sets cache headers
- Configures CDN fallbacks

### apache
Configures Apache web server.
- Sets up virtual hosts
- Configures SSL
- Manages modules and performance

### health-check
Sets up monitoring and health checks.
- Creates health endpoints
- Configures CloudWatch alarms
- Sets up log aggregation

## Testing

### Pre-Deployment Validation
```bash
# Check inventory
ansible-inventory -i inventory/production.yml --list

# Validate playbook syntax
ansible-playbook deploy-dnsscience.yml --syntax-check

# Run in check mode
./deploy.sh --check
```

### Post-Deployment Testing
The system automatically runs smoke tests including:
- Home page accessibility
- Health endpoint status
- API functionality
- Static file serving
- Database connectivity

## Monitoring

### Health Checks
- Endpoint: `/health`
- Frequency: Every 5 minutes
- Alerts: CloudWatch alarms

### Logs
- Application: `/var/log/dnsscience/app.log`
- Deployment: `/var/log/dnsscience/deployments.log`
- Apache: `/var/log/httpd/error.log`

## Troubleshooting

### Common Issues

**1. AWS SSM Connection Failed**
```bash
# Check EC2 instance has SSM permissions
aws ssm describe-instance-information

# Verify Session Manager plugin
session-manager-plugin --version
```

**2. Database Connection Error**
```bash
# Test connection
psql -h <host> -U <user> -d <database> -c "SELECT 1;"
```

**3. Apache Not Starting**
```bash
# Check configuration
httpd -t

# View error logs
sudo tail -f /var/log/httpd/error.log
```

**4. Python Import Errors**
```bash
# Activate venv and test
source /var/www/dnsscience/venv/bin/activate
python -c "import app"
```

### Recovery Procedures

**Rollback Deployment:**
```bash
./deploy.sh --rollback
```

**Manual Recovery:**
```bash
# Restore from backup
cd /var/www/dnsscience
tar xzf /var/backups/dnsscience/backup_<timestamp>.tar.gz

# Restart services
sudo systemctl restart httpd
```

## Security Considerations

- ✅ Uses AWS SSM (no SSH keys)
- ✅ Encrypted variables with Ansible Vault
- ✅ Secure file permissions
- ✅ SELinux contexts properly set
- ✅ SSL/TLS enforcement
- ✅ Security headers configured

### Using Ansible Vault

```bash
# Encrypt sensitive variables
ansible-vault encrypt group_vars/production.yml

# Create vault password file
echo "your-vault-password" > .vault_pass
chmod 600 .vault_pass
```

## Performance Optimization

### Parallel Execution
```yaml
# In ansible.cfg
[defaults]
forks = 10
pipelining = True
```

### Connection Reuse
```yaml
[ssh_connection]
control_master = auto
control_persist = 60s
```

## Maintenance

### Regular Tasks
- Review and rotate logs weekly
- Update Python packages monthly
- Test rollback procedures quarterly
- Review security patches

### Updating the System
```bash
# Update Ansible collections
ansible-galaxy collection install -r requirements.yml --force

# Update Python packages
pip install -r requirements.txt --upgrade

# Test changes in staging first
./deploy.sh --inventory inventory/staging.yml --check
```

## Contributing

1. Create feature branch
2. Test in development environment
3. Run ansible-lint
4. Submit pull request

## Support

For issues or questions:
- Check logs in `/var/log/dnsscience/`
- Review this documentation
- Contact DevOps team

## License

Copyright (c) 2024 DNS Science. All rights reserved.