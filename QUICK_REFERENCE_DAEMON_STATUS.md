# Quick Reference: Daemon Status

## Current Status (November 15, 2025 - 07:41 UTC)

### All Systems Operational ✓

```
┌─────────────────────────────────────────────────────────────┐
│                  DNS SCIENCE DAEMONS                        │
├─────────────────────────────────────────────────────────────┤
│  ✓ SSL Monitor          ACTIVE - Collecting certificates   │
│  ✓ SSL Scanner          ACTIVE - Scanning 6.5 domains/sec  │
│  ✓ Email Validator      ACTIVE - 81.6 records/minute       │
├─────────────────────────────────────────────────────────────┤
│  Total Daemons Running: 16/16                               │
│  Broken Daemons:        0/16                                │
│  Collection Status:     OPERATIONAL                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Data Collection Summary

### SSL Certificates
```
Total Collected:        1,016
Valid:                  988
Expiring Soon (< 30d):  26
Expired:                2
```

### Email Security
```
Total Records:          16,379
MX Records:             9,632 (58.8%)
SPF Configured:         8,922 (54.5%)
DMARC Configured:       5,994 (36.6%)
DKIM Configured:        4,525 (27.6%)
```

---

## Quick Commands

### Check Daemon Status
```bash
# SSH to instance
ssh ec2-user@i-09a4c4b10763e3d39

# Check all 3 fixed daemons
systemctl status ssl-monitor.service
systemctl status ssl-scanner.service
systemctl status email-validator.service

# View recent logs
journalctl -u ssl-monitor.service -n 20
journalctl -u ssl-scanner.service -n 20
journalctl -u email-validator.service -n 20
```

### Check Data Collection
```bash
# SSH to instance and run Python
cd /var/www/dnsscience
python3 -c "
import sys
sys.path.insert(0, '/var/www/dnsscience')
from config import Config
import psycopg2
conn = psycopg2.connect(host=Config.DB_HOST, port=Config.DB_PORT, database=Config.DB_NAME, user=Config.DB_USER, password=Config.DB_PASS)
cur = conn.cursor()
cur.execute('SELECT COUNT(*) FROM ssl_certificates')
print(f'SSL Certificates: {cur.fetchone()[0]}')
cur.execute('SELECT COUNT(*) FROM email_security_records')
print(f'Email Security Records: {cur.fetchone()[0]}')
conn.close()
"
```

### Restart Daemons (if needed)
```bash
sudo systemctl restart ssl-monitor.service
sudo systemctl restart ssl-scanner.service
sudo systemctl restart email-validator.service
```

---

## File Locations

### Production Files
```
/var/www/dnsscience/daemons/ssl_monitor_daemon.py
/var/www/dnsscience/daemons/ssl_scanner_daemon.py
/var/www/dnsscience/daemons/email_validator_daemon.py
```

### Service Files
```
/etc/systemd/system/ssl-monitor.service
/etc/systemd/system/ssl-scanner.service
/etc/systemd/system/email-validator.service
```

### S3 Backups
```
s3://dnsscience-deployments/daemons/ssl_monitord.py
s3://dnsscience-deployments/daemons/ssl_scanner_daemon.py
s3://dnsscience-deployments/daemons/emaild.py
```

---

## What Was Fixed

### SSL Monitor
- **Problem:** Queried `certificate_history` table (wrong table name)
- **Fix:** Changed to query `ssl_certificates` table
- **Status:** Collecting certificates without errors

### SSL Scanner
- **Problem:** Referenced `domains.ssl_expiry_date` column (doesn't exist)
- **Fix:** Removed reference, uses only `last_ssl_scan`
- **Status:** Scanning at 6.5 domains/second

### Email Validator
- **Problem:** Tried to insert `has_sender_id` columns (don't exist)
- **Fix:** Removed SenderID columns from queries
- **Status:** Collecting 81.6 records/minute

---

## Monitoring

### Health Check
All daemons should show:
- Status: `active (running)`
- No ERROR messages in logs
- Increasing record counts in database

### Expected Behavior
- **SSL Monitor:** Periodic INFO messages about database connections
- **SSL Scanner:** INFO messages about domains scanned, certificates found
- **Email Validator:** INFO messages about email security checks

### Red Flags (None currently)
- ❌ Service status shows `failed` or `inactive`
- ❌ ERROR messages in logs about schema or database
- ❌ Zero records collected after 5+ minutes

---

## Contact

**Instance:** i-09a4c4b10763e3d39
**Region:** us-east-1
**Database:** dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com

**Fixed By:** Claude (Overnight Optimization)
**Date:** November 15, 2025
**Report:** See `DAEMON_FIX_COMPLETE_REPORT.md` for full details
