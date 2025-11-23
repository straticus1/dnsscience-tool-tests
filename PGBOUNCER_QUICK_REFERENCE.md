# PgBouncer Quick Reference - DNS Science Production

**Instance:** i-09a4c4b10763e3d39
**Installed:** November 15, 2025
**Version:** PgBouncer 1.16.1

---

## Quick Status Check

```bash
# Check if PgBouncer is running
sudo systemctl status pgbouncer

# Quick pool statistics
/usr/local/bin/pgbouncer-monitor

# Or manually:
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h 127.0.0.1 -p 6432 -U dnsscience -d pgbouncer -c 'SHOW POOLS;'
```

---

## Connection Information

| Component | Host | Port | Notes |
|-----------|------|------|-------|
| **PgBouncer** | 127.0.0.1 | 6432 | Localhost only |
| **RDS (Direct)** | dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com | 5432 | Fallback |
| **Admin Interface** | 127.0.0.1 | 6432 | Database: pgbouncer |

---

## Common Operations

### Restart PgBouncer
```bash
sudo systemctl restart pgbouncer
```

### View Logs
```bash
sudo tail -f /var/log/pgbouncer/pgbouncer.log
sudo journalctl -u pgbouncer -f
```

### Reload Configuration (No Downtime)
```bash
sudo systemctl reload pgbouncer
# Or send HUP signal
sudo pkill -HUP pgbouncer
```

### Check Pool Statistics
```bash
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h 127.0.0.1 -p 6432 -U dnsscience -d pgbouncer <<EOF
SHOW POOLS;
SHOW CLIENTS;
SHOW SERVERS;
SHOW STATS;
SHOW CONFIG;
EOF
```

### Pause/Resume Connections
```bash
# Pause all connections (for maintenance)
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h 127.0.0.1 -p 6432 -U dnsscience -d pgbouncer -c 'PAUSE dnsscience;'

# Resume connections
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h 127.0.0.1 -p 6432 -U dnsscience -d pgbouncer -c 'RESUME dnsscience;'
```

---

## Health Checks

### Is PgBouncer Healthy?
```bash
# 1. Service is running
sudo systemctl is-active pgbouncer
# Expected: active

# 2. Listening on port
sudo netstat -tlnp | grep 6432
# Expected: 127.0.0.1:6432

# 3. Can connect
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h 127.0.0.1 -p 6432 -U dnsscience -d dnsscience -c 'SELECT 1;'
# Expected: Row returned

# 4. No waiting clients
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h 127.0.0.1 -p 6432 -U dnsscience -d pgbouncer -t -c 'SHOW POOLS;' | grep dnsscience | awk '{print $4}'
# Expected: 0
```

---

## Performance Metrics

### Key Metrics to Monitor

| Metric | Command | Healthy Value |
|--------|---------|---------------|
| **Waiting Clients** | `SHOW POOLS` → cl_waiting | 0 |
| **Active Clients** | `SHOW POOLS` → cl_active | < 500 |
| **Active Servers** | `SHOW POOLS` → sv_active | < 50 |
| **Max Wait Time** | `SHOW POOLS` → maxwait | 0 |
| **Avg Query Time** | `SHOW STATS` → avg_query_time | < 100ms |

### Sample Output
```
  database  | cl_active | cl_waiting | sv_active | sv_idle | maxwait |  pool_mode
------------+-----------+------------+-----------+---------+---------+-------------
 dnsscience |         8 |          0 |         6 |       1 |       0 | transaction

✅ Healthy: 0 waiting, low active count, no maxwait
```

---

## Troubleshooting

### Problem: Daemons Can't Connect

**Symptoms:**
- Daemon logs show connection errors
- Application errors about database

**Check:**
```bash
# 1. Is PgBouncer running?
sudo systemctl status pgbouncer

# 2. Can you connect manually?
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h 127.0.0.1 -p 6432 -U dnsscience -d dnsscience -c 'SELECT 1;'

# 3. Check PgBouncer logs
sudo tail -50 /var/log/pgbouncer/pgbouncer.log
```

**Fix:**
```bash
# Restart PgBouncer
sudo systemctl restart pgbouncer

# If that fails, daemons will automatically fall back to direct RDS
```

---

### Problem: High Connection Wait Times

**Symptoms:**
- `cl_waiting > 0` in SHOW POOLS
- `maxwait > 5` seconds

**Check:**
```bash
# How many clients are waiting?
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h 127.0.0.1 -p 6432 -U dnsscience -d pgbouncer -c 'SHOW POOLS;'
```

**Fix:**
```bash
# Edit config to increase pool size
sudo nano /etc/pgbouncer/pgbouncer.ini

# Change:
default_pool_size = 35  # From 25
reserve_pool_size = 15  # From 10

# Reload config
sudo systemctl reload pgbouncer
```

---

### Problem: Too Many RDS Connections

**Symptoms:**
- RDS connection count approaching limit
- `sv_active + sv_idle > 45` in SHOW POOLS

**Check:**
```bash
# Check RDS connection count
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h 127.0.0.1 -p 6432 -U dnsscience -d dnsscience -c \
"SELECT count(*) FROM pg_stat_activity WHERE datname = 'dnsscience';"
```

**Fix:**
```bash
# Reduce pool size in config
sudo nano /etc/pgbouncer/pgbouncer.ini

# Change:
default_pool_size = 20  # From 25
max_db_connections = 40  # From 50

# Reload config
sudo systemctl reload pgbouncer
```

---

### Problem: PgBouncer Won't Start

**Check:**
```bash
# View startup errors
sudo journalctl -u pgbouncer -n 50

# Common issues:
# 1. Config file syntax error
sudo pgbouncer -v /etc/pgbouncer/pgbouncer.ini

# 2. Port already in use
sudo netstat -tlnp | grep 6432

# 3. Permission issues
ls -la /etc/pgbouncer/
ls -la /var/log/pgbouncer/
ls -la /var/run/pgbouncer/
```

**Fix:**
```bash
# Fix permissions
sudo chown -R postgres:postgres /var/log/pgbouncer /var/run/pgbouncer
sudo chmod 600 /etc/pgbouncer/userlist.txt

# Kill any stuck processes
sudo pkill -9 pgbouncer

# Start fresh
sudo systemctl start pgbouncer
```

---

## Configuration Files

### Main Config: /etc/pgbouncer/pgbouncer.ini
```bash
sudo nano /etc/pgbouncer/pgbouncer.ini
# After changes: sudo systemctl reload pgbouncer
```

### Authentication: /etc/pgbouncer/userlist.txt
```bash
sudo nano /etc/pgbouncer/userlist.txt
# After changes: sudo systemctl reload pgbouncer
# Must be: chmod 600, owned by postgres:postgres
```

### Environment: /var/www/dnsscience/.env
```bash
sudo nano /var/www/dnsscience/.env
# After changes: sudo systemctl restart apache2
```

---

## Emergency Procedures

### Emergency: Disable PgBouncer (Fallback to Direct RDS)

```bash
# 1. Stop PgBouncer
sudo systemctl stop pgbouncer

# 2. Restore direct RDS configuration
sudo cp /var/www/dnsscience/.env.backup-pgbouncer /var/www/dnsscience/.env

# 3. Restart web server
sudo systemctl restart apache2

# 4. Restart daemons (they auto-fallback)
# No action needed - daemons automatically detect PgBouncer down

# 5. Verify direct connections
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com -p 5432 \
-U dnsscience -d dnsscience -c 'SELECT count(*) FROM domains LIMIT 1;'
```

### Re-enable PgBouncer

```bash
# 1. Start PgBouncer
sudo systemctl start pgbouncer

# 2. Verify it's working
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h 127.0.0.1 -p 6432 -U dnsscience -d dnsscience -c 'SELECT 1;'

# 3. Restore PgBouncer configuration
sudo nano /var/www/dnsscience/.env
# Set: DB_HOST=127.0.0.1 and DB_PORT=6432

# 4. Restart web server
sudo systemctl restart apache2

# 5. Monitor for issues
/usr/local/bin/pgbouncer-monitor
```

---

## Performance Tuning

### Current Configuration (Optimal for 16 daemons)
```ini
max_client_conn = 500        # Max clients PgBouncer will accept
default_pool_size = 25       # Connections per database to RDS
reserve_pool_size = 10       # Extra connections for spikes
max_db_connections = 50      # Hard limit to RDS
pool_mode = transaction      # Best for our workload
```

### When to Adjust

| Scenario | Adjustment |
|----------|------------|
| **More daemons (20-30)** | Increase `max_client_conn = 750` |
| **High wait times** | Increase `default_pool_size = 35` |
| **RDS connection limit hit** | Upgrade RDS instance or decrease `max_db_connections` |
| **Long transactions** | Consider `pool_mode = session` (not recommended) |

---

## Monitoring Integration

### CloudWatch Metrics (To Be Configured)
- PgBouncer service uptime
- Client waiting count
- Server connection count
- Query latency

### Sample CloudWatch Agent Config
```json
{
  "metrics": {
    "namespace": "DNSScience/PgBouncer",
    "metrics_collected": {
      "procstat": [
        {
          "pattern": "pgbouncer",
          "measurement": [
            "cpu_usage",
            "memory_rss"
          ]
        }
      ]
    }
  }
}
```

---

## Key Files and Locations

| File | Location | Purpose |
|------|----------|---------|
| **Config** | `/etc/pgbouncer/pgbouncer.ini` | Main configuration |
| **Auth** | `/etc/pgbouncer/userlist.txt` | User credentials |
| **Log** | `/var/log/pgbouncer/pgbouncer.log` | PgBouncer logs |
| **PID** | `/var/run/pgbouncer/pgbouncer.pid` | Process ID |
| **Service** | `/lib/systemd/system/pgbouncer.service` | Systemd service |
| **Override** | `/etc/systemd/system/pgbouncer.service.d/override.conf` | Custom service config |
| **Monitor** | `/usr/local/bin/pgbouncer-monitor` | Quick monitoring script |
| **Backup** | `/var/www/dnsscience/.env.backup-pgbouncer` | Original .env backup |

---

## Support Resources

- **Documentation:** `/Users/ryan/development/dnsscience-tool-tests/PGBOUNCER_DEPLOYMENT_COMPLETE.md`
- **Official Docs:** https://www.pgbouncer.org/
- **FAQ:** https://www.pgbouncer.org/faq.html
- **Config Reference:** https://www.pgbouncer.org/config.html

---

## Quick Commands Summary

```bash
# Status
sudo systemctl status pgbouncer
/usr/local/bin/pgbouncer-monitor

# Restart
sudo systemctl restart pgbouncer

# Logs
sudo tail -f /var/log/pgbouncer/pgbouncer.log

# Stats
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h 127.0.0.1 -p 6432 -U dnsscience -d pgbouncer -c 'SHOW POOLS; SHOW STATS;'

# Emergency stop
sudo systemctl stop pgbouncer

# Test connection
PGPASSWORD='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK' \
psql -h 127.0.0.1 -p 6432 -U dnsscience -d dnsscience -c 'SELECT current_database();'
```

---

**Last Updated:** November 15, 2025
**Maintained By:** DNS Science Operations
