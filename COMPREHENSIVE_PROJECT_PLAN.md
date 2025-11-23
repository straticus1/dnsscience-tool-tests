# DNS SCIENCE - COMPREHENSIVE PROJECT PLAN
**Date:** November 15, 2025 - 04:30 AM EST
**Instance:** i-09a4c4b10763e3d39 (www.dnsscience.io)
**Objective:** Fix ALL Missing Data Collection Features + Complete System Integration
**Status:** IN PROGRESS

---

## EXECUTIVE SUMMARY

This document provides a complete analysis of all identified issues, fixes applied, and remaining work required to achieve full data collection and display functionality for DNS Science.

### Current State (Before This Session)
- Email security daemon collecting: MX, SPF, DMARC, DKIM (25,411 records)
- GeoIP tables created but empty (0 records)
- Redis NOT running - homepage stuck on "Loading..."
- DANE/TLSA records: NOT being collected (no code exists)
- MTA-STS policies: NOT being collected (no code exists)
- Homepage NOT showing DKIM counts with other email security metrics

### Target State (After Completion)
- Complete email security monitoring: MX, SPF, DMARC, DKIM, DANE, TLSA, MTA-STS
- GeoIP data populated with IP geolocation
- Redis running with live statistics
- Homepage displaying all metrics with NO "Loading..." states
- All data collection automated and working

---

## CRITICAL ISSUES IDENTIFIED

### Issue 1: DANE/TLSA Records - NOT BEING COLLECTED ❌

**Problem:**
- Email daemon (`/var/www/dnsscience/daemons/emaild.py`) has NO code to check DANE/TLSA records
- Database has NO columns for DANE/TLSA data in `email_security_records` table
- Count shows 0 because we're literally not checking this at all

**Impact:** HIGH - Missing critical email security data

**Root Cause Analysis:**
- DANE (DNS-based Authentication of Named Entities) provides SMTP security via TLSA records
- TLSA records specify which certificates are valid for a mail server
- Currently: No DNS queries for TLSA records (_25._tcp, _443._tcp)
- Currently: No database columns to store results

**Fix Required:**

1. **Database Schema Changes:**
```sql
ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS has_dane BOOLEAN DEFAULT false;

ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS tlsa_records JSONB DEFAULT '[]'::jsonb;

ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS tlsa_count INTEGER DEFAULT 0;

CREATE INDEX idx_email_security_dane
ON email_security_records(has_dane)
WHERE has_dane = true;
```

2. **Email Daemon Code Addition:**
- Add `check_tlsa_records(domain)` function
- Query `_443._tcp.<domain>` for HTTPS TLSA
- Query `_25._tcp.<domain>` for SMTP TLSA
- Parse TLSA record components: usage, selector, matching_type, cert_data
- Store in database with domain_id

3. **Verification:**
- Run daemon for 1 hour
- Check: `SELECT COUNT(*) FROM email_security_records WHERE has_dane = true`
- Expected: > 0 (some domains should have DANE)

---

### Issue 2: MTA-STS - NOT BEING COLLECTED ❌

**Problem:**
- MTA-STS (Mail Transfer Agent Strict Transport Security) completely missing
- No code in email daemon to check MTA-STS
- No database columns for MTA-STS data
- MTA-STS requires checking BOTH DNS and HTTPS

**Impact:** HIGH - Missing modern email security standard

**Technical Details:**
MTA-STS involves two checks:
1. DNS TXT record at `_mta-sts.<domain>` (contains version ID)
2. HTTPS policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`

Policy file format:
```
version: STSv1
mode: enforce
mx: mail.example.com
mx: *.example.com
max_age: 86400
```

**Fix Required:**

1. **Database Schema Changes:**
```sql
ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS has_mta_sts BOOLEAN DEFAULT false;

ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS mta_sts_policy TEXT;

ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS mta_sts_mode VARCHAR(20);

ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS mta_sts_max_age INTEGER;

CREATE INDEX idx_email_security_mta_sts
ON email_security_records(has_mta_sts)
WHERE has_mta_sts = true;
```

2. **Email Daemon Code Addition:**
- Add `check_mta_sts(domain)` function
- Step 1: DNS lookup for `_mta-sts.<domain>` TXT record
- Step 2: If found, HTTPS GET `https://mta-sts.<domain>/.well-known/mta-sts.txt`
- Parse policy: version, mode (enforce/testing/none), mx list, max_age
- Store in database
- Handle timeouts and SSL errors gracefully

3. **Verification:**
- Test with known MTA-STS domains: gmail.com, outlook.com
- Check: `SELECT COUNT(*) FROM email_security_records WHERE has_mta_sts = true`
- Expected: > 0

---

### Issue 3: DKIM Not Showing on Homepage ❌

**Problem:**
- Homepage displays DMARC and SPF counts
- DKIM count exists in database but not displayed
- Frontend needs update to show DKIM

**Impact:** MEDIUM - Data exists but not visible to users

**Fix Required:**

1. **Update `/api/stats` Endpoint:**
- Add DKIM count to response JSON
- Query: `SELECT COUNT(*) FROM email_security_records WHERE has_dkim = true`
- Include in stats payload

2. **Update Homepage Template:**
- Add DKIM display element
- Position with DMARC/SPF stats
- Use same styling/formatting

3. **Verification:**
- Visit homepage
- Check DKIM count displays
- Should show ~same percentage as DMARC (both require DNS management)

---

### Issue 4: GeoIP Data Empty (0 records) ❌

**Problem:**
- Tables exist: `geoip_locations`, `geoip_blocks` (created in last deployment)
- Both tables have 0 rows (except 5 sample locations)
- Domain enrichment not populating GeoIP data

**Impact:** HIGH - Geographic distribution features not working

**Root Cause:**
- GeoIP tables created but MaxMind data not imported
- Daemon can't populate what doesn't exist
- Requires MaxMind GeoLite2 database import

**Fix Required:**

1. **Import MaxMind GeoLite2 Database:**
```bash
# Script already exists: /usr/local/bin/update_geoip_data.sh
# Requires: MAXMIND_LICENSE_KEY in .env.production

sudo /usr/local/bin/update_geoip_data.sh
```

Expected import:
- ~3,000,000 location records
- ~4,000,000 IP block records
- ~500MB data

2. **Verify GeoIP Daemon Running:**
```bash
ps aux | grep geoip_daemon
```

3. **Populate Existing Domains:**
- Run enrichment daemon to backfill
- Query IPs for existing domains
- Look up in GeoIP database
- Update domain records

4. **Verification:**
```sql
SELECT COUNT(*) FROM geoip_locations;  -- Should be ~3M
SELECT COUNT(*) FROM geoip_blocks;     -- Should be ~4M
SELECT COUNT(*) FROM domains WHERE geo_location IS NOT NULL;  -- Should increase
```

---

### Issue 5: Redis Not Running - Causes "Loading..." Forever ❌

**Problem:**
- Redis service not installed/running on instance
- Homepage depends on Redis for live stats
- When Redis unavailable, homepage shows "Loading..." forever
- No fallback to SQL queries

**Impact:** CRITICAL - Homepage appears broken

**Technical Analysis:**
Homepage JavaScript expects Redis-backed endpoints:
- Market valuation stats
- Domains added today
- Domain status counts
- Geographic distribution

When Redis unavailable:
- AJAX calls timeout or return empty
- "Loading..." never replaced with data
- User sees broken site

**Fix Required:**

1. **Install Redis:**
```bash
sudo apt-get update
sudo apt-get install -y redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

2. **Configure Redis:**
```bash
# Set memory limits
redis-cli CONFIG SET maxmemory 256mb
redis-cli CONFIG SET maxmemory-policy allkeys-lru
redis-cli CONFIG REWRITE

# Enable persistence
redis-cli CONFIG SET save "900 1 300 10 60 10000"
```

3. **Create Populate Script:**
`/usr/local/bin/populate_redis_stats.py`
- Query current stats from PostgreSQL
- Populate Redis with keys:
  - `stats:total_domains`
  - `stats:total_valuations`
  - `stats:domains_today`
  - `stats:countries` (JSON hash)
  - `stats:email:dmarc_count`
  - `stats:email:spf_count`
  - `stats:email:dkim_count`
  - `stats:email:dane_count`
  - `stats:email:mta_sts_count`

4. **Update API Endpoints - Dual Source Strategy:**
```python
def get_stats():
    try:
        # Try Redis first (fast)
        if redis_client.exists('stats:total_domains'):
            return redis_client.hgetall('stats:all')
        else:
            # Fallback to SQL
            stats = query_stats_from_db()
            # Populate Redis for next time
            populate_redis(stats)
            return stats
    except:
        # Redis down - use SQL
        return query_stats_from_db()
```

5. **Setup Cron Job:**
```cron
# Refresh Redis stats every 5 minutes
*/5 * * * * /usr/bin/python3 /usr/local/bin/populate_redis_stats.py
```

---

### Issue 6: Homepage Stuck on "Loading..." ❌

**Problem:**
Multiple homepage sections stuck on "Loading...":
- Market Valuation: Loading...
- Domains added today: Loading...
- Domain status: Loading...
- Geographic distribution: Loading...

**Impact:** CRITICAL - User experience broken

**Root Cause:**
- Frontend expects Redis data
- Redis not running (Issue 5)
- No fallback to SQL in frontend or backend
- AJAX calls failing silently

**Fix Required:**

1. **Fix Redis (see Issue 5)**

2. **Add Frontend Fallback Logic:**
```javascript
function loadStats() {
    fetch('/api/stats/live')
        .then(response => response.json())
        .then(data => {
            // Update all stat displays
            document.getElementById('total-domains').textContent = data.total_domains.toLocaleString();
            document.getElementById('domains-today').textContent = data.domains_today.toLocaleString();
            // ... etc
        })
        .catch(error => {
            console.error('Stats failed, trying fallback:', error);
            // Try SQL-backed endpoint
            fetch('/api/stats/sql')
                .then(response => response.json())
                .then(data => updateStats(data))
                .catch(() => showError('Unable to load statistics'));
        });
}
```

3. **Add SQL Fallback Endpoint:**
`/api/stats/sql` - Pure SQL queries, no Redis dependency

4. **Pre-populate Redis on Page Load:**
- When user visits homepage
- Check if Redis has data
- If not, trigger populate script
- Return SQL data while Redis loads

---

## WORK COMPLETED (Previous Sessions)

### Phase 1: Database Infrastructure ✅
**Date:** November 14-15, 2025

**Completed:**
- Created `geoip_locations` table (schema complete)
- Created `geoip_blocks` table (schema complete)
- Added 5 GeoIP indexes for performance
- Created sample location data (5 cities)
- Created sample IP blocks (2 entries)
- Fixed `ip_reputation` table column errors
- Created performance indexes on domains table

**Files Modified:**
- `/var/www/dnsscience/database_schema.sql`
- Deployed via `fix_all_database_issues.py`

**Status:** ✅ COMPLETE (but needs data import)

---

### Phase 2: Daemon Fixes ✅
**Date:** November 14-15, 2025

**Completed:**
1. **Reputation Daemon Fixed:**
   - Issue: `column r.last_checked does not exist`
   - Fix: Ensured column exists via schema migration
   - File: `/var/www/dnsscience/daemons/reputationd.py`
   - Status: ✅ DEPLOYED

2. **Enrichment Daemon Fixed:**
   - Issue: Database connection errors
   - Fix: Robust connection handling
   - File: `/var/www/dnsscience/daemons/enrichment_daemon.py`
   - Status: ✅ DEPLOYED

3. **Email Daemon Working:**
   - Collecting: MX, SPF, DMARC, DKIM
   - 25,411 records collected
   - Status: ✅ OPERATIONAL

4. **SSL Scanner Daemon Working:**
   - Collecting SSL certificate data
   - Certificate expiry tracking
   - Status: ✅ OPERATIONAL

**Files Modified:**
- `/var/www/dnsscience/daemons/reputationd.py`
- `/var/www/dnsscience/daemons/enrichment_daemon.py`
- Backups created with `.bak` extension

**Status:** ✅ COMPLETE (but needs DANE/MTA-STS additions)

---

### Phase 3: Automated Maintenance ✅
**Date:** November 15, 2025

**Completed:**
1. **GeoIP Update Script:**
   - File: `/usr/local/bin/update_geoip_data.sh`
   - Purpose: Monthly MaxMind GeoLite2 import
   - Schedule: 1st of month, 3:00 AM
   - Status: ✅ INSTALLED

2. **Database Maintenance Script:**
   - File: `/usr/local/bin/db_maintenance.sh`
   - Purpose: Weekly VACUUM, ANALYZE, cleanup
   - Schedule: Sundays, 2:00 AM
   - Status: ✅ INSTALLED

3. **Cron Jobs:**
   - File: `/etc/cron.d/dnsscience_maintenance`
   - Jobs: GeoIP update (monthly), DB maintenance (weekly)
   - Status: ✅ ACTIVE

**Status:** ✅ COMPLETE

---

## REMAINING WORK (This Session)

### Priority 1: Email Security Collection (CRITICAL)

#### Task 1.1: Create DANE/TLSA Database Migration
**File:** `/Users/ryan/development/dnsscience-tool-tests/migrations/015_dane_tlsa_columns.sql`

```sql
-- Migration: Add DANE/TLSA support to email_security_records
-- Date: 2025-11-15
-- Purpose: Enable DANE/TLSA record collection

BEGIN;

-- Add DANE columns
ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS has_dane BOOLEAN DEFAULT false;

ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS tlsa_records JSONB DEFAULT '[]'::jsonb;

ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS tlsa_count INTEGER DEFAULT 0;

-- Add index for DANE queries
CREATE INDEX IF NOT EXISTS idx_email_security_dane
ON email_security_records(has_dane)
WHERE has_dane = true;

-- Add comments
COMMENT ON COLUMN email_security_records.has_dane IS 'Whether domain has DANE TLSA records';
COMMENT ON COLUMN email_security_records.tlsa_records IS 'Array of TLSA records with port, usage, selector, matching_type, cert_data';
COMMENT ON COLUMN email_security_records.tlsa_count IS 'Total number of TLSA records found';

COMMIT;
```

**Deployment:**
```bash
psql -h localhost -p 6432 -U dnsscience -d dnsscience -f 015_dane_tlsa_columns.sql
```

---

#### Task 1.2: Create MTA-STS Database Migration
**File:** `/Users/ryan/development/dnsscience-tool-tests/migrations/016_mta_sts_columns.sql`

```sql
-- Migration: Add MTA-STS support to email_security_records
-- Date: 2025-11-15
-- Purpose: Enable MTA-STS policy collection

BEGIN;

-- Add MTA-STS columns
ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS has_mta_sts BOOLEAN DEFAULT false;

ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS mta_sts_policy TEXT;

ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS mta_sts_mode VARCHAR(20);

ALTER TABLE email_security_records
ADD COLUMN IF NOT EXISTS mta_sts_max_age INTEGER;

-- Add index for MTA-STS queries
CREATE INDEX IF NOT EXISTS idx_email_security_mta_sts
ON email_security_records(has_mta_sts)
WHERE has_mta_sts = true;

-- Add comments
COMMENT ON COLUMN email_security_records.has_mta_sts IS 'Whether domain has MTA-STS policy';
COMMENT ON COLUMN email_security_records.mta_sts_policy IS 'Full MTA-STS policy text from .well-known/mta-sts.txt';
COMMENT ON COLUMN email_security_records.mta_sts_mode IS 'MTA-STS mode: enforce, testing, or none';
COMMENT ON COLUMN email_security_records.mta_sts_max_age IS 'MTA-STS max_age in seconds';

COMMIT;
```

---

#### Task 1.3: Update Email Daemon with DANE/TLSA Collection
**File:** `/Users/ryan/development/dnsscience-tool-tests/daemons/emaild_complete.py`

**Additions:**
1. Import binascii for hex encoding
2. Add `check_tlsa_records(domain)` function
3. Update database INSERT to include DANE fields
4. Add error handling for DNS timeouts

**Code Structure:**
```python
def check_tlsa_records(domain):
    """Check for DANE TLSA records on HTTPS (443) and SMTP (25) ports"""
    tlsa_records = []

    for port in [443, 25]:
        try:
            query = f"_{port}._tcp.{domain}"
            answers = resolver.resolve(query, 'TLSA')

            for rdata in answers:
                tlsa_records.append({
                    'port': port,
                    'usage': rdata.usage,
                    'selector': rdata.selector,
                    'matching_type': rdata.mtype,
                    'cert_data': binascii.hexlify(rdata.cert).decode()[:64]  # First 64 chars
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass  # No TLSA records for this port
        except Exception as e:
            self.logger.warning(f"TLSA check error for {domain} port {port}: {e}")

    return tlsa_records
```

---

#### Task 1.4: Update Email Daemon with MTA-STS Collection
**File:** `/Users/ryan/development/dnsscience-tool-tests/daemons/emaild_complete.py`

**Additions:**
1. Import requests for HTTPS calls
2. Add `check_mta_sts(domain)` function
3. Add `parse_mta_sts_policy(policy_text)` helper
4. Update database INSERT to include MTA-STS fields

**Code Structure:**
```python
def check_mta_sts(domain):
    """Check for MTA-STS policy via DNS and HTTPS"""
    # Step 1: Check DNS TXT record
    try:
        txt_query = f"_mta-sts.{domain}"
        answers = resolver.resolve(txt_query, 'TXT')

        # Found DNS record, proceed to HTTPS check
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"

        try:
            response = requests.get(policy_url, timeout=10, verify=True)
            if response.status_code == 200:
                return parse_mta_sts_policy(response.text)
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"MTA-STS HTTPS fetch failed for {domain}: {e}")

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass  # No MTA-STS DNS record

    return None

def parse_mta_sts_policy(policy_text):
    """Parse MTA-STS policy file"""
    policy = {
        'mode': None,
        'max_age': None,
        'mx': [],
        'full_policy': policy_text
    }

    for line in policy_text.split('\n'):
        line = line.strip()
        if line.startswith('mode:'):
            policy['mode'] = line.split(':', 1)[1].strip()
        elif line.startswith('max_age:'):
            policy['max_age'] = int(line.split(':', 1)[1].strip())
        elif line.startswith('mx:'):
            policy['mx'].append(line.split(':', 1)[1].strip())

    return policy
```

---

### Priority 2: Redis Setup (CRITICAL)

#### Task 2.1: Install Redis on Production Instance
**Commands:**
```bash
sudo apt-get update
sudo apt-get install -y redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Configure Redis
redis-cli CONFIG SET maxmemory 256mb
redis-cli CONFIG SET maxmemory-policy allkeys-lru
redis-cli CONFIG SET save "900 1 300 10 60 10000"
redis-cli CONFIG REWRITE

# Verify
redis-cli PING  # Should return PONG
```

---

#### Task 2.2: Create Redis Population Script
**File:** `/usr/local/bin/populate_redis_stats.py`

```python
#!/usr/bin/env python3
"""
Populate Redis with current statistics from PostgreSQL
Run via cron every 5 minutes
"""

import sys
import os
import redis
import psycopg2
import json

sys.path.append('/var/www/dnsscience')
from config import Config

def main():
    # Connect to database
    conn = psycopg2.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        database=Config.DB_NAME,
        user=Config.DB_USER,
        password=Config.DB_PASS
    )
    cur = conn.cursor()

    # Connect to Redis
    r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

    # Query stats
    stats = {}

    # Total domains
    cur.execute("SELECT COUNT(*) FROM domains WHERE is_active = true")
    stats['total_domains'] = cur.fetchone()[0]

    # Domains added today
    cur.execute("SELECT COUNT(*) FROM domains WHERE DATE(created_at) = CURRENT_DATE")
    stats['domains_today'] = cur.fetchone()[0]

    # Email security stats
    cur.execute("""
        SELECT
            COUNT(CASE WHEN has_dmarc = true THEN 1 END) as dmarc_count,
            COUNT(CASE WHEN has_spf = true THEN 1 END) as spf_count,
            COUNT(CASE WHEN has_dkim = true THEN 1 END) as dkim_count,
            COUNT(CASE WHEN has_dane = true THEN 1 END) as dane_count,
            COUNT(CASE WHEN has_mta_sts = true THEN 1 END) as mta_sts_count,
            COUNT(*) as total_checked
        FROM email_security_records
    """)
    email_stats = cur.fetchone()
    stats['email_dmarc'] = email_stats[0]
    stats['email_spf'] = email_stats[1]
    stats['email_dkim'] = email_stats[2]
    stats['email_dane'] = email_stats[3]
    stats['email_mta_sts'] = email_stats[4]
    stats['email_total'] = email_stats[5]

    # SSL certificates
    cur.execute("SELECT COUNT(*) FROM ssl_certificates")
    stats['ssl_total'] = cur.fetchone()[0]

    # Geographic distribution
    cur.execute("""
        SELECT country_name, COUNT(*) as cnt
        FROM domains d
        JOIN geoip_blocks gb ON d.ip_address <<= gb.network
        JOIN geoip_locations gl ON gb.geoname_id = gl.geoname_id
        WHERE d.is_active = true
        GROUP BY country_name
        ORDER BY cnt DESC
        LIMIT 20
    """)
    countries = {row[0]: row[1] for row in cur.fetchall()}
    stats['countries'] = json.dumps(countries)

    # Store in Redis
    pipe = r.pipeline()
    for key, value in stats.items():
        pipe.set(f'stats:{key}', value)
    pipe.set('stats:last_update', datetime.utcnow().isoformat())
    pipe.execute()

    print(f"Redis stats updated: {len(stats)} keys")

    conn.close()

if __name__ == '__main__':
    main()
```

**Deployment:**
```bash
sudo cp populate_redis_stats.py /usr/local/bin/
sudo chmod +x /usr/local/bin/populate_redis_stats.py

# Add to cron
echo "*/5 * * * * /usr/bin/python3 /usr/local/bin/populate_redis_stats.py >> /var/log/dnsscience/redis_populate.log 2>&1" | sudo tee -a /etc/cron.d/dnsscience_maintenance
```

---

### Priority 3: Frontend Updates (HIGH)

#### Task 3.1: Update /api/stats Endpoint
**File:** `/var/www/dnsscience/app.py`

**Modify `/api/stats/live` route:**
```python
@app.route('/api/stats/live')
def get_live_stats():
    """Get live statistics with Redis primary, SQL fallback"""
    try:
        # Try Redis first
        if redis_client and redis_client.exists('stats:total_domains'):
            return jsonify({
                'total_domains': int(redis_client.get('stats:total_domains')),
                'domains_today': int(redis_client.get('stats:domains_today')),
                'email_security': {
                    'dmarc': int(redis_client.get('stats:email_dmarc')),
                    'spf': int(redis_client.get('stats:email_spf')),
                    'dkim': int(redis_client.get('stats:email_dkim')),
                    'dane': int(redis_client.get('stats:email_dane')),
                    'mta_sts': int(redis_client.get('stats:email_mta_sts')),
                    'total': int(redis_client.get('stats:email_total'))
                },
                'ssl_certificates': int(redis_client.get('stats:ssl_total')),
                'countries': json.loads(redis_client.get('stats:countries')),
                'source': 'redis'
            })
    except Exception as e:
        app.logger.warning(f"Redis unavailable, falling back to SQL: {e}")

    # Fallback to SQL
    return jsonify(get_stats_from_sql())
```

---

#### Task 3.2: Update Homepage Template
**File:** `/var/www/dnsscience/templates/index.php` (or index.html)

**Add email security metrics section:**
```html
<div class="email-security-stats">
    <h3>Email Security Coverage</h3>
    <div class="stat-grid">
        <div class="stat-card">
            <div class="stat-number" id="dmarc-count">Loading...</div>
            <div class="stat-label">DMARC Records</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="spf-count">Loading...</div>
            <div class="stat-label">SPF Records</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="dkim-count">Loading...</div>
            <div class="stat-label">DKIM Configured</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="dane-count">Loading...</div>
            <div class="stat-label">DANE/TLSA Records</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="mta-sts-count">Loading...</div>
            <div class="stat-label">MTA-STS Policies</div>
        </div>
    </div>
</div>

<script>
function loadStats() {
    fetch('/api/stats/live')
        .then(response => response.json())
        .then(data => {
            document.getElementById('dmarc-count').textContent = data.email_security.dmarc.toLocaleString();
            document.getElementById('spf-count').textContent = data.email_security.spf.toLocaleString();
            document.getElementById('dkim-count').textContent = data.email_security.dkim.toLocaleString();
            document.getElementById('dane-count').textContent = data.email_security.dane.toLocaleString();
            document.getElementById('mta-sts-count').textContent = data.email_security.mta_sts.toLocaleString();

            // Update other stats...
            document.getElementById('total-domains').textContent = data.total_domains.toLocaleString();
            document.getElementById('domains-today').textContent = data.domains_today.toLocaleString();
        })
        .catch(error => {
            console.error('Failed to load stats:', error);
            // Show error message instead of "Loading..."
            document.querySelectorAll('.stat-number').forEach(el => {
                if (el.textContent === 'Loading...') {
                    el.textContent = 'N/A';
                }
            });
        });
}

// Load on page load
document.addEventListener('DOMContentLoaded', loadStats);

// Refresh every 30 seconds
setInterval(loadStats, 30000);
</script>
```

---

### Priority 4: GeoIP Data Import (HIGH)

#### Task 4.1: Run MaxMind Import Script
**Prerequisite:** Set MAXMIND_LICENSE_KEY in `.env.production`

**Command:**
```bash
# SSH to instance
aws ssm start-session --target i-09a4c4b10763e3d39

# On instance:
cd /var/www/dnsscience
sudo -u www-data bash

# Set license key in .env.production
nano .env.production
# Add: MAXMIND_LICENSE_KEY=your_key_here

# Run import
sudo /usr/local/bin/update_geoip_data.sh

# Monitor progress
tail -f /var/log/dnsscience/geoip_update.log
```

**Expected Results:**
- Download: ~200MB compressed CSV files
- Import: ~3,000,000 location records
- Import: ~4,000,000 IP block records
- Duration: ~15-30 minutes
- Disk usage: ~500MB

---

#### Task 4.2: Verify GeoIP Daemon Collecting Data
**Commands:**
```bash
# Check daemon running
ps aux | grep geoip_daemon

# Check logs
sudo tail -f /var/log/dnsscience/geoipd.log

# Verify data collection
psql -h localhost -p 6432 -U dnsscience -d dnsscience -c "
SELECT COUNT(*) as domains_with_geo
FROM domains
WHERE geo_location IS NOT NULL
"
```

---

## DEPLOYMENT STRATEGY

### Phase 1: Database Migrations (15 minutes)
1. Upload migration files to S3
2. Download to instance via SSM
3. Run migrations via psql
4. Verify columns created
5. Check indexes created

**Rollback:** Drop new columns if issues

---

### Phase 2: Daemon Updates (20 minutes)
1. Backup current emaild.py
2. Deploy updated emaild_complete.py
3. Test with single domain
4. Restart email daemon
5. Monitor logs for 5 minutes
6. Verify DANE/MTA-STS collection starting

**Rollback:** Restore from backup

---

### Phase 3: Redis Setup (10 minutes)
1. Install Redis package
2. Configure Redis
3. Start Redis service
4. Deploy populate script
5. Run populate script manually
6. Verify Redis has data
7. Setup cron job

**Rollback:** Stop Redis, remove from startup

---

### Phase 4: Frontend Updates (15 minutes)
1. Update app.py with new API endpoint
2. Update homepage template
3. Restart Apache
4. Test homepage loads
5. Verify no "Loading..." states
6. Verify all stats display

**Rollback:** Restore app.py and template from backup

---

### Phase 5: GeoIP Import (30 minutes)
1. Set MaxMind license key
2. Run import script
3. Monitor progress
4. Verify data imported
5. Test GeoIP lookups

**Rollback:** Not needed (additive operation)

---

### Phase 6: Verification (20 minutes)
1. Check DANE count > 0
2. Check TLSA count > 0
3. Check MTA-STS count > 0
4. Check DKIM displays on homepage
5. Check no "Loading..." on homepage
6. Check GeoIP data > 0
7. Run full daemon log check
8. Verify zero errors

---

## SUCCESS CRITERIA

### Email Security Collection ✓
- [ ] DANE/TLSA columns exist in database
- [ ] MTA-STS columns exist in database
- [ ] Email daemon code includes DANE checking
- [ ] Email daemon code includes MTA-STS checking
- [ ] After 1 hour: COUNT(*) WHERE has_dane = true > 0
- [ ] After 1 hour: COUNT(*) WHERE has_mta_sts = true > 0
- [ ] Zero daemon errors related to missing columns

### Homepage Display ✓
- [ ] Redis installed and running
- [ ] Redis populated with current stats
- [ ] Homepage shows DMARC count
- [ ] Homepage shows SPF count
- [ ] Homepage shows DKIM count
- [ ] Homepage shows DANE count
- [ ] Homepage shows MTA-STS count
- [ ] No "Loading..." states after page load
- [ ] Stats refresh every 30 seconds

### GeoIP Data ✓
- [ ] geoip_locations COUNT(*) > 1,000,000
- [ ] geoip_blocks COUNT(*) > 1,000,000
- [ ] GeoIP daemon running without errors
- [ ] Domains table populating geo_location
- [ ] Homepage shows geographic distribution

### System Health ✓
- [ ] All daemons running
- [ ] Zero database errors in logs
- [ ] Redis responding to PING
- [ ] Apache serving pages
- [ ] No 500 errors on any endpoint

---

## TIMELINE ESTIMATE

### Immediate (Next 2 Hours)
- Create all migration files
- Create updated email daemon
- Create Redis population script
- Create deployment script
- Test locally where possible

### Deployment (1.5 Hours)
- Upload files to S3
- Run database migrations
- Deploy daemon updates
- Install Redis
- Update frontend
- Restart all services

### Verification (1 Hour)
- Monitor daemon logs
- Check data collection
- Test all homepage features
- Verify zero errors
- Document results

**Total Time:** ~4-5 hours

---

## RISK ASSESSMENT

### Low Risk Items
- Database migrations (additive only, can rollback)
- Redis installation (isolated service)
- Frontend updates (can rollback quickly)

### Medium Risk Items
- Email daemon updates (affects data collection)
  - **Mitigation:** Test with single domain first
  - **Rollback:** Restore from backup
- GeoIP import (large data volume)
  - **Mitigation:** Monitor disk space
  - **Rollback:** Not needed (can delete data if issues)

### High Risk Items
- None identified

---

## MONITORING PLAN

### During Deployment (Real-time)
```bash
# Terminal 1: Daemon logs
sudo tail -f /var/log/dnsscience/emaild.log

# Terminal 2: Apache logs
sudo tail -f /var/log/apache2/error.log

# Terminal 3: Database queries
watch -n 5 'psql -h localhost -p 6432 -U dnsscience -d dnsscience -t -c "
SELECT
  COUNT(*) as total,
  COUNT(CASE WHEN has_dane THEN 1 END) as dane,
  COUNT(CASE WHEN has_mta_sts THEN 1 END) as mta_sts
FROM email_security_records
WHERE last_checked > NOW() - INTERVAL '\''10 minutes'\''
"'
```

### Post-Deployment (24 hours)
- Hourly log checks for errors
- Monitor data collection rates
- Check Redis memory usage
- Verify cron jobs running
- Review database performance

---

## ROLLBACK PROCEDURES

### Email Daemon Rollback
```bash
sudo cp /var/www/dnsscience/daemons/emaild.py.bak.$(date +%Y%m%d) \
       /var/www/dnsscience/daemons/emaild.py
sudo pkill -f emaild
sudo -u www-data nohup python3 /var/www/dnsscience/daemons/emaild.py &
```

### Database Rollback
```sql
-- Remove DANE columns
ALTER TABLE email_security_records DROP COLUMN IF EXISTS has_dane;
ALTER TABLE email_security_records DROP COLUMN IF EXISTS tlsa_records;
ALTER TABLE email_security_records DROP COLUMN IF EXISTS tlsa_count;

-- Remove MTA-STS columns
ALTER TABLE email_security_records DROP COLUMN IF EXISTS has_mta_sts;
ALTER TABLE email_security_records DROP COLUMN IF EXISTS mta_sts_policy;
ALTER TABLE email_security_records DROP COLUMN IF EXISTS mta_sts_mode;
ALTER TABLE email_security_records DROP COLUMN IF EXISTS mta_sts_max_age;
```

### Redis Rollback
```bash
sudo systemctl stop redis-server
sudo systemctl disable redis-server
sudo apt-get remove redis-server
```

### Frontend Rollback
```bash
sudo cp /var/www/dnsscience/app.py.bak /var/www/dnsscience/app.py
sudo cp /var/www/dnsscience/templates/index.php.bak /var/www/dnsscience/templates/index.php
sudo systemctl restart apache2
```

---

## DOCUMENTATION UPDATES NEEDED

After completion:
- [ ] Update API documentation with new stats fields
- [ ] Update database schema documentation
- [ ] Update daemon documentation
- [ ] Create operator runbook for Redis maintenance
- [ ] Update monitoring dashboard with new metrics

---

## FUTURE ENHANCEMENTS (Post-MVP)

### Email Security
- BIMI record checking
- TLS-RPT report collection
- ARC (Authenticated Received Chain) validation
- Email authentication scoring algorithm

### Performance
- Redis clustering for high availability
- Read replicas for database
- CDN for static assets
- Caching layer for API responses

### Features
- Real-time email security alerts
- Comparative domain analysis
- Industry benchmarking
- Security score trending

---

## CONTACT & ESCALATION

### Instance Access
```bash
aws ssm start-session --target i-09a4c4b10763e3d39
```

### Database Access
```bash
psql -h localhost -p 6432 -U dnsscience -d dnsscience
```

### Critical Files
- Email Daemon: `/var/www/dnsscience/daemons/emaild.py`
- API Server: `/var/www/dnsscience/app.py`
- Homepage: `/var/www/dnsscience/templates/index.php`
- Redis Script: `/usr/local/bin/populate_redis_stats.py`
- Cron Jobs: `/etc/cron.d/dnsscience_maintenance`

### Log Locations
- Daemons: `/var/log/dnsscience/*.log`
- Apache: `/var/log/apache2/error.log`
- Redis: `/var/log/redis/redis-server.log`
- Cron: `/var/log/syslog` (grep for dnsscience)

---

## APPENDIX A: Sample Queries

### Check Email Security Coverage
```sql
SELECT
    COUNT(*) as total_domains,
    COUNT(CASE WHEN has_mx THEN 1 END) as has_mx,
    COUNT(CASE WHEN has_spf THEN 1 END) as has_spf,
    COUNT(CASE WHEN has_dmarc THEN 1 END) as has_dmarc,
    COUNT(CASE WHEN has_dkim THEN 1 END) as has_dkim,
    COUNT(CASE WHEN has_dane THEN 1 END) as has_dane,
    COUNT(CASE WHEN has_mta_sts THEN 1 END) as has_mta_sts,
    ROUND(100.0 * COUNT(CASE WHEN has_dmarc THEN 1 END) / COUNT(*), 2) as dmarc_pct,
    ROUND(100.0 * COUNT(CASE WHEN has_dane THEN 1 END) / COUNT(*), 2) as dane_pct,
    ROUND(100.0 * COUNT(CASE WHEN has_mta_sts THEN 1 END) / COUNT(*), 2) as mta_sts_pct
FROM email_security_records
WHERE last_checked > NOW() - INTERVAL '7 days';
```

### Check Data Collection Rate
```sql
SELECT
    DATE_TRUNC('hour', last_checked) as hour,
    COUNT(*) as records_checked
FROM email_security_records
WHERE last_checked > NOW() - INTERVAL '24 hours'
GROUP BY hour
ORDER BY hour DESC;
```

### Find Domains with Full Email Security
```sql
SELECT
    d.domain_name,
    e.has_mx,
    e.has_spf,
    e.has_dmarc,
    e.has_dkim,
    e.has_dane,
    e.has_mta_sts
FROM domains d
JOIN email_security_records e ON d.id = e.domain_id
WHERE e.has_mx = true
  AND e.has_spf = true
  AND e.has_dmarc = true
  AND e.has_dkim = true
  AND e.has_dane = true
  AND e.has_mta_sts = true
LIMIT 10;
```

---

## APPENDIX B: Testing Domains

Use these domains for testing (known to have various email security features):

### DANE/TLSA Testing:
- `fedoraproject.org` - Has TLSA records
- `freebsd.org` - Has TLSA records
- `sys4.de` - Has TLSA records

### MTA-STS Testing:
- `gmail.com` - Has MTA-STS
- `outlook.com` - Has MTA-STS
- `yahoo.com` - Has MTA-STS
- `protonmail.com` - Has MTA-STS

### Full Stack Testing:
- `google.com` - MX, SPF, DMARC, DKIM, MTA-STS
- `microsoft.com` - MX, SPF, DMARC, DKIM, MTA-STS
- `cloudflare.com` - Full email security

---

**Document Status:** DRAFT
**Last Updated:** 2025-11-15 04:30 AM EST
**Next Review:** After deployment completion
**Approver:** Pending deployment

---

**END OF COMPREHENSIVE PROJECT PLAN**
