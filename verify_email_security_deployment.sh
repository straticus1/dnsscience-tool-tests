#!/bin/bash
#
# DNS Science - Email Security Deployment Verification Script
# Run this on the production instance to verify DANE/TLSA and MTA-STS collection
#
# Usage: sudo bash verify_email_security_deployment.sh
#

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Functions
log_section() {
    echo -e "\n${BLUE}$======================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}======================================================================${NC}\n"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

check_count() {
    local description=$1
    local count=$2
    local expected_min=$3

    if [ "$count" -ge "$expected_min" ]; then
        log_success "$description: $count (expected >= $expected_min)"
        return 0
    else
        log_warning "$description: $count (expected >= $expected_min)"
        return 1
    fi
}

# Load environment
cd /var/www/dnsscience
if [ -f .env.production ]; then
    export $(grep -v '^#' .env.production | xargs)
else
    log_error ".env.production not found"
    exit 1
fi

log_section "DNS SCIENCE - EMAIL SECURITY DEPLOYMENT VERIFICATION"

# 1. Check Database Schema
log_section "1. DATABASE SCHEMA VERIFICATION"

echo "Checking for DANE/TLSA columns..."
DANE_COLS=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
"SELECT COUNT(*) FROM information_schema.columns
 WHERE table_name = 'email_security_records'
 AND column_name IN ('has_dane', 'tlsa_records', 'tlsa_count')")

if [ "$DANE_COLS" -eq 3 ]; then
    log_success "DANE/TLSA columns exist (3/3)"
else
    log_error "DANE/TLSA columns missing ($DANE_COLS/3)"
fi

echo ""
echo "Checking for MTA-STS columns..."
MTA_STS_COLS=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
"SELECT COUNT(*) FROM information_schema.columns
 WHERE table_name = 'email_security_records'
 AND column_name IN ('has_mta_sts', 'mta_sts_policy', 'mta_sts_mode', 'mta_sts_max_age')")

if [ "$MTA_STS_COLS" -eq 4 ]; then
    log_success "MTA-STS columns exist (4/4)"
else
    log_error "MTA-STS columns missing ($MTA_STS_COLS/4)"
fi

# 2. Check Email Daemon
log_section "2. EMAIL DAEMON STATUS"

if ps aux | grep -v grep | grep -q 'python3.*emaild'; then
    log_success "Email daemon is running"
    ps aux | grep -v grep | grep 'python3.*emaild'
else
    log_error "Email daemon is NOT running"
fi

echo ""
echo "Checking daemon code for DANE/MTA-STS support..."
if grep -q "check_tlsa_records" /var/www/dnsscience/daemons/emaild.py; then
    log_success "Email daemon has TLSA checking code"
else
    log_warning "Email daemon missing TLSA checking code"
fi

if grep -q "check_mta_sts" /var/www/dnsscience/daemons/emaild.py; then
    log_success "Email daemon has MTA-STS checking code"
else
    log_warning "Email daemon missing MTA-STS checking code"
fi

# 3. Check Redis
log_section "3. REDIS STATUS"

if command -v redis-cli &> /dev/null; then
    log_success "Redis is installed"

    if redis-cli PING &> /dev/null; then
        log_success "Redis is responding"

        # Check for stats keys
        STATS_KEYS=$(redis-cli KEYS 'stats:*' | wc -l)
        if [ "$STATS_KEYS" -gt 0 ]; then
            log_success "Redis has $STATS_KEYS stats keys"

            echo ""
            echo "Sample Redis values:"
            echo "  total_domains: $(redis-cli GET stats:total_domains)"
            echo "  email_dmarc: $(redis-cli GET stats:email_dmarc)"
            echo "  email_dane: $(redis-cli GET stats:email_dane)"
            echo "  email_mta_sts: $(redis-cli GET stats:email_mta_sts)"
        else
            log_warning "Redis has no stats keys (run populate_redis_stats.py)"
        fi
    else
        log_error "Redis is not responding"
    fi
else
    log_error "Redis is not installed"
fi

# 4. Check Data Collection
log_section "4. DATA COLLECTION VERIFICATION"

echo "Querying email security statistics..."
PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
SELECT
    COUNT(*) as total_records,
    COUNT(CASE WHEN has_mx = true THEN 1 END) as mx_count,
    COUNT(CASE WHEN has_spf = true THEN 1 END) as spf_count,
    COUNT(CASE WHEN has_dmarc = true THEN 1 END) as dmarc_count,
    COUNT(CASE WHEN has_dkim = true THEN 1 END) as dkim_count,
    COUNT(CASE WHEN has_dane = true THEN 1 END) as dane_count,
    COUNT(CASE WHEN has_mta_sts = true THEN 1 END) as mta_sts_count
FROM email_security_records;
EOF

echo ""
echo "Recent collection (last hour)..."
RECENT_COUNT=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
"SELECT COUNT(*) FROM email_security_records WHERE last_checked > NOW() - INTERVAL '1 hour'")

check_count "Records checked in last hour" "$RECENT_COUNT" "1"

echo ""
echo "DANE collection (last hour)..."
DANE_RECENT=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
"SELECT COUNT(*) FROM email_security_records WHERE last_checked > NOW() - INTERVAL '1 hour' AND has_dane = true")

if [ "$DANE_RECENT" -gt 0 ]; then
    log_success "DANE records being collected ($DANE_RECENT found in last hour)"
else
    log_warning "No DANE records found yet (may take time, only a few domains have DANE)"
fi

echo ""
echo "MTA-STS collection (last hour)..."
MTA_STS_RECENT=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
"SELECT COUNT(*) FROM email_security_records WHERE last_checked > NOW() - INTERVAL '1 hour' AND has_mta_sts = true")

if [ "$MTA_STS_RECENT" -gt 0 ]; then
    log_success "MTA-STS records being collected ($MTA_STS_RECENT found in last hour)"
else
    log_warning "No MTA-STS records found yet (may take time, only major providers have MTA-STS)"
fi

# 5. Check Logs
log_section "5. DAEMON LOGS"

echo "Last 20 lines of email daemon log:"
tail -20 /var/log/dnsscience/emaild.log

echo ""
echo "Checking for errors..."
ERROR_COUNT=$(grep -i error /var/log/dnsscience/emaild.log | tail -20 | wc -l)
if [ "$ERROR_COUNT" -gt 0 ]; then
    log_warning "Found $ERROR_COUNT recent errors in log:"
    grep -i error /var/log/dnsscience/emaild.log | tail -5
else
    log_success "No recent errors in email daemon log"
fi

# 6. Check Cron Jobs
log_section "6. CRON JOBS"

if grep -q "populate_redis_stats" /etc/cron.d/dnsscience_maintenance 2>/dev/null; then
    log_success "Redis population cron job exists"
    grep "populate_redis_stats" /etc/cron.d/dnsscience_maintenance
else
    log_warning "Redis population cron job not found"
fi

# 7. Test API Endpoint
log_section "7. API ENDPOINT TEST"

echo "Testing /api/stats/live endpoint..."
if curl -s http://localhost/api/stats/live > /tmp/api_test.json; then
    log_success "API endpoint responded"

    if grep -q "email_dane" /tmp/api_test.json; then
        log_success "API includes DANE count"
    else
        log_warning "API missing DANE count"
    fi

    if grep -q "email_mta_sts" /tmp/api_test.json; then
        log_success "API includes MTA-STS count"
    else
        log_warning "API missing MTA-STS count"
    fi

    echo ""
    echo "API response sample:"
    python3 -m json.tool /tmp/api_test.json 2>/dev/null | head -30
else
    log_error "API endpoint not responding"
fi

# 8. Final Summary
log_section "VERIFICATION SUMMARY"

TOTAL_CHECKS=0
PASSED_CHECKS=0

# Database schema
if [ "$DANE_COLS" -eq 3 ] && [ "$MTA_STS_COLS" -eq 4 ]; then
    ((PASSED_CHECKS++))
fi
((TOTAL_CHECKS++))

# Daemon running
if ps aux | grep -v grep | grep -q 'python3.*emaild'; then
    ((PASSED_CHECKS++))
fi
((TOTAL_CHECKS++))

# Redis running
if redis-cli PING &> /dev/null; then
    ((PASSED_CHECKS++))
fi
((TOTAL_CHECKS++))

# Data collection
if [ "$RECENT_COUNT" -gt 0 ]; then
    ((PASSED_CHECKS++))
fi
((TOTAL_CHECKS++))

echo ""
echo "Overall Status: $PASSED_CHECKS/$TOTAL_CHECKS checks passed"

if [ "$PASSED_CHECKS" -eq "$TOTAL_CHECKS" ]; then
    log_success "ALL CHECKS PASSED - Deployment successful!"
    exit 0
elif [ "$PASSED_CHECKS" -ge $((TOTAL_CHECKS - 1)) ]; then
    log_warning "Most checks passed - Minor issues detected"
    exit 0
else
    log_error "Multiple checks failed - Review deployment"
    exit 1
fi
