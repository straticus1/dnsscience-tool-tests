#!/bin/bash
###############################################################################
# DNS Science - Database Maintenance Script
# Performs routine database maintenance tasks
# Schedule with cron: 0 2 * * 0 /usr/local/bin/db_maintenance.sh (weekly)
###############################################################################

set -euo pipefail

# Configuration
LOG_FILE="/var/log/dnsscience/db_maintenance.log"
DB_NAME="${DB_NAME:-dnsscience}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-6432}"
DB_USER="${DB_USER:-dnsscience_app}"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Error handler
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Load environment variables
if [ -f /var/www/dnsscience/.env.production ]; then
    export $(grep -v '^#' /var/www/dnsscience/.env.production | xargs)
fi

# Main execution
main() {
    log "=== Starting Database Maintenance ==="

    # 1. Vacuum and Analyze
    log "Running VACUUM ANALYZE..."
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
-- Vacuum analyze all tables
VACUUM ANALYZE;
EOF

    if [ $? -ne 0 ]; then
        error_exit "VACUUM ANALYZE failed"
    fi
    log "✓ VACUUM ANALYZE complete"

    # 2. Update table statistics
    log "Updating table statistics..."
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
-- Analyze critical tables
ANALYZE domains;
ANALYZE domain_lookups;
ANALYZE whois_records;
ANALYZE dns_records;
ANALYZE ip_reputation;
ANALYZE geoip_blocks;
ANALYZE geoip_locations;
ANALYZE ssl_certificates;
ANALYZE malware_indicators;
EOF

    if [ $? -ne 0 ]; then
        error_exit "Statistics update failed"
    fi
    log "✓ Statistics updated"

    # 3. Check for table bloat
    log "Checking for table bloat..."
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -A <<EOF | tee -a "$LOG_FILE"
SELECT
    schemaname || '.' || tablename AS table,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size,
    CASE WHEN n_dead_tup > n_live_tup * 0.2 THEN 'HIGH BLOAT' ELSE 'OK' END AS status
FROM pg_stat_user_tables
WHERE n_dead_tup > 10000
ORDER BY n_dead_tup DESC
LIMIT 10;
EOF

    # 4. Reindex if needed (for tables with high bloat)
    log "Checking if reindexing is needed..."
    BLOATED_TABLES=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -A <<EOF
SELECT tablename
FROM pg_stat_user_tables
WHERE n_dead_tup > n_live_tup * 0.3 AND n_live_tup > 10000
LIMIT 5;
EOF
)

    if [ -n "$BLOATED_TABLES" ]; then
        log "Reindexing bloated tables..."
        while IFS= read -r table; do
            if [ -n "$table" ]; then
                log "  Reindexing: $table"
                PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "REINDEX TABLE $table;" || log "    WARNING: Reindex failed for $table"
            fi
        done <<< "$BLOATED_TABLES"
    else
        log "No reindexing needed"
    fi

    # 5. Clean old log entries (keep last 90 days)
    log "Cleaning old log entries..."
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
-- Clean old domain lookups (keep 90 days)
DELETE FROM domain_lookups
WHERE lookup_date < NOW() - INTERVAL '90 days';

-- Clean old enrichment history (keep 90 days)
DELETE FROM enrichment_history
WHERE enriched_at < NOW() - INTERVAL '90 days'
  AND EXISTS (SELECT 1 FROM enrichment_history);

-- Clean old API logs if table exists (keep 30 days)
DELETE FROM api_logs
WHERE created_at < NOW() - INTERVAL '30 days'
  AND EXISTS (SELECT 1 FROM api_logs);
EOF

    log "✓ Old entries cleaned"

    # 6. Database size report
    log "Database size report:"
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -A <<EOF | tee -a "$LOG_FILE"
SELECT
    pg_size_pretty(pg_database_size('$DB_NAME')) AS total_size;

SELECT
    schemaname || '.' || tablename AS table,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS total_size,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) AS table_size,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) AS index_size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
LIMIT 20;
EOF

    # 7. Connection pool stats
    log "Connection pool statistics:"
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -A <<EOF | tee -a "$LOG_FILE"
SELECT
    'Active connections: ' || COUNT(*) AS connections
FROM pg_stat_activity
WHERE datname = '$DB_NAME';

SELECT
    state,
    COUNT(*) as count
FROM pg_stat_activity
WHERE datname = '$DB_NAME'
GROUP BY state;
EOF

    log "=== Database Maintenance Complete ==="
}

# Run main
main "$@"
