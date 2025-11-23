#!/bin/bash
# Wrapper to run database fixes with proper environment

cd /var/www/dnsscience
source .env 2>/dev/null || true

# Export DB variables if they exist
export DB_HOST DB_PORT DB_NAME DB_USER DB_PASS

# Run the SQL fix
PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" < /tmp/dnsscience_fixes/database_schema_fixes.sql
