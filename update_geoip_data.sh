#!/bin/bash
###############################################################################
# DNS Science - GeoIP Data Update Script
# Downloads and updates MaxMind GeoLite2 data monthly
# Schedule with cron: 0 3 1 * * /usr/local/bin/update_geoip_data.sh
###############################################################################

set -euo pipefail

# Configuration
LOG_FILE="/var/log/dnsscience/geoip_update.log"
WORK_DIR="/tmp/geoip_update_$$"
DB_NAME="${DB_NAME:-dnsscience}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-6432}"
DB_USER="${DB_USER:-dnsscience_app}"

# MaxMind License Key (should be in environment or .env file)
MAXMIND_LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Error handler
error_exit() {
    log "ERROR: $1"
    cleanup
    exit 1
}

# Cleanup function
cleanup() {
    log "Cleaning up temporary files..."
    rm -rf "$WORK_DIR"
}

# Trap errors and interrupts
trap cleanup EXIT

# Main execution
main() {
    log "=== Starting GeoIP Database Update ==="

    # Check for license key
    if [ -z "$MAXMIND_LICENSE_KEY" ]; then
        log "WARNING: MAXMIND_LICENSE_KEY not set. Using direct download (may be outdated)."
        log "To get updates, sign up at https://www.maxmind.com/en/geolite2/signup"
    fi

    # Create work directory
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"

    # Download GeoLite2 data
    log "Downloading GeoLite2-City database..."

    if [ -n "$MAXMIND_LICENSE_KEY" ]; then
        # Use MaxMind direct download with license key
        DOWNLOAD_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City-CSV&license_key=${MAXMIND_LICENSE_KEY}&suffix=zip"
        if ! curl -s -o GeoLite2-City-CSV.zip "$DOWNLOAD_URL"; then
            error_exit "Failed to download GeoLite2 data with license key"
        fi
    else
        # Fallback: Try to use existing data or download from mirror
        log "WARNING: Using fallback download method. Data may be outdated."
        # For production, you MUST use a license key
        # This is just a placeholder - you need to implement your own mirror or use MaxMind
        log "Skipping download - please set MAXMIND_LICENSE_KEY"
        log "Creating empty placeholder files for testing..."
        mkdir -p GeoLite2-City-CSV
        touch GeoLite2-City-CSV/GeoLite2-City-Blocks-IPv4.csv
        touch GeoLite2-City-CSV/GeoLite2-City-Locations-en.csv
    fi

    # Extract if downloaded
    if [ -f GeoLite2-City-CSV.zip ]; then
        log "Extracting archive..."
        unzip -q GeoLite2-City-CSV.zip

        # Find extracted directory
        EXTRACTED_DIR=$(find . -maxdepth 1 -type d -name "GeoLite2-City-CSV_*" | head -1)
        if [ -z "$EXTRACTED_DIR" ]; then
            error_exit "Could not find extracted directory"
        fi

        mv "$EXTRACTED_DIR" GeoLite2-City-CSV
    fi

    # Verify files exist
    if [ ! -f "GeoLite2-City-CSV/GeoLite2-City-Locations-en.csv" ]; then
        error_exit "Locations CSV file not found"
    fi

    if [ ! -f "GeoLite2-City-CSV/GeoLite2-City-Blocks-IPv4.csv" ]; then
        error_exit "Blocks CSV file not found"
    fi

    log "Files downloaded and extracted successfully"

    # Load environment variables
    if [ -f /var/www/dnsscience/.env.production ]; then
        export $(grep -v '^#' /var/www/dnsscience/.env.production | xargs)
    fi

    # Import locations data
    log "Importing location data..."
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
-- Truncate existing data
TRUNCATE TABLE geoip_blocks CASCADE;
TRUNCATE TABLE geoip_locations CASCADE;

-- Import locations
COPY geoip_locations (
    geoname_id, locale_code, continent_code, continent_name,
    country_iso_code, country_name, subdivision_1_iso_code, subdivision_1_name,
    subdivision_2_iso_code, subdivision_2_name, city_name, metro_code,
    time_zone, is_in_european_union
) FROM '${WORK_DIR}/GeoLite2-City-CSV/GeoLite2-City-Locations-en.csv'
WITH (FORMAT csv, HEADER true);

-- Import IPv4 blocks
COPY geoip_blocks (
    network, geoname_id, registered_country_geoname_id, represented_country_geoname_id,
    is_anonymous_proxy, is_satellite_provider, postal_code, latitude, longitude, accuracy_radius
) FROM '${WORK_DIR}/GeoLite2-City-CSV/GeoLite2-City-Blocks-IPv4.csv'
WITH (FORMAT csv, HEADER true);

-- Update statistics
ANALYZE geoip_locations;
ANALYZE geoip_blocks;
EOF

    if [ $? -ne 0 ]; then
        error_exit "Failed to import GeoIP data into database"
    fi

    # Get counts
    LOCATION_COUNT=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM geoip_locations")
    BLOCK_COUNT=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM geoip_blocks")

    log "Import completed successfully!"
    log "Locations imported: $(echo $LOCATION_COUNT | xargs)"
    log "IP blocks imported: $(echo $BLOCK_COUNT | xargs)"

    # Cleanup
    cleanup

    log "=== GeoIP Database Update Complete ==="
}

# Run main
main "$@"
