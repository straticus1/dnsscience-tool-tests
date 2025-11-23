-- DNS Science - Database Schema Fixes
-- Run this to fix all database schema issues

-- Create GeoIP tables
DROP TABLE IF EXISTS geoip_blocks CASCADE;
DROP TABLE IF EXISTS geoip_locations CASCADE;

CREATE TABLE geoip_locations (
    geoname_id INTEGER PRIMARY KEY,
    locale_code VARCHAR(10) DEFAULT 'en',
    continent_code VARCHAR(2),
    continent_name VARCHAR(100),
    country_iso_code VARCHAR(2),
    country_name VARCHAR(100),
    subdivision_1_iso_code VARCHAR(3),
    subdivision_1_name VARCHAR(100),
    subdivision_2_iso_code VARCHAR(3),
    subdivision_2_name VARCHAR(100),
    city_name VARCHAR(100),
    metro_code INTEGER,
    time_zone VARCHAR(50),
    is_in_european_union BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE geoip_blocks (
    id SERIAL PRIMARY KEY,
    network CIDR NOT NULL,
    geoname_id INTEGER REFERENCES geoip_locations(geoname_id),
    registered_country_geoname_id INTEGER,
    represented_country_geoname_id INTEGER,
    is_anonymous_proxy BOOLEAN DEFAULT false,
    is_satellite_provider BOOLEAN DEFAULT false,
    postal_code VARCHAR(20),
    latitude NUMERIC(10,7),
    longitude NUMERIC(10,7),
    accuracy_radius INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(network)
);

-- Create GeoIP indexes
CREATE INDEX idx_geoip_blocks_network ON geoip_blocks USING GIST (network inet_ops);
CREATE INDEX idx_geoip_blocks_geoname ON geoip_blocks (geoname_id);
CREATE INDEX idx_geoip_locations_country ON geoip_locations (country_iso_code);
CREATE INDEX idx_geoip_locations_city ON geoip_locations (city_name);
CREATE INDEX idx_geoip_locations_continent ON geoip_locations (continent_code);

-- Add missing columns to ip_reputation table (if not exist)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ip_reputation' AND column_name = 'last_checked') THEN
        ALTER TABLE ip_reputation ADD COLUMN last_checked TIMESTAMP;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ip_reputation' AND column_name = 'updated_at') THEN
        ALTER TABLE ip_reputation ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ip_reputation' AND column_name = 'created_at') THEN
        ALTER TABLE ip_reputation ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    END IF;
END $$;

-- Add missing columns to domains table (if not exist)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'domains' AND column_name = 'last_checked') THEN
        ALTER TABLE domains ADD COLUMN last_checked TIMESTAMP;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'domains' AND column_name = 'geo_location') THEN
        ALTER TABLE domains ADD COLUMN geo_location VARCHAR(255);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'domains' AND column_name = 'reputation_score') THEN
        ALTER TABLE domains ADD COLUMN reputation_score INTEGER DEFAULT 50;
    END IF;
END $$;

-- Create performance indexes
CREATE INDEX IF NOT EXISTS idx_domains_last_checked ON domains (last_checked) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_domains_active ON domains (is_active, last_checked);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_last_checked ON ip_reputation (last_checked);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_domain ON ip_reputation (domain_id, last_checked);

-- Insert sample GeoIP data for testing
INSERT INTO geoip_locations (geoname_id, locale_code, continent_code, continent_name, country_iso_code, country_name, subdivision_1_iso_code, subdivision_1_name, city_name, metro_code, time_zone, is_in_european_union)
VALUES
(4180439, 'en', 'NA', 'North America', 'US', 'United States', 'VA', 'Virginia', 'Ashburn', 511, 'America/New_York', false),
(2643743, 'en', 'EU', 'Europe', 'GB', 'United Kingdom', 'ENG', 'England', 'London', NULL, 'Europe/London', true),
(5375480, 'en', 'NA', 'North America', 'US', 'United States', 'CA', 'California', 'Mountain View', 807, 'America/Los_Angeles', false),
(1850147, 'en', 'AS', 'Asia', 'JP', 'Japan', '13', 'Tokyo', 'Tokyo', NULL, 'Asia/Tokyo', false),
(2988507, 'en', 'EU', 'Europe', 'FR', 'France', 'IDF', 'Île-de-France', 'Paris', NULL, 'Europe/Paris', true)
ON CONFLICT (geoname_id) DO NOTHING;

INSERT INTO geoip_blocks (network, geoname_id, registered_country_geoname_id, is_anonymous_proxy, is_satellite_provider, latitude, longitude, accuracy_radius)
VALUES
('8.8.8.0/24', 5375480, 6252001, false, false, 37.3860, -122.0838, 1000),
('1.1.1.0/24', 4180439, 6252001, false, false, 39.0481, -77.4728, 1000)
ON CONFLICT (network) DO NOTHING;

-- Update statistics
ANALYZE geoip_locations;
ANALYZE geoip_blocks;
ANALYZE ip_reputation;
ANALYZE domains;
