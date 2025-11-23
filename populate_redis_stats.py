#!/usr/bin/env python3
"""
DNS Science - Redis Statistics Population Script
Queries current statistics from PostgreSQL and populates Redis cache
Run via cron every 5 minutes for fast homepage loading

This script ensures homepage shows real data instead of "Loading..."
when Redis is the primary data source for live statistics.
"""

import sys
import os
import json
from datetime import datetime

# Add DNS Science path for imports
sys.path.append('/var/www/dnsscience')

try:
    import redis
    import psycopg2
    import psycopg2.extras
    from config import Config
    DEPS_AVAILABLE = True
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip3 install redis psycopg2-binary")
    DEPS_AVAILABLE = False
    sys.exit(1)

class RedisStatsPopulator:
    """Populates Redis with statistics from PostgreSQL"""

    def __init__(self):
        """Initialize database and Redis connections"""
        # Connect to PostgreSQL
        self.conn = psycopg2.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            database=Config.DB_NAME,
            user=Config.DB_USER,
            password=Config.DB_PASS
        )
        self.cur = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Connect to Redis
        self.redis_client = redis.Redis(
            host='localhost',
            port=6379,
            db=0,
            decode_responses=True,
            socket_connect_timeout=5
        )

        # Test Redis connection
        try:
            self.redis_client.ping()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Connected to Redis")
        except redis.exceptions.ConnectionError:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: Redis not available")
            sys.exit(1)

    def get_domain_stats(self):
        """Get domain-related statistics"""
        stats = {}

        # Total active domains
        self.cur.execute("SELECT COUNT(*) FROM domains WHERE is_active = true")
        stats['total_domains'] = self.cur.fetchone()[0]

        # Domains added today
        self.cur.execute("""
            SELECT COUNT(*)
            FROM domains
            WHERE DATE(created_at) = CURRENT_DATE
        """)
        stats['domains_today'] = self.cur.fetchone()[0]

        # Domains added this week
        self.cur.execute("""
            SELECT COUNT(*)
            FROM domains
            WHERE created_at >= DATE_TRUNC('week', CURRENT_DATE)
        """)
        stats['domains_this_week'] = self.cur.fetchone()[0]

        # Domains added this month
        self.cur.execute("""
            SELECT COUNT(*)
            FROM domains
            WHERE created_at >= DATE_TRUNC('month', CURRENT_DATE)
        """)
        stats['domains_this_month'] = self.cur.fetchone()[0]

        return stats

    def get_email_security_stats(self):
        """Get comprehensive email security statistics"""
        stats = {}

        # Email security coverage
        self.cur.execute("""
            SELECT
                COUNT(*) as total_checked,
                COUNT(CASE WHEN has_mx = true THEN 1 END) as mx_count,
                COUNT(CASE WHEN has_spf = true THEN 1 END) as spf_count,
                COUNT(CASE WHEN has_dmarc = true THEN 1 END) as dmarc_count,
                COUNT(CASE WHEN has_dkim = true THEN 1 END) as dkim_count,
                COUNT(CASE WHEN has_dane = true THEN 1 END) as dane_count,
                COUNT(CASE WHEN has_mta_sts = true THEN 1 END) as mta_sts_count
            FROM email_security_records
        """)

        row = self.cur.fetchone()
        stats['email_total'] = row['total_checked']
        stats['email_mx'] = row['mx_count']
        stats['email_spf'] = row['spf_count']
        stats['email_dmarc'] = row['dmarc_count']
        stats['email_dkim'] = row['dkim_count']
        stats['email_dane'] = row['dane_count']
        stats['email_mta_sts'] = row['mta_sts_count']

        # Calculate percentages
        if stats['email_total'] > 0:
            stats['email_spf_pct'] = round(100.0 * stats['email_spf'] / stats['email_total'], 2)
            stats['email_dmarc_pct'] = round(100.0 * stats['email_dmarc'] / stats['email_total'], 2)
            stats['email_dkim_pct'] = round(100.0 * stats['email_dkim'] / stats['email_total'], 2)
            stats['email_dane_pct'] = round(100.0 * stats['email_dane'] / stats['email_total'], 2)
            stats['email_mta_sts_pct'] = round(100.0 * stats['email_mta_sts'] / stats['email_total'], 2)
        else:
            stats['email_spf_pct'] = 0
            stats['email_dmarc_pct'] = 0
            stats['email_dkim_pct'] = 0
            stats['email_dane_pct'] = 0
            stats['email_mta_sts_pct'] = 0

        return stats

    def get_ssl_stats(self):
        """Get SSL certificate statistics"""
        stats = {}

        # Total SSL certificates
        self.cur.execute("SELECT COUNT(*) FROM ssl_certificates")
        stats['ssl_total'] = self.cur.fetchone()[0]

        # SSL certificates expiring soon (30 days)
        self.cur.execute("""
            SELECT COUNT(*)
            FROM ssl_certificates
            WHERE expires_at BETWEEN NOW() AND NOW() + INTERVAL '30 days'
        """)
        stats['ssl_expiring_soon'] = self.cur.fetchone()[0]

        # Expired SSL certificates
        self.cur.execute("""
            SELECT COUNT(*)
            FROM ssl_certificates
            WHERE expires_at < NOW()
        """)
        stats['ssl_expired'] = self.cur.fetchone()[0]

        return stats

    def get_geoip_stats(self):
        """Get geographic distribution statistics"""
        stats = {}

        # Check if GeoIP tables have data
        self.cur.execute("SELECT COUNT(*) FROM geoip_locations")
        geoip_locations_count = self.cur.fetchone()[0]

        if geoip_locations_count == 0:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] WARNING: GeoIP data not imported yet")
            stats['countries'] = json.dumps({})
            stats['geoip_ready'] = False
            return stats

        # Geographic distribution (top 20 countries)
        try:
            self.cur.execute("""
                SELECT gl.country_name, COUNT(*) as cnt
                FROM domains d
                JOIN geoip_blocks gb ON d.ip_address <<= gb.network
                JOIN geoip_locations gl ON gb.geoname_id = gl.geoname_id
                WHERE d.is_active = true
                  AND gl.country_name IS NOT NULL
                GROUP BY gl.country_name
                ORDER BY cnt DESC
                LIMIT 20
            """)

            countries = {row['country_name']: row['cnt'] for row in self.cur.fetchall()}
            stats['countries'] = json.dumps(countries)
            stats['geoip_ready'] = True

        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] WARNING: GeoIP query failed: {e}")
            stats['countries'] = json.dumps({})
            stats['geoip_ready'] = False

        return stats

    def get_valuation_stats(self):
        """Get domain valuation statistics"""
        stats = {}

        # Check if valuation table exists
        self.cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'domain_valuations'
            )
        """)

        if not self.cur.fetchone()[0]:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: domain_valuations table not found")
            stats['total_valuations'] = 0
            stats['total_market_value'] = 0
            return stats

        # Total valuations
        try:
            self.cur.execute("SELECT COUNT(*) FROM domain_valuations")
            stats['total_valuations'] = self.cur.fetchone()[0]

            # Total market value
            self.cur.execute("SELECT COALESCE(SUM(estimated_value), 0) FROM domain_valuations")
            stats['total_market_value'] = self.cur.fetchone()[0]

        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] WARNING: Valuation query failed: {e}")
            stats['total_valuations'] = 0
            stats['total_market_value'] = 0

        return stats

    def populate_redis(self):
        """Gather all stats and populate Redis"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting Redis population...")

        all_stats = {}

        # Gather all statistics
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Querying domain stats...")
        all_stats.update(self.get_domain_stats())

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Querying email security stats...")
        all_stats.update(self.get_email_security_stats())

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Querying SSL stats...")
        all_stats.update(self.get_ssl_stats())

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Querying GeoIP stats...")
        all_stats.update(self.get_geoip_stats())

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Querying valuation stats...")
        all_stats.update(self.get_valuation_stats())

        # Add timestamp
        all_stats['last_update'] = datetime.utcnow().isoformat()
        all_stats['last_update_unix'] = int(datetime.utcnow().timestamp())

        # Populate Redis using pipeline for efficiency
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Writing to Redis...")
        pipe = self.redis_client.pipeline()

        for key, value in all_stats.items():
            redis_key = f'stats:{key}'
            pipe.set(redis_key, str(value))
            # Set TTL of 10 minutes (600 seconds) - cron runs every 5 minutes
            pipe.expire(redis_key, 600)

        # Also store as single hash for convenience
        pipe.delete('stats:all')
        pipe.hset('stats:all', mapping=all_stats)
        pipe.expire('stats:all', 600)

        # Execute pipeline
        pipe.execute()

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Redis updated with {len(all_stats)} keys")
        return all_stats

    def print_summary(self, stats):
        """Print summary of populated statistics"""
        print("\n" + "="*60)
        print("REDIS STATISTICS SUMMARY")
        print("="*60)
        print(f"\nDomains:")
        print(f"  Total Active: {stats.get('total_domains', 0):,}")
        print(f"  Added Today: {stats.get('domains_today', 0):,}")
        print(f"  Added This Week: {stats.get('domains_this_week', 0):,}")
        print(f"  Added This Month: {stats.get('domains_this_month', 0):,}")

        print(f"\nEmail Security ({stats.get('email_total', 0):,} domains checked):")
        print(f"  MX Records: {stats.get('email_mx', 0):,}")
        print(f"  SPF: {stats.get('email_spf', 0):,} ({stats.get('email_spf_pct', 0)}%)")
        print(f"  DMARC: {stats.get('email_dmarc', 0):,} ({stats.get('email_dmarc_pct', 0)}%)")
        print(f"  DKIM: {stats.get('email_dkim', 0):,} ({stats.get('email_dkim_pct', 0)}%)")
        print(f"  DANE/TLSA: {stats.get('email_dane', 0):,} ({stats.get('email_dane_pct', 0)}%)")
        print(f"  MTA-STS: {stats.get('email_mta_sts', 0):,} ({stats.get('email_mta_sts_pct', 0)}%)")

        print(f"\nSSL Certificates:")
        print(f"  Total: {stats.get('ssl_total', 0):,}")
        print(f"  Expiring Soon: {stats.get('ssl_expiring_soon', 0):,}")
        print(f"  Expired: {stats.get('ssl_expired', 0):,}")

        print(f"\nValuations:")
        print(f"  Total Valuations: {stats.get('total_valuations', 0):,}")
        print(f"  Total Market Value: ${stats.get('total_market_value', 0):,.2f}")

        if stats.get('geoip_ready'):
            countries = json.loads(stats.get('countries', '{}'))
            if countries:
                print(f"\nTop 5 Countries:")
                for i, (country, count) in enumerate(list(countries.items())[:5], 1):
                    print(f"  {i}. {country}: {count:,} domains")

        print(f"\nLast Updated: {stats.get('last_update', 'Unknown')}")
        print("="*60 + "\n")

    def close(self):
        """Close database and Redis connections"""
        self.cur.close()
        self.conn.close()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Connections closed")

def main():
    """Main execution"""
    if not DEPS_AVAILABLE:
        return 1

    try:
        populator = RedisStatsPopulator()
        stats = populator.populate_redis()
        populator.print_summary(stats)
        populator.close()
        return 0

    except Exception as e:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
