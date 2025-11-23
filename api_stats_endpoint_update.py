"""
DNS Science - API Stats Endpoint Update Example
Add this code to /var/www/dnsscience/app.py

This provides dual-source statistics (Redis primary, SQL fallback)
with all email security metrics including DANE and MTA-STS
"""

# Add to imports section
import redis
import json
from datetime import datetime

# Initialize Redis client (add near other initializations)
try:
    redis_client = redis.Redis(
        host='localhost',
        port=6379,
        db=0,
        decode_responses=True,
        socket_connect_timeout=2
    )
    redis_client.ping()
    REDIS_AVAILABLE = True
except:
    redis_client = None
    REDIS_AVAILABLE = False

# Replace or update the /api/stats/live endpoint
@app.route('/api/stats/live')
def get_live_stats():
    """
    Get live statistics with Redis primary, SQL fallback
    Returns all domain, email security, SSL, and GeoIP statistics
    """
    try:
        # Try Redis first (fast path)
        if REDIS_AVAILABLE and redis_client.exists('stats:total_domains'):
            return jsonify({
                'total_domains': int(redis_client.get('stats:total_domains') or 0),
                'domains_today': int(redis_client.get('stats:domains_today') or 0),
                'domains_this_week': int(redis_client.get('stats:domains_this_week') or 0),
                'domains_this_month': int(redis_client.get('stats:domains_this_month') or 0),
                'email_security': {
                    'total': int(redis_client.get('stats:email_total') or 0),
                    'mx': int(redis_client.get('stats:email_mx') or 0),
                    'spf': int(redis_client.get('stats:email_spf') or 0),
                    'spf_pct': float(redis_client.get('stats:email_spf_pct') or 0),
                    'dmarc': int(redis_client.get('stats:email_dmarc') or 0),
                    'dmarc_pct': float(redis_client.get('stats:email_dmarc_pct') or 0),
                    'dkim': int(redis_client.get('stats:email_dkim') or 0),
                    'dkim_pct': float(redis_client.get('stats:email_dkim_pct') or 0),
                    'dane': int(redis_client.get('stats:email_dane') or 0),
                    'dane_pct': float(redis_client.get('stats:email_dane_pct') or 0),
                    'mta_sts': int(redis_client.get('stats:email_mta_sts') or 0),
                    'mta_sts_pct': float(redis_client.get('stats:email_mta_sts_pct') or 0),
                },
                'ssl_certificates': {
                    'total': int(redis_client.get('stats:ssl_total') or 0),
                    'expiring_soon': int(redis_client.get('stats:ssl_expiring_soon') or 0),
                    'expired': int(redis_client.get('stats:ssl_expired') or 0),
                },
                'valuations': {
                    'total': int(redis_client.get('stats:total_valuations') or 0),
                    'total_value': float(redis_client.get('stats:total_market_value') or 0),
                },
                'countries': json.loads(redis_client.get('stats:countries') or '{}'),
                'geoip_ready': redis_client.get('stats:geoip_ready') == 'True',
                'last_update': redis_client.get('stats:last_update'),
                'source': 'redis'
            })
    except Exception as e:
        app.logger.warning(f"Redis unavailable, falling back to SQL: {e}")

    # Fallback to SQL (slower but always works)
    return jsonify(get_stats_from_sql())


def get_stats_from_sql():
    """
    Query statistics directly from PostgreSQL
    Used as fallback when Redis is unavailable
    """
    stats = {
        'total_domains': 0,
        'domains_today': 0,
        'domains_this_week': 0,
        'domains_this_month': 0,
        'email_security': {},
        'ssl_certificates': {},
        'valuations': {},
        'countries': {},
        'geoip_ready': False,
        'last_update': datetime.utcnow().isoformat(),
        'source': 'sql'
    }

    try:
        conn = db.get_db_connection()
        cur = conn.cursor()

        # Domain stats
        cur.execute("SELECT COUNT(*) FROM domains WHERE is_active = true")
        stats['total_domains'] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM domains WHERE DATE(created_at) = CURRENT_DATE")
        stats['domains_today'] = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM domains
            WHERE created_at >= DATE_TRUNC('week', CURRENT_DATE)
        """)
        stats['domains_this_week'] = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM domains
            WHERE created_at >= DATE_TRUNC('month', CURRENT_DATE)
        """)
        stats['domains_this_month'] = cur.fetchone()[0]

        # Email security stats
        cur.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(CASE WHEN has_mx = true THEN 1 END) as mx,
                COUNT(CASE WHEN has_spf = true THEN 1 END) as spf,
                COUNT(CASE WHEN has_dmarc = true THEN 1 END) as dmarc,
                COUNT(CASE WHEN has_dkim = true THEN 1 END) as dkim,
                COUNT(CASE WHEN has_dane = true THEN 1 END) as dane,
                COUNT(CASE WHEN has_mta_sts = true THEN 1 END) as mta_sts
            FROM email_security_records
        """)
        row = cur.fetchone()
        total = row[0] or 1  # Avoid division by zero
        stats['email_security'] = {
            'total': row[0],
            'mx': row[1],
            'spf': row[2],
            'spf_pct': round(100.0 * row[2] / total, 2),
            'dmarc': row[3],
            'dmarc_pct': round(100.0 * row[3] / total, 2),
            'dkim': row[4],
            'dkim_pct': round(100.0 * row[4] / total, 2),
            'dane': row[5],
            'dane_pct': round(100.0 * row[5] / total, 2),
            'mta_sts': row[6],
            'mta_sts_pct': round(100.0 * row[6] / total, 2),
        }

        # SSL certificate stats
        cur.execute("SELECT COUNT(*) FROM ssl_certificates")
        stats['ssl_certificates']['total'] = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM ssl_certificates
            WHERE expires_at BETWEEN NOW() AND NOW() + INTERVAL '30 days'
        """)
        stats['ssl_certificates']['expiring_soon'] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM ssl_certificates WHERE expires_at < NOW()")
        stats['ssl_certificates']['expired'] = cur.fetchone()[0]

        # Valuation stats (if table exists)
        try:
            cur.execute("SELECT COUNT(*), COALESCE(SUM(estimated_value), 0) FROM domain_valuations")
            row = cur.fetchone()
            stats['valuations'] = {
                'total': row[0],
                'total_value': float(row[1])
            }
        except:
            stats['valuations'] = {'total': 0, 'total_value': 0}

        # GeoIP stats (if data exists)
        try:
            cur.execute("""
                SELECT gl.country_name, COUNT(*) as cnt
                FROM domains d
                JOIN geoip_blocks gb ON d.ip_address <<= gb.network
                JOIN geoip_locations gl ON gb.geoname_id = gl.geoname_id
                WHERE d.is_active = true AND gl.country_name IS NOT NULL
                GROUP BY gl.country_name
                ORDER BY cnt DESC
                LIMIT 20
            """)
            stats['countries'] = {row[0]: row[1] for row in cur.fetchall()}
            stats['geoip_ready'] = len(stats['countries']) > 0
        except:
            stats['countries'] = {}
            stats['geoip_ready'] = False

        cur.close()
        conn.close()

    except Exception as e:
        app.logger.error(f"Error querying stats from SQL: {e}")

    return stats


# Add backward compatibility endpoint
@app.route('/api/stats')
def get_stats_legacy():
    """Legacy stats endpoint - redirects to /api/stats/live"""
    return get_live_stats()
