"""Database management for DNS Science Platform - PostgreSQL Edition"""
import psycopg2
import psycopg2.extras
import psycopg2.pool
import json
import os
from datetime import datetime
from config import Config

class Database:
    """PostgreSQL database operations wrapper"""

    _pool = None

    def __init__(self, db_config=None):
        """
        Initialize database connection pool.

        Args:
            db_config: Optional dict with connection parameters
                      {host, port, dbname, user, password}
        """
        if db_config:
            self.db_config = db_config
        else:
            # Use environment variables - NO DEFAULTS for credentials
            self.db_config = {
                'host': os.getenv('DB_HOST'),
                'port': os.getenv('DB_PORT', '5432'),
                'dbname': os.getenv('DB_NAME', 'dnsscience'),
                'user': os.getenv('DB_USER'),
                'password': os.getenv('DB_PASS')
            }

            # Validate required credentials
            if not self.db_config['host']:
                raise ValueError("DB_HOST environment variable is required")
            if not self.db_config['user']:
                raise ValueError("DB_USER environment variable is required")
            if not self.db_config['password']:
                raise ValueError("DB_PASS environment variable is required")

        # Initialize connection pool
        if Database._pool is None:
            Database._pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=2,
                maxconn=20,
                host=self.db_config['host'],
                port=self.db_config['port'],
                dbname=self.db_config['dbname'],
                user=self.db_config['user'],
                password=self.db_config['password'],
                connect_timeout=10
            )

    def get_connection(self):
        """Get database connection from pool"""
        return Database._pool.getconn()

    @staticmethod
    def serialize_row(row_dict):
        """
        Convert database row to JSON-serializable dict.
        Handles datetime objects by converting them to ISO format strings.

        Args:
            row_dict: Dictionary from database cursor (RealDictCursor)

        Returns:
            Dictionary with datetime objects converted to strings
        """
        if not row_dict:
            return None

        result = {}
        for key, value in row_dict.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            else:
                result[key] = value
        return result

    def return_connection(self, conn):
        """Return connection to pool"""
        Database._pool.putconn(conn)

    def add_domain(self, domain_name):
        """Add a domain to track, return domain_id"""
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO domains (domain_name, first_checked)
                    VALUES (%s, NOW())
                    ON CONFLICT (domain_name) DO UPDATE SET last_checked = NOW()
                    RETURNING id
                    """,
                    (domain_name.lower(),)
                )
                domain_id = cursor.fetchone()[0]
                conn.commit()
                return domain_id
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.return_connection(conn)

    def save_scan_result(self, domain_name, scan_data):
        """Save scan result to history using JSONB schema"""
        domain_id = self.add_domain(domain_name)

        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                # Store all scan data in JSONB column, pull out commonly queried fields
                cursor.execute("""
                    INSERT INTO scan_history (
                        domain_id,
                        dnssec_enabled,
                        spf_record,
                        dmarc_record,
                        scan_data,
                        scan_status
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s
                    )
                """, (
                    domain_id,
                    scan_data.get('dnssec_enabled'),
                    scan_data.get('spf_record'),
                    scan_data.get('dmarc_record'),
                    json.dumps(scan_data),
                    scan_data.get('scan_status', 'completed')
                ))

                # Update last_checked timestamp and increment scan_count
                cursor.execute(
                    "UPDATE domains SET last_checked = NOW(), scan_count = COALESCE(scan_count, 0) + 1 WHERE id = %s",
                    (domain_id,)
                )

                conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.return_connection(conn)

    def get_latest_scan(self, domain_name):
        """Get the latest scan result for a domain"""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT
                        sh.id,
                        d.domain_name,
                        sh.dnssec_enabled,
                        sh.spf_record,
                        sh.dmarc_record,
                        sh.scan_data,
                        sh.scan_status,
                        sh.scan_timestamp as scanned_at
                    FROM scan_history sh
                    JOIN domains d ON sh.domain_id = d.id
                    WHERE d.domain_name = %s
                    ORDER BY sh.scan_timestamp DESC
                    LIMIT 1
                """, (domain_name.lower(),))

                result = cursor.fetchone()
                if result:
                    result_dict = self.serialize_row(dict(result))
                    # Merge JSONB data into the result
                    if result_dict.get('scan_data'):
                        scan_data = result_dict.pop('scan_data')
                        result_dict.update(scan_data)
                    return result_dict
                return None
        finally:
            self.return_connection(conn)

    def get_scan_history(self, domain_name, limit=100):
        """Get scan history for a domain"""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT sh.* FROM scan_history sh
                    JOIN domains d ON sh.domain_id = d.id
                    WHERE d.domain_name = %s
                    ORDER BY sh.scan_timestamp DESC
                    LIMIT %s
                """, (domain_name.lower(), limit))

                results = cursor.fetchall()
                history = []
                for row in results:
                    row_dict = self.serialize_row(dict(row))
                    # Merge JSONB data
                    if row_dict.get('scan_data'):
                        scan_data = row_dict.pop('scan_data')
                        row_dict.update(scan_data)
                    history.append(row_dict)
                return history
        finally:
            self.return_connection(conn)

    def search_domains(self, query):
        """Search domains by name"""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM domains
                    WHERE domain_name ILIKE %s
                    ORDER BY last_checked DESC
                """, (f"%{query}%",))

                results = cursor.fetchall()
                return [self.serialize_row(dict(row)) for row in results]
        finally:
            self.return_connection(conn)

    def get_all_domains(self, limit=100):
        """Get all tracked domains"""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM domains
                    ORDER BY last_checked DESC
                    LIMIT %s
                """, (limit,))

                results = cursor.fetchall()
                return [self.serialize_row(dict(row)) for row in results]
        finally:
            self.return_connection(conn)

    def save_certificate_result(self, domain_name, cert_data):
        """
        Save SSL certificate data to history.

        Args:
            domain_name: Domain name
            cert_data: Dictionary with certificate information
        """
        domain_id = self.add_domain(domain_name)

        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO certificate_history (
                        domain_id, port, service,
                        subject_cn, subject_o, subject_ou, subject_c, subject_st, subject_l,
                        issuer_cn, issuer_o, issuer_c,
                        sha1_fingerprint, sha256_fingerprint,
                        san, san_count,
                        not_before, not_after, days_until_expiry, is_expired,
                        serial_number, version, cert_pem
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s
                    )
                """, (
                    domain_id,
                    cert_data.get('port'),
                    cert_data.get('service'),
                    cert_data.get('subject_cn'),
                    cert_data.get('subject_o'),
                    cert_data.get('subject_ou'),
                    cert_data.get('subject_c'),
                    cert_data.get('subject_st'),
                    cert_data.get('subject_l'),
                    cert_data.get('issuer_cn'),
                    cert_data.get('issuer_o'),
                    cert_data.get('issuer_c'),
                    cert_data.get('sha1_fingerprint'),
                    cert_data.get('sha256_fingerprint'),
                    json.dumps(cert_data.get('san', [])),
                    cert_data.get('san_count', 0),
                    cert_data.get('not_before'),
                    cert_data.get('not_after'),
                    cert_data.get('days_until_expiry'),
                    cert_data.get('is_expired'),
                    cert_data.get('serial_number'),
                    cert_data.get('version'),
                    cert_data.get('cert_pem')
                ))

                conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.return_connection(conn)

    def save_certificates_batch(self, domain_name, certificates):
        """
        Save multiple certificate results at once.

        Args:
            domain_name: Domain name
            certificates: List of certificate dictionaries
        """
        for cert in certificates:
            self.save_certificate_result(domain_name, cert)

    def get_latest_certificates(self, domain_name):
        """Get the latest certificates for a domain (one per port)"""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM latest_certificates
                    WHERE domain_name = %s
                    ORDER BY port
                """, (domain_name.lower(),))

                results = cursor.fetchall()
                certs = [dict(row) for row in results]

                # Parse SAN JSON
                for cert in certs:
                    if cert.get('san'):
                        try:
                            cert['san'] = json.loads(cert['san'])
                        except:
                            cert['san'] = []

                return certs
        finally:
            self.return_connection(conn)

    def get_certificate_history(self, domain_name, port=None, limit=100):
        """
        Get certificate history for a domain.

        Args:
            domain_name: Domain to query
            port: Optional port filter
            limit: Max results to return
        """
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                if port:
                    cursor.execute("""
                        SELECT ch.* FROM certificate_history ch
                        JOIN domains d ON ch.domain_id = d.id
                        WHERE d.domain_name = %s AND ch.port = %s
                        ORDER BY ch.scan_timestamp DESC
                        LIMIT %s
                    """, (domain_name.lower(), port, limit))
                else:
                    cursor.execute("""
                        SELECT ch.* FROM certificate_history ch
                        JOIN domains d ON ch.domain_id = d.id
                        WHERE d.domain_name = %s
                        ORDER BY ch.scan_timestamp DESC
                        LIMIT %s
                    """, (domain_name.lower(), limit))

                results = cursor.fetchall()
                certs = [dict(row) for row in results]

                # Parse SAN JSON
                for cert in certs:
                    if cert.get('san'):
                        try:
                            cert['san'] = json.loads(cert['san'])
                        except:
                            cert['san'] = []

                return certs
        finally:
            self.return_connection(conn)

    def get_expiring_certificates(self, days=30):
        """Get certificates expiring within N days"""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM expiring_certificates
                    WHERE days_until_expiry <= %s
                """, (days,))

                results = cursor.fetchall()
                return [dict(row) for row in results]
        finally:
            self.return_connection(conn)

    def get_expired_certificates(self):
        """Get all expired certificates"""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM expired_certificates")
                results = cursor.fetchall()
                return [dict(row) for row in results]
        finally:
            self.return_connection(conn)

    def get_certificate_changes(self, domain_name=None, days=30):
        """
        Get certificate changes (drift detection).

        Args:
            domain_name: Optional domain filter
            days: Look back this many days
        """
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                if domain_name:
                    cursor.execute("""
                        SELECT * FROM certificate_changes
                        WHERE domain_name = %s
                          AND change_timestamp >= NOW() - INTERVAL '%s days'
                        ORDER BY change_timestamp DESC
                    """, (domain_name.lower(), days))
                else:
                    cursor.execute("""
                        SELECT * FROM certificate_changes
                        WHERE change_timestamp >= NOW() - INTERVAL '%s days'
                        ORDER BY change_timestamp DESC
                    """, (days,))

                results = cursor.fetchall()
                return [dict(row) for row in results]
        finally:
            self.return_connection(conn)

    def cleanup_old_certificates(self, days=1825):
        """
        Delete certificate history older than specified days (default: 5 years = 1825 days).

        Args:
            days: Delete certificates older than this many days
        """
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    DELETE FROM certificate_history
                    WHERE scan_timestamp < NOW() - INTERVAL '%s days'
                """, (days,))

                deleted_count = cursor.rowcount
                conn.commit()
                return deleted_count
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.return_connection(conn)

    def get_live_statistics(self):
        """
        Get live platform statistics for dashboard display.

        Returns:
            dict: Platform statistics
        """
        conn = self.get_connection()
        # Ensure we start with a clean transaction
        conn.rollback()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                # Get total domains
                cursor.execute("SELECT COUNT(*) as count FROM domains")
                total_domains = cursor.fetchone()['count']

                # Get SSL certificates tracked (if table exists)
                try:
                    cursor.execute("""
                        SELECT COUNT(DISTINCT domain_id) as count
                        FROM certificate_history
                    """)
                    ssl_certificates = cursor.fetchone()['count']
                except Exception as e:
                    print(f"Warning: Could not count certificates: {e}")
                    ssl_certificates = 0
                    conn.rollback()  # Rollback any failed transaction

                # Get email records (domains with SPF or DMARC in JSONB)
                cursor.execute("""
                    SELECT COUNT(DISTINCT d.id) as count
                    FROM domains d
                    JOIN scan_history sh ON d.id = sh.domain_id
                    WHERE sh.spf_record IS NOT NULL
                       OR sh.dmarc_record IS NOT NULL
                """)
                email_records = cursor.fetchone()['count']

                # Get domains being monitored for drift (have historical scans)
                cursor.execute("""
                    SELECT COUNT(DISTINCT domain_id) as count
                    FROM scan_history
                """)
                drift_monitoring = cursor.fetchone()['count']

                # Get unique IPs tracked (if table exists)
                try:
                    cursor.execute("""
                        SELECT COUNT(DISTINCT ip_address) as count
                        FROM threat_intelligence
                        WHERE ip_address IS NOT NULL
                    """)
                    ips_tracked = cursor.fetchone()['count']
                except Exception as e:
                    print(f"Warning: Could not count IPs: {e}")
                    ips_tracked = 0
                    conn.rollback()  # Rollback any failed transaction

                # Get timestamp
                cursor.execute("SELECT NOW() as ts")
                last_updated = cursor.fetchone()['ts'].isoformat()

                return {
                    'total_domains': total_domains,
                    'ssl_certificates': ssl_certificates,
                    'email_records': email_records,
                    'drift_monitoring': drift_monitoring,
                    'ips_tracked': ips_tracked,
                    'active_feeds': 20,
                    'last_updated': last_updated
                }
        finally:
            self.return_connection(conn)

    def get_recent_threats(self, limit=50, severity=None):
        """
        Get recent threat intelligence detections.

        Args:
            limit: Maximum number of threats to return
            severity: Optional severity filter (critical, high, medium, low)

        Returns:
            list: Recent threat detections
        """
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                if severity:
                    cursor.execute("""
                        SELECT
                            id,
                            domain_name as domain,
                            ip_address as ip,
                            threat_type,
                            severity,
                            source,
                            detected_at,
                            description
                        FROM threat_intelligence
                        WHERE severity = %s
                        ORDER BY detected_at DESC
                        LIMIT %s
                    """, (severity, limit))
                else:
                    cursor.execute("""
                        SELECT
                            id,
                            domain_name as domain,
                            ip_address as ip,
                            threat_type,
                            severity,
                            source,
                            detected_at,
                            description
                        FROM threat_intelligence
                        ORDER BY detected_at DESC
                        LIMIT %s
                    """, (limit,))

                results = cursor.fetchall()
                return [dict(row) for row in results]
        finally:
            self.return_connection(conn)

    def get_current_timestamp(self):
        """Get current database timestamp"""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT NOW() as ts")
                return cursor.fetchone()['ts'].isoformat()
        finally:
            self.return_connection(conn)

    def get_dashboard_statistics(self):
        """Get comprehensive dashboard statistics"""
        return self.get_live_statistics()

    def get_platform_stats(self):
        """Alias for get_live_statistics() - used by GraphQL API"""
        stats = self.get_live_statistics()
        # Add aliases for GraphQL compatibility
        return {
            'total_domains': stats.get('total_domains', 0),
            'total_ip_scans': stats.get('ips_tracked', 0),
            'dnssec_enabled': 0,  # TODO: Add DNSSEC count
            'ssl_valid': stats.get('ssl_certificates', 0),
            'total_users': 0,  # TODO: Add user count
            'ssl_certificates': stats.get('ssl_certificates', 0),
            'email_records': stats.get('email_records', 0),
            'drift_monitoring': stats.get('drift_monitoring', 0),
            'ips_tracked': stats.get('ips_tracked', 0),
            'active_feeds': stats.get('active_feeds', 20),
            'last_updated': stats.get('last_updated')
        }

    def get_domain_id(self, domain_name):
        """
        Get the domain ID for a given domain name.
        If domain doesn't exist, returns None.
        """
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT id FROM domains WHERE domain_name = %s
                """, (domain_name.lower(),))

                result = cursor.fetchone()
                return result['id'] if result else None
        finally:
            self.return_connection(conn)

    def save_domain_valuation(self, domain_name, valuation_data):
        """
        Save domain valuation result.

        Args:
            domain_name: Domain name
            valuation_data: Dictionary from DomainValuationEngine.estimate_value()
        """
        domain_id = self.add_domain(domain_name)

        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                # Set expiration to 30 days from now (valuations age)
                cursor.execute("""
                    INSERT INTO domain_valuations (
                        domain_id,
                        estimated_value_low,
                        estimated_value_mid,
                        estimated_value_high,
                        length_score,
                        tld_score,
                        age_score,
                        activity_score,
                        keyword_score,
                        overall_score,
                        valuation_method,
                        algorithm_version,
                        factors,
                        expires_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        NOW() + INTERVAL '30 days'
                    )
                """, (
                    domain_id,
                    valuation_data['estimated_value_low'],
                    valuation_data['estimated_value_mid'],
                    valuation_data['estimated_value_high'],
                    valuation_data['scores']['length_score'],
                    valuation_data['scores']['tld_score'],
                    valuation_data['scores']['age_score'],
                    valuation_data['scores']['activity_score'],
                    valuation_data['scores']['keyword_score'],
                    valuation_data['overall_score'],
                    valuation_data['valuation_method'],
                    valuation_data['algorithm_version'],
                    json.dumps(valuation_data['factors'])
                ))

                conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.return_connection(conn)

    def get_latest_valuation(self, domain_name):
        """
        Get the latest non-expired valuation for a domain.

        Args:
            domain_name: Domain to query

        Returns:
            Dictionary with valuation data or None
        """
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM latest_domain_valuations
                    WHERE domain_name = %s
                    LIMIT 1
                """, (domain_name.lower(),))

                result = cursor.fetchone()
                if result:
                    valuation = dict(result)
                    # Parse factors JSON
                    if valuation.get('factors'):
                        try:
                            valuation['factors'] = json.loads(valuation['factors']) if isinstance(valuation['factors'], str) else valuation['factors']
                        except:
                            pass
                    # Convert Decimal to float for JSON serialization
                    for key in ['estimated_value_low', 'estimated_value_mid', 'estimated_value_high']:
                        if key in valuation and valuation[key] is not None:
                            valuation[key] = float(valuation[key])
                    return valuation
                return None
        finally:
            self.return_connection(conn)

    def get_valuation_history(self, domain_name, limit=10):
        """
        Get valuation history for a domain.

        Args:
            domain_name: Domain to query
            limit: Max results to return

        Returns:
            List of valuation dictionaries
        """
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT dv.* FROM domain_valuations dv
                    JOIN domains d ON dv.domain_id = d.id
                    WHERE d.domain_name = %s
                    ORDER BY dv.created_at DESC
                    LIMIT %s
                """, (domain_name.lower(), limit))

                results = cursor.fetchall()
                valuations = []
                for row in results:
                    val = dict(row)
                    # Parse factors JSON
                    if val.get('factors'):
                        try:
                            val['factors'] = json.loads(val['factors']) if isinstance(val['factors'], str) else val['factors']
                        except:
                            pass
                    # Convert Decimal to float for JSON serialization
                    for key in ['estimated_value_low', 'estimated_value_mid', 'estimated_value_high']:
                        if key in val and val[key] is not None:
                            val[key] = float(val[key])
                    valuations.append(val)
                return valuations
        finally:
            self.return_connection(conn)

    def get_top_valued_domains(self, limit=100):
        """
        Get domains with highest valuations.

        Args:
            limit: Max results to return

        Returns:
            List of domains with their latest valuations
        """
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM latest_domain_valuations
                    ORDER BY overall_score DESC, estimated_value_mid DESC
                    LIMIT %s
                """, (limit,))

                results = cursor.fetchall()
                valuations = []
                for row in results:
                    val = dict(row)
                    # Convert Decimal to float for JSON serialization
                    for key in ['estimated_value_low', 'estimated_value_mid', 'estimated_value_high']:
                        if key in val and val[key] is not None:
                            val[key] = float(val[key])
                    valuations.append(val)
                return valuations
        finally:
            self.return_connection(conn)

    # ============================================================================
    # IP Intelligence Methods
    # ============================================================================

    def save_ip_scan(self, ip_address, scan_data):
        """
        Save IP scan result to database.

        Args:
            ip_address: IP address that was scanned
            scan_data: Dictionary from IPIntelligenceEngine.scan_ip()
        """
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                # Extract data from scan_data
                geo = scan_data.get('geolocation', {})
                net = scan_data.get('network', {})
                bgp = scan_data.get('bgp', {})
                rep = scan_data.get('reputation', {})
                whois = scan_data.get('whois', {})
                ptr = scan_data.get('reverse_dns', {})

                cursor.execute("""
                    INSERT INTO ip_scans (
                        ip_address, scan_timestamp,
                        country, region, city, latitude, longitude, timezone, postal_code,
                        asn, asn_name, isp, organization, usage_type,
                        is_hosting, is_vpn, is_proxy, is_tor, is_mobile, is_datacenter,
                        abuse_confidence, total_reports, last_report_date, is_whitelisted, threat_categories,
                        in_spamhaus, in_sorbs, in_barracuda, in_spamcop, rbl_hit_count, rbl_details,
                        prefix, origin_asn, as_path, is_announced, rpki_status,
                        whois_registry, whois_net_range, whois_net_name, whois_description,
                        whois_country, whois_abuse_contact,
                        ptr_record, ptr_valid,
                        full_data, scan_duration_ms, api_errors, data_sources
                    ) VALUES (
                        %s, NOW(),
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s,
                        %s, %s, %s, %s
                    )
                """, (
                    ip_address,
                    # Geolocation
                    geo.get('country'), geo.get('region'), geo.get('city'),
                    geo.get('coordinates', {}).get('latitude'),
                    geo.get('coordinates', {}).get('longitude'),
                    geo.get('timezone'), geo.get('postal_code'),
                    # Network
                    net.get('asn'), net.get('asn_name'), rep.get('isp'), net.get('organization'), rep.get('usage_type'),
                    # Classification
                    net.get('is_hosting', False), net.get('is_vpn', False), net.get('is_proxy', False),
                    net.get('is_tor', False), net.get('is_mobile', False), False,
                    # Reputation
                    rep.get('abuse_confidence', 0), rep.get('total_reports', 0),
                    rep.get('last_reported_at'), rep.get('is_whitelisted', False),
                    rep.get('threat_categories'),
                    # RBL
                    rep.get('in_spamhaus', False), rep.get('in_sorbs', False),
                    rep.get('in_barracuda', False), rep.get('in_spamcop', False),
                    rep.get('blacklists', {}).get('hit_count', 0),
                    json.dumps(rep.get('blacklists', {}).get('details', {})),
                    # BGP
                    bgp.get('prefix'), bgp.get('origin_asn'), bgp.get('path'),
                    bgp.get('is_announced'), bgp.get('rpki_status'),
                    # WHOIS
                    'RIPE', whois.get('net_range'), whois.get('net_name'),
                    whois.get('description'), whois.get('country'), whois.get('abuse_contact'),
                    # PTR
                    ptr.get('ptr_record'), ptr.get('has_ptr', False),
                    # Metadata
                    json.dumps(scan_data), scan_data.get('scan_duration_ms'),
                    json.dumps(scan_data.get('errors', [])), scan_data.get('data_sources')
                ))

                conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.return_connection(conn)

    def _convert_decimals(self, obj):
        """
        Recursively convert Decimal objects to float for JSON serialization.

        Args:
            obj: Object to convert (dict, list, or value)

        Returns:
            Object with Decimals converted to floats
        """
        from decimal import Decimal

        if isinstance(obj, dict):
            return {k: self._convert_decimals(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_decimals(item) for item in obj]
        elif isinstance(obj, Decimal):
            return float(obj)
        else:
            return obj

    def get_latest_ip_scan(self, ip_address, max_age_hours=24):
        """
        Get the latest IP scan if it's not too old.

        Args:
            ip_address: IP address to query
            max_age_hours: Maximum age of cached scan in hours

        Returns:
            Dictionary with scan data or None
        """
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM ip_scans
                    WHERE ip_address = %s
                      AND scan_timestamp > NOW() - INTERVAL '%s hours'
                    ORDER BY scan_timestamp DESC
                    LIMIT 1
                """, (ip_address, max_age_hours))

                result = cursor.fetchone()
                if result:
                    scan = dict(result)
                    # Parse JSON fields
                    for field in ['full_data', 'rbl_details', 'api_errors']:
                        if scan.get(field):
                            try:
                                scan[field] = json.loads(scan[field]) if isinstance(scan[field], str) else scan[field]
                            except:
                                pass
                    # Convert Decimal types to float for JSON serialization
                    scan = self._convert_decimals(scan)
                    return scan
                return None
        finally:
            self.return_connection(conn)

    def get_ip_scan_history(self, ip_address, limit=10):
        """
        Get scan history for an IP.

        Args:
            ip_address: IP address to query
            limit: Maximum results to return

        Returns:
            List of scan dictionaries
        """
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM ip_scans
                    WHERE ip_address = %s
                    ORDER BY scan_timestamp DESC
                    LIMIT %s
                """, (ip_address, limit))

                results = cursor.fetchall()
                scans = []
                for row in results:
                    scan = dict(row)
                    # Parse JSON fields
                    for field in ['full_data', 'rbl_details', 'api_errors']:
                        if scan.get(field):
                            try:
                                scan[field] = json.loads(scan[field]) if isinstance(scan[field], str) else scan[field]
                            except:
                                pass
                    scans.append(scan)
                return scans
        finally:
            self.return_connection(conn)

    def get_high_risk_ips(self, limit=100, min_confidence=75):
        """
        Get high-risk IPs based on abuse confidence.

        Args:
            limit: Maximum results
            min_confidence: Minimum abuse confidence score

        Returns:
            List of high-risk IP dictionaries
        """
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM high_risk_ips
                    WHERE abuse_confidence >= %s
                    ORDER BY abuse_confidence DESC, rbl_hit_count DESC
                    LIMIT %s
                """, (min_confidence, limit))

                return [dict(row) for row in cursor.fetchall()]
        finally:
            self.return_connection(conn)

    def save_asn_info(self, asn, asn_data):
        """
        Save or update AS information.

        Args:
            asn: AS number
            asn_data: Dictionary with AS information
        """
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO autonomous_systems (
                        asn, as_name, organization, country,
                        asn_data, last_updated
                    ) VALUES (%s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (asn) DO UPDATE SET
                        as_name = EXCLUDED.as_name,
                        organization = EXCLUDED.organization,
                        country = EXCLUDED.country,
                        asn_data = EXCLUDED.asn_data,
                        last_updated = NOW()
                """, (
                    asn,
                    asn_data.get('as_name'),
                    asn_data.get('organization'),
                    asn_data.get('country'),
                    json.dumps(asn_data)
                ))

                conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.return_connection(conn)

    def get_asn_info(self, asn):
        """
        Get AS information from database.

        Args:
            asn: AS number

        Returns:
            Dictionary with AS data or None
        """
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM autonomous_systems
                    WHERE asn = %s
                """, (asn,))

                result = cursor.fetchone()
                if result:
                    asn_info = dict(result)
                    if asn_info.get('asn_data'):
                        try:
                            asn_info['asn_data'] = json.loads(asn_info['asn_data']) if isinstance(asn_info['asn_data'], str) else asn_info['asn_data']
                        except:
                            pass
                    return asn_info
                return None
        finally:
            self.return_connection(conn)

    def close_all_connections(self):
        """Close all connections in pool (use for cleanup)"""
        if Database._pool:
            Database._pool.closeall()
            Database._pool = None
