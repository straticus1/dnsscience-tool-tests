"""Database management for DNS Science - PostgreSQL Version"""
import psycopg2
import psycopg2.extras
import json
import os
from datetime import datetime
from contextlib import contextmanager

class Database:
    """PostgreSQL database operations wrapper"""

    def __init__(self):
        self.db_host = os.environ.get('DB_HOST', 'localhost')
        self.db_port = os.environ.get('DB_PORT', '5432')
        self.db_name = os.environ.get('DB_NAME', 'dnsscience')
        self.db_user = os.environ.get('DB_USER', 'dnsscience')
        self.db_password = os.environ.get('DB_PASSWORD', '')

    @contextmanager
    def get_connection(self):
        """Get database connection context manager"""
        conn = psycopg2.connect(
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
            user=self.db_user,
            password=self.db_password,
            cursor_factory=psycopg2.extras.RealDictCursor
        )
        try:
            yield conn
        finally:
            conn.close()

    def add_domain(self, domain_name, user_id=None):
        """Add a domain to track, return domain_id"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            try:
                cursor.execute(
                    "INSERT INTO domains (domain_name, created_by_user_id) VALUES (%s, %s) RETURNING id",
                    (domain_name.lower(), user_id)
                )
                domain_id = cursor.fetchone()['id']
                conn.commit()
            except psycopg2.IntegrityError:
                conn.rollback()
                # Domain already exists, get its ID
                cursor.execute(
                    "SELECT id FROM domains WHERE domain_name = %s",
                    (domain_name.lower(),)
                )
                domain_id = cursor.fetchone()['id']

            return domain_id

    def save_scan_result(self, domain_name, scan_data):
        """Save scan result to history"""
        domain_id = self.add_domain(domain_name)

        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO scan_history (
                    domain_id,
                    dnssec_enabled, dnssec_valid, dnssec_details,
                    spf_record, spf_valid, spf_details,
                    dkim_selectors, dkim_valid, dkim_details,
                    dmarc_record, dmarc_policy, dmarc_valid,
                    mta_sts_enabled, mta_sts_policy, mta_sts_details,
                    smtp_starttls_25, smtp_starttls_587, smtp_details,
                    scan_status, error_message
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                domain_id,
                scan_data.get('dnssec_enabled'),
                scan_data.get('dnssec_valid'),
                scan_data.get('dnssec_details'),
                scan_data.get('spf_record'),
                scan_data.get('spf_valid'),
                scan_data.get('spf_details'),
                json.dumps(scan_data.get('dkim_selectors', [])),
                scan_data.get('dkim_valid'),
                scan_data.get('dkim_details'),
                scan_data.get('dmarc_record'),
                scan_data.get('dmarc_policy'),
                scan_data.get('dmarc_valid'),
                scan_data.get('mta_sts_enabled'),
                scan_data.get('mta_sts_policy'),
                scan_data.get('mta_sts_details'),
                scan_data.get('smtp_starttls_25'),
                scan_data.get('smtp_starttls_587'),
                scan_data.get('smtp_details'),
                scan_data.get('scan_status', 'completed'),
                scan_data.get('error_message')
            ))

            conn.commit()

    def get_latest_scan(self, domain_name):
        """Get the latest scan result for a domain"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM latest_scans WHERE domain_name = %s
            """, (domain_name.lower(),))

            result = cursor.fetchone()
            return dict(result) if result else None

    def get_scan_history(self, domain_name, limit=100):
        """Get scan history for a domain"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT sh.* FROM scan_history sh
                JOIN domains d ON sh.domain_id = d.id
                WHERE d.domain_name = %s
                ORDER BY sh.scan_timestamp DESC
                LIMIT %s
            """, (domain_name.lower(), limit))

            results = cursor.fetchall()
            return [dict(row) for row in results]

    def search_domains(self, query):
        """Search domains by name"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM domains
                WHERE domain_name LIKE %s
                ORDER BY last_checked DESC
            """, (f"%{query}%",))

            results = cursor.fetchall()
            return [dict(row) for row in results]

    def get_all_domains(self, limit=100):
        """Get all tracked domains"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM domains
                ORDER BY last_checked DESC
                LIMIT %s
            """, (limit,))

            results = cursor.fetchall()
            return [dict(row) for row in results]

    def save_certificate_result(self, domain_name, cert_data):
        """Save SSL certificate data to history"""
        domain_id = self.add_domain(domain_name)

        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO certificate_history (
                    domain_id, port, service,
                    subject_cn, subject_o, subject_ou, subject_c, subject_st, subject_l,
                    issuer_cn, issuer_o, issuer_c,
                    sha1_fingerprint, sha256_fingerprint,
                    san, san_count,
                    not_before, not_after, days_until_expiry, is_expired,
                    tls_version, cipher_suite,
                    is_valid, validation_errors
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                cert_data.get('tls_version'),
                cert_data.get('cipher_suite'),
                cert_data.get('is_valid'),
                cert_data.get('validation_errors')
            ))

            conn.commit()

    def save_certificates_batch(self, domain_name, certificates):
        """Save multiple certificate results at once"""
        for cert in certificates:
            self.save_certificate_result(domain_name, cert)

    def get_latest_certificates(self, domain_name):
        """Get the latest certificates for a domain (one per port)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT ch.* FROM certificate_history ch
                JOIN domains d ON ch.domain_id = d.id
                WHERE d.domain_name = %s
                AND ch.id IN (
                    SELECT DISTINCT ON (domain_id, port) id
                    FROM certificate_history
                    WHERE domain_id = (SELECT id FROM domains WHERE domain_name = %s)
                    ORDER BY domain_id, port, scan_timestamp DESC
                )
                ORDER BY ch.port
            """, (domain_name.lower(), domain_name.lower()))

            results = cursor.fetchall()
            return [dict(row) for row in results]

    def get_certificate_history(self, domain_name, port=None, limit=100):
        """Get certificate history for a domain"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

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
            return [dict(row) for row in results]

    def get_expiring_certificates(self, days=30):
        """Get certificates expiring within N days"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM expiring_certificates
                WHERE days_until_expiry <= %s
            """, (days,))

            results = cursor.fetchall()
            return [dict(row) for row in results]

    def get_expired_certificates(self):
        """Get all expired certificates"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM expired_certificates")

            results = cursor.fetchall()
            return [dict(row) for row in results]

    def get_certificate_changes(self, domain_name=None, days=30):
        """Get certificate changes (drift detection)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            if domain_name:
                cursor.execute("""
                    SELECT d.domain_name, ch1.*, ch2.sha256_fingerprint as old_fingerprint
                    FROM certificate_history ch1
                    JOIN domains d ON ch1.domain_id = d.id
                    LEFT JOIN LATERAL (
                        SELECT sha256_fingerprint
                        FROM certificate_history
                        WHERE domain_id = ch1.domain_id
                          AND port = ch1.port
                          AND scan_timestamp < ch1.scan_timestamp
                        ORDER BY scan_timestamp DESC
                        LIMIT 1
                    ) ch2 ON true
                    WHERE d.domain_name = %s
                      AND ch1.scan_timestamp >= NOW() - INTERVAL '%s days'
                      AND ch1.sha256_fingerprint != ch2.sha256_fingerprint
                    ORDER BY ch1.scan_timestamp DESC
                """, (domain_name.lower(), days))
            else:
                cursor.execute("""
                    SELECT d.domain_name, ch1.*, ch2.sha256_fingerprint as old_fingerprint
                    FROM certificate_history ch1
                    JOIN domains d ON ch1.domain_id = d.id
                    LEFT JOIN LATERAL (
                        SELECT sha256_fingerprint
                        FROM certificate_history
                        WHERE domain_id = ch1.domain_id
                          AND port = ch1.port
                          AND scan_timestamp < ch1.scan_timestamp
                        ORDER BY scan_timestamp DESC
                        LIMIT 1
                    ) ch2 ON true
                    WHERE ch1.scan_timestamp >= NOW() - INTERVAL '%s days'
                      AND ch1.sha256_fingerprint != ch2.sha256_fingerprint
                    ORDER BY ch1.scan_timestamp DESC
                """, (days,))

            results = cursor.fetchall()
            return [dict(row) for row in results]
