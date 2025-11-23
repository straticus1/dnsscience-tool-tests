#!/usr/bin/env python3
"""
DNS Science - SSL Certificate Monitoring Daemon
Monitors SSL certificates for expiration and changes
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from base_daemon import BaseDaemon
import ssl
import socket
from datetime import datetime, timedelta
from OpenSSL import crypto

class SSLMonitorDaemon(BaseDaemon):
    """Daemon for SSL certificate monitoring"""

    def __init__(self):
        super().__init__('dnsscience_ssl_monitord')

    def process_iteration(self):
        """Monitor SSL certificates"""
        work_done = False

        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Get domains with expiring certificates (within 30 days)
            cursor.execute("""
                SELECT DISTINCT d.id, d.domain_name, ch.expires_at
                FROM domains d
                JOIN certificate_history ch ON d.id = ch.domain_id
                WHERE d.is_active = TRUE
                AND ch.expires_at IS NOT NULL
                AND ch.expires_at < NOW() + INTERVAL '30 days'
                AND ch.expires_at > NOW()
                ORDER BY ch.expires_at ASC
                LIMIT 50
            """)

            expiring_certs = cursor.fetchall()

            for domain_id, domain_name, expires_at in expiring_certs:
                days_until_expiry = (expires_at - datetime.utcnow()).days

                self.logger.warning(
                    f"Certificate expiring soon: {domain_name} "
                    f"({days_until_expiry} days)"
                )

                # Create alert
                cursor.execute("""
                    INSERT INTO ssl_alerts
                    (domain_id, alert_type, severity, message, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (domain_id, alert_type) DO UPDATE
                    SET message = EXCLUDED.message,
                        created_at = EXCLUDED.created_at
                """, (
                    domain_id,
                    'certificate_expiring',
                    'high' if days_until_expiry < 7 else 'medium',
                    f"Certificate expires in {days_until_expiry} days",
                    datetime.utcnow()
                ))

                work_done = True

            # Get domains that need SSL checks
            cursor.execute("""
                SELECT d.id, d.domain_name
                FROM domains d
                LEFT JOIN certificate_history ch ON d.id = ch.domain_id
                WHERE d.is_active = TRUE
                AND (ch.scan_timestamp IS NULL
                     OR ch.scan_timestamp < NOW() - INTERVAL '7 days')
                LIMIT 20
            """)

            domains = cursor.fetchall()

            for domain_id, domain_name in domains:
                try:
                    cert_info = self.get_ssl_certificate(domain_name)

                    if cert_info:
                        cursor.execute("""
                            INSERT INTO certificate_history
                            (domain_id, scan_timestamp, port, service,
                             subject_cn, issuer_cn, valid_from, expires_at,
                             serial_number, signature_algorithm, key_size)
                            VALUES (%s, %s, 443, 'https', %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            domain_id,
                            datetime.utcnow(),
                            cert_info['subject_cn'],
                            cert_info['issuer_cn'],
                            cert_info['valid_from'],
                            cert_info['expires_at'],
                            cert_info['serial_number'],
                            cert_info['signature_algorithm'],
                            cert_info['key_size']
                        ))

                        conn.commit()
                        work_done = True

                except Exception as e:
                    self.logger.error(f"Error checking SSL for {domain_name}: {e}")
                    conn.rollback()

            cursor.close()

        except Exception as e:
            self.logger.error(f"Error in SSL monitoring: {e}")

        return work_done

    def get_ssl_certificate(self, domain_name, port=443):
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain_name, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)

                    return {
                        'subject_cn': cert.get_subject().CN,
                        'issuer_cn': cert.get_issuer().CN,
                        'valid_from': datetime.strptime(
                            cert.get_notBefore().decode('ascii'),
                            '%Y%m%d%H%M%SZ'
                        ),
                        'expires_at': datetime.strptime(
                            cert.get_notAfter().decode('ascii'),
                            '%Y%m%d%H%M%SZ'
                        ),
                        'serial_number': str(cert.get_serial_number()),
                        'signature_algorithm': cert.get_signature_algorithm().decode('ascii'),
                        'key_size': cert.get_pubkey().bits()
                    }
        except Exception as e:
            self.logger.debug(f"Could not get SSL cert for {domain_name}: {e}")
            return None

if __name__ == '__main__':
    daemon = SSLMonitorDaemon()
    daemon.run()
