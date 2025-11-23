#!/usr/bin/env python3
"""
DNS Science - SSL Certificate Monitoring Daemon
Monitors SSL certificates for expiration and changes
FIXED: Works with ssl_certificates table (not certificate_history)
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

            # Get domains that need SSL checks
            # Check domains that haven't been scanned or haven't been scanned in 7 days
            cursor.execute("""
                SELECT d.id, d.domain_name
                FROM domains d
                LEFT JOIN ssl_certificates sc ON d.domain_name = sc.domain_name
                WHERE d.is_active = TRUE
                AND (sc.last_checked IS NULL
                     OR sc.last_checked < NOW() - INTERVAL '7 days')
                LIMIT 20
            """)

            domains = cursor.fetchall()

            for domain_id, domain_name in domains:
                try:
                    cert_info = self.get_ssl_certificate(domain_name)

                    if cert_info:
                        # Insert or update SSL certificate record
                        cursor.execute("""
                            INSERT INTO ssl_certificates
                            (domain_name, port, subject_cn, issuer_cn,
                             valid_from, valid_to, expires_at, last_checked, created_at)
                            VALUES (%s, 443, %s, %s, %s, %s, %s, NOW(), NOW())
                            ON CONFLICT (domain_name, port) DO UPDATE
                            SET subject_cn = EXCLUDED.subject_cn,
                                issuer_cn = EXCLUDED.issuer_cn,
                                valid_from = EXCLUDED.valid_from,
                                valid_to = EXCLUDED.valid_to,
                                expires_at = EXCLUDED.expires_at,
                                last_checked = NOW()
                        """, (
                            domain_name,
                            cert_info['subject_cn'],
                            cert_info['issuer_cn'],
                            cert_info['valid_from'],
                            cert_info['expires_at'],
                            cert_info['expires_at']
                        ))

                        # Update domain with last SSL scan time
                        cursor.execute("""
                            UPDATE domains
                            SET last_ssl_scan = NOW()
                            WHERE id = %s
                        """, (domain_id,))

                        conn.commit()
                        work_done = True

                        days_until_expiry = (cert_info['expires_at'] - datetime.utcnow()).days
                        self.logger.info(
                            f"SSL cert for {domain_name}: "
                            f"expires in {days_until_expiry} days, "
                            f"issuer: {cert_info['issuer_cn']}"
                        )

                except Exception as e:
                    self.logger.error(f"Error checking SSL for {domain_name}: {e}")
                    conn.rollback()

            # Log expiring certificates
            cursor.execute("""
                SELECT domain_name, expires_at
                FROM ssl_certificates
                WHERE expires_at IS NOT NULL
                AND expires_at < NOW() + INTERVAL '30 days'
                AND expires_at > NOW()
                ORDER BY expires_at ASC
                LIMIT 10
            """)

            expiring_certs = cursor.fetchall()

            for domain_name, expires_at in expiring_certs:
                days_until_expiry = (expires_at - datetime.utcnow()).days
                self.logger.warning(
                    f"Certificate expiring soon: {domain_name} "
                    f"({days_until_expiry} days)"
                )

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
