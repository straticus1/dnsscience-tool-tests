#!/usr/bin/env python3
"""
DNS Science - ARPA (Reverse DNS) Monitoring Daemon
Tracks reverse DNS zones and PTR records
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from base_daemon import BaseDaemon
import dns.resolver
import dns.reversename
from datetime import datetime

class ARPADaemon(BaseDaemon):
    """Daemon for reverse DNS monitoring"""

    def __init__(self):
        super().__init__('dnsscience_arpad')

    def process_iteration(self):
        """Process reverse DNS checks"""
        work_done = False

        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Get domains that need reverse DNS checks
            cursor.execute("""
                SELECT DISTINCT d.id, d.domain_name
                FROM domains d
                LEFT JOIN reverse_dns_scans r ON d.id = r.domain_id
                WHERE d.is_active = TRUE
                AND (r.last_checked IS NULL OR r.last_checked < NOW() - INTERVAL '7 days')
                LIMIT 100
            """)

            domains = cursor.fetchall()

            for domain_id, domain_name in domains:
                try:
                    # Resolve domain to IP
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 5
                    resolver.lifetime = 5

                    answers = resolver.resolve(domain_name, 'A')

                    for rdata in answers:
                        ip_address = str(rdata)

                        # Check reverse DNS
                        try:
                            rev_name = dns.reversename.from_address(ip_address)
                            rev_answers = resolver.resolve(rev_name, 'PTR')

                            for rev_rdata in rev_answers:
                                ptr_record = str(rev_rdata).rstrip('.')

                                # Store PTR record
                                cursor.execute("""
                                    INSERT INTO ptr_records
                                    (domain_id, ip_address, ptr_record, checked_at)
                                    VALUES (%s, %s, %s, %s)
                                    ON CONFLICT (domain_id, ip_address) DO UPDATE
                                    SET ptr_record = EXCLUDED.ptr_record,
                                        checked_at = EXCLUDED.checked_at,
                                        check_count = ptr_records.check_count + 1
                                """, (domain_id, ip_address, ptr_record, datetime.utcnow()))

                        except Exception as e:
                            # No PTR record
                            cursor.execute("""
                                INSERT INTO ptr_records
                                (domain_id, ip_address, ptr_record, has_ptr, checked_at)
                                VALUES (%s, %s, NULL, FALSE, %s)
                                ON CONFLICT (domain_id, ip_address) DO UPDATE
                                SET has_ptr = FALSE,
                                    checked_at = EXCLUDED.checked_at
                            """, (domain_id, ip_address, datetime.utcnow()))

                    # Update reverse DNS scan timestamp
                    cursor.execute("""
                        INSERT INTO reverse_dns_scans (domain_id, last_checked, scan_status)
                        VALUES (%s, %s, 'completed')
                        ON CONFLICT (domain_id) DO UPDATE
                        SET last_checked = EXCLUDED.last_checked,
                            scan_status = EXCLUDED.scan_status
                    """, (domain_id, datetime.utcnow()))

                    conn.commit()
                    work_done = True

                except Exception as e:
                    self.logger.error(f"Error checking reverse DNS for {domain_name}: {e}")
                    conn.rollback()

            cursor.close()

        except Exception as e:
            self.logger.error(f"Error in ARPA processing: {e}")

        return work_done

if __name__ == '__main__':
    daemon = ARPADaemon()
    daemon.run()
