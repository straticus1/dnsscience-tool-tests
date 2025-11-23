#!/usr/bin/env python3
"""
DNS Science - DNS Record Type Validation Daemon
Validates and tracks all DNS record types
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from base_daemon import BaseDaemon
import dns.resolver
from datetime import datetime
import json

class RecordTypeDaemon(BaseDaemon):
    """Daemon for DNS record type validation"""

    def __init__(self):
        super().__init__('dnsscience_recordtyped')
        self.record_types = [
            'A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA',
            'PTR', 'SRV', 'CAA', 'TLSA', 'DS', 'DNSKEY'
        ]

    def process_iteration(self):
        """Check DNS record types"""
        work_done = False

        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Get domains that need record type checks
            cursor.execute("""
                SELECT d.id, d.domain_name
                FROM domains d
                LEFT JOIN dns_records dr ON d.id = dr.domain_id
                WHERE d.is_active = TRUE
                AND (dr.last_updated IS NULL
                     OR dr.last_updated < NOW() - INTERVAL '3 days')
                LIMIT 100
            """)

            domains = cursor.fetchall()

            for domain_id, domain_name in domains:
                try:
                    records = self.get_all_records(domain_name)

                    for record_type, record_data in records.items():
                        if record_data:
                            cursor.execute("""
                                INSERT INTO dns_records
                                (domain_id, record_type, record_value, ttl, last_updated)
                                VALUES (%s, %s, %s, %s, %s)
                                ON CONFLICT (domain_id, record_type) DO UPDATE
                                SET record_value = EXCLUDED.record_value,
                                    ttl = EXCLUDED.ttl,
                                    last_updated = EXCLUDED.last_updated,
                                    check_count = dns_records.check_count + 1
                            """, (
                                domain_id,
                                record_type,
                                json.dumps(record_data['values']),
                                record_data['ttl'],
                                datetime.utcnow()
                            ))

                    conn.commit()
                    work_done = True

                except Exception as e:
                    self.logger.error(f"Error checking records for {domain_name}: {e}")
                    conn.rollback()

            cursor.close()

        except Exception as e:
            self.logger.error(f"Error in record type daemon: {e}")

        return work_done

    def get_all_records(self, domain_name):
        """Get all DNS record types for a domain"""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        results = {}

        for record_type in self.record_types:
            try:
                answers = resolver.resolve(domain_name, record_type)
                values = []
                ttl = None

                for rdata in answers:
                    values.append(str(rdata).rstrip('.'))
                    if ttl is None:
                        ttl = answers.rrset.ttl

                results[record_type] = {
                    'values': values,
                    'ttl': ttl
                }

            except Exception as e:
                results[record_type] = None

        return results

if __name__ == '__main__':
    daemon = RecordTypeDaemon()
    daemon.run()
