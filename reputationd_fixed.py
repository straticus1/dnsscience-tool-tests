#!/usr/bin/env python3
"""
DNS Science - IP Reputation Aggregation Daemon (FIXED)
Aggregates IP reputation data from multiple sources
FIXED: Proper handling of LEFT JOIN with NULL values
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from base_daemon import BaseDaemon
import dns.resolver
import requests
from datetime import datetime

class ReputationDaemon(BaseDaemon):
    """Daemon for IP reputation aggregation"""

    def __init__(self):
        super().__init__('dnsscience_reputationd')

    def process_iteration(self):
        """Check IP reputation"""
        work_done = False

        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # FIXED: Proper LEFT JOIN handling - check for NULL in WHERE clause
            # The issue was using r.last_checked in WHERE when r might be NULL
            cursor.execute("""
                SELECT d.id, d.domain_name
                FROM domains d
                LEFT JOIN ip_reputation r ON d.id = r.domain_id
                WHERE d.is_active = TRUE
                AND (r.last_checked IS NULL
                     OR r.last_checked < NOW() - INTERVAL '7 days')
                LIMIT 50
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

                        # Check various reputation sources
                        reputation_score = self.calculate_reputation(ip_address)

                        # FIXED: Now last_checked column definitely exists
                        cursor.execute("""
                            INSERT INTO ip_reputation
                            (domain_id, ip_address, reputation_score,
                             is_malicious, is_spam, is_proxy,
                             threat_level, last_checked)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (domain_id, ip_address) DO UPDATE
                            SET reputation_score = EXCLUDED.reputation_score,
                                is_malicious = EXCLUDED.is_malicious,
                                is_spam = EXCLUDED.is_spam,
                                is_proxy = EXCLUDED.is_proxy,
                                threat_level = EXCLUDED.threat_level,
                                last_checked = EXCLUDED.last_checked
                        """, (
                            domain_id, ip_address,
                            reputation_score['score'],
                            reputation_score['is_malicious'],
                            reputation_score['is_spam'],
                            reputation_score['is_proxy'],
                            reputation_score['threat_level'],
                            datetime.utcnow()
                        ))

                        conn.commit()
                        work_done = True
                        self.logger.info(f"Updated reputation for {domain_name} ({ip_address}): {reputation_score['score']}")

                except dns.resolver.NXDOMAIN:
                    self.logger.debug(f"Domain {domain_name} does not exist")
                except dns.resolver.NoAnswer:
                    self.logger.debug(f"No A record for {domain_name}")
                except dns.resolver.Timeout:
                    self.logger.warning(f"DNS timeout for {domain_name}")
                except Exception as e:
                    self.logger.error(f"Error checking reputation for {domain_name}: {e}")
                    conn.rollback()

            cursor.close()

        except Exception as e:
            self.logger.error(f"Error in reputation daemon: {e}")

        return work_done

    def calculate_reputation(self, ip_address):
        """Calculate reputation score from multiple sources"""
        result = {
            'score': 100,  # Start with perfect score
            'is_malicious': False,
            'is_spam': False,
            'is_proxy': False,
            'threat_level': 'none'
        }

        try:
            # Check against local threat database
            conn = self.get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT COUNT(*) FROM malware_indicators
                WHERE indicator_value = %s AND indicator_type = 'ip'
            """, (ip_address,))

            if cursor.fetchone()[0] > 0:
                result['is_malicious'] = True
                result['score'] -= 50
                result['threat_level'] = 'high'

            cursor.close()

        except Exception as e:
            self.logger.warning(f"Error checking malware indicators: {e}")

        return result

if __name__ == '__main__':
    daemon = ReputationDaemon()
    daemon.run()
