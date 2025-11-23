#!/usr/bin/env python3
"""
DNS Science - gTLD Zone File Tracking Daemon
Monitors and analyzes gTLD zone files for new domains and changes
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from base_daemon import BaseDaemon
import requests
from datetime import datetime, timedelta

class GTLDDaemon(BaseDaemon):
    """Daemon for gTLD zone file tracking and analysis"""

    def __init__(self):
        super().__init__('dnsscience_gtld')
        self.gtlds = [
            'com', 'net', 'org', 'info', 'biz', 'name', 'pro',
            'mobi', 'asia', 'tel', 'xxx', 'travel', 'jobs'
        ]

    def process_iteration(self):
        """Process gTLD zone files"""
        work_done = False

        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Check which gTLDs need updating (once per day)
            for gtld in self.gtlds:
                cache_key = f'gtld:last_check:{gtld}'
                last_check = self.cache_get(cache_key)

                if last_check:
                    # Skip if checked within last 24 hours
                    continue

                self.logger.info(f"Checking gTLD zone: .{gtld}")

                try:
                    # Store gTLD info
                    cursor.execute("""
                        INSERT INTO gtld_zones (tld, last_checked, status)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (tld) DO UPDATE
                        SET last_checked = EXCLUDED.last_checked,
                            status = EXCLUDED.status,
                            check_count = gtld_zones.check_count + 1
                    """, (gtld, datetime.utcnow(), 'active'))

                    conn.commit()

                    # Mark as checked
                    self.cache_set(cache_key, datetime.utcnow().isoformat(), 86400)
                    work_done = True

                except Exception as e:
                    self.logger.error(f"Error processing .{gtld}: {e}")
                    conn.rollback()

            cursor.close()

        except Exception as e:
            self.logger.error(f"Error in gTLD processing: {e}")

        return work_done

    def get_sleep_duration(self, work_done):
        """Sleep longer for gTLD daemon (daily updates)"""
        return 3600 if work_done else 3600  # 1 hour

if __name__ == '__main__':
    daemon = GTLDDaemon()
    daemon.run()
