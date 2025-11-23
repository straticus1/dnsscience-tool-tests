#!/usr/bin/env python3
"""
DNS Science - Threat Intelligence Feed Daemon
Aggregates threat intelligence from CISA KEV, Abuse.ch, Shadowserver, MISP
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from base_daemon import BaseDaemon
import requests
from datetime import datetime
import json

class ThreatIntelDaemon(BaseDaemon):
    """Daemon for threat intelligence feed aggregation"""

    def __init__(self):
        super().__init__('dnsscience_threatinteld')
        self.feeds = {
            'cisa_kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            'abuse_ch_urlhaus': 'https://urlhaus.abuse.ch/downloads/json/',
            'abuse_ch_threatfox': 'https://threatfox.abuse.ch/export/json/recent/',
        }

    def process_iteration(self):
        """Update threat intelligence feeds"""
        work_done = False

        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Process CISA KEV
            if self.should_update_feed('cisa_kev'):
                work_done |= self.update_cisa_kev(cursor)

            # Process Abuse.ch feeds
            if self.should_update_feed('abuse_ch'):
                work_done |= self.update_abuse_ch(cursor)

            conn.commit()

        except Exception as e:
            self.logger.error(f"Error in threat intel daemon: {e}")

        return work_done

    def should_update_feed(self, feed_name):
        """Check if feed should be updated"""
        cache_key = f'threatintel:last_update:{feed_name}'
        last_update = self.cache_get(cache_key)

        if not last_update:
            return True

        # Update daily
        return False

    def update_cisa_kev(self, cursor):
        """Update CISA Known Exploited Vulnerabilities"""
        try:
            self.logger.info("Updating CISA KEV feed...")

            response = requests.get(self.feeds['cisa_kev'], timeout=30)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            count = 0
            for vuln in vulnerabilities:
                cursor.execute("""
                    INSERT INTO cisa_kev_vulnerabilities
                    (cve_id, vendor_project, product, vulnerability_name,
                     date_added, short_description, required_action,
                     due_date, known_ransomware, notes)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id) DO UPDATE
                    SET vulnerability_name = EXCLUDED.vulnerability_name,
                        short_description = EXCLUDED.short_description,
                        required_action = EXCLUDED.required_action,
                        updated_at = NOW()
                """, (
                    vuln.get('cveID'),
                    vuln.get('vendorProject'),
                    vuln.get('product'),
                    vuln.get('vulnerabilityName'),
                    vuln.get('dateAdded'),
                    vuln.get('shortDescription'),
                    vuln.get('requiredAction'),
                    vuln.get('dueDate'),
                    vuln.get('knownRansomwareCampaignUse') == 'Known',
                    vuln.get('notes')
                ))
                count += 1

            self.logger.info(f"Updated {count} CISA KEV entries")
            self.cache_set('threatintel:last_update:cisa_kev', datetime.utcnow().isoformat(), 86400)

            return count > 0

        except Exception as e:
            self.logger.error(f"Error updating CISA KEV: {e}")
            return False

    def update_abuse_ch(self, cursor):
        """Update Abuse.ch feeds"""
        try:
            self.logger.info("Updating Abuse.ch ThreatFox feed...")

            response = requests.get(self.feeds['abuse_ch_threatfox'], timeout=30)
            response.raise_for_status()

            data = response.json()
            entries = data.get('data', []) if isinstance(data, dict) else data

            count = 0
            for entry in entries:
                ioc = entry.get('ioc')
                ioc_type = entry.get('ioc_type')

                if ioc and ioc_type:
                    cursor.execute("""
                        INSERT INTO threat_intel_iocs
                        (indicator_value, indicator_type, threat_type,
                         malware_family, confidence_level, first_seen,
                         last_seen, source, tags)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (indicator_value, source) DO UPDATE
                        SET last_seen = EXCLUDED.last_seen,
                            confidence_level = EXCLUDED.confidence_level,
                            updated_at = NOW()
                    """, (
                        ioc,
                        ioc_type,
                        entry.get('threat_type'),
                        entry.get('malware'),
                        entry.get('confidence_level', 50),
                        entry.get('first_seen'),
                        entry.get('last_seen'),
                        'abuse.ch_threatfox',
                        json.dumps(entry.get('tags', []))
                    ))
                    count += 1

            self.logger.info(f"Updated {count} Abuse.ch entries")
            self.cache_set('threatintel:last_update:abuse_ch', datetime.utcnow().isoformat(), 86400)

            return count > 0

        except Exception as e:
            self.logger.error(f"Error updating Abuse.ch: {e}")
            return False

if __name__ == '__main__':
    daemon = ThreatIntelDaemon()
    daemon.run()
