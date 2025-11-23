#!/usr/bin/env python3
"""
DNS Science - GeoIP Data Enrichment Daemon
Enriches domain data with GeoIP information
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from base_daemon import BaseDaemon
import dns.resolver
from datetime import datetime

class GeoIPDaemon(BaseDaemon):
    """Daemon for GeoIP data enrichment"""

    def __init__(self):
        super().__init__('dnsscience_geoipd')

    def process_iteration(self):
        """Enrich domains with GeoIP data"""
        work_done = False

        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Get domains that need GeoIP enrichment
            cursor.execute("""
                SELECT d.id, d.domain_name
                FROM domains d
                LEFT JOIN domain_geoip dg ON d.id = dg.domain_id
                WHERE d.is_active = TRUE
                AND (dg.last_updated IS NULL
                     OR dg.last_updated < NOW() - INTERVAL '30 days')
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

                        # Look up GeoIP data
                        cursor.execute("""
                            SELECT g.country_code, g.country_name, g.city,
                                   g.latitude, g.longitude, a.asn, a.organization
                            FROM geoip_blocks g
                            LEFT JOIN asn_data a ON g.asn = a.asn
                            WHERE %s::inet <<= g.network
                            LIMIT 1
                        """, (ip_address,))

                        geoip_row = cursor.fetchone()

                        if geoip_row:
                            country_code, country_name, city, lat, lon, asn, org = geoip_row

                            cursor.execute("""
                                INSERT INTO domain_geoip
                                (domain_id, ip_address, country_code, country_name,
                                 city, latitude, longitude, asn, organization, last_updated)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                ON CONFLICT (domain_id, ip_address) DO UPDATE
                                SET country_code = EXCLUDED.country_code,
                                    country_name = EXCLUDED.country_name,
                                    city = EXCLUDED.city,
                                    latitude = EXCLUDED.latitude,
                                    longitude = EXCLUDED.longitude,
                                    asn = EXCLUDED.asn,
                                    organization = EXCLUDED.organization,
                                    last_updated = EXCLUDED.last_updated
                            """, (
                                domain_id, ip_address, country_code, country_name,
                                city, lat, lon, asn, org, datetime.utcnow()
                            ))

                            conn.commit()
                            work_done = True

                except Exception as e:
                    self.logger.error(f"Error enriching GeoIP for {domain_name}: {e}")
                    conn.rollback()

            cursor.close()

        except Exception as e:
            self.logger.error(f"Error in GeoIP daemon: {e}")

        return work_done

if __name__ == '__main__':
    daemon = GeoIPDaemon()
    daemon.run()
