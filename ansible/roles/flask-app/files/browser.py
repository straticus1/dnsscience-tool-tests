"""Data Browser Module for DNS Science Platform

Provides comprehensive data browsing and exploration:
- Browse domains by TLD
- Browse by SSL status
- Browse threat intelligence
- Browse blacklist data
- Complete domain profiles
- Complete IP profiles
"""

import psycopg2
import psycopg2.extras
import json
from typing import Dict, List, Optional
from datetime import datetime
from database import Database


class DataBrowser:
    """Browse and explore collected DNS data"""

    def __init__(self, db: Database = None):
        """
        Initialize data browser.

        Args:
            db: Optional Database instance
        """
        self.db = db if db else Database()

    def browse_tlds(self, page: int = 1, per_page: int = 50) -> Dict:
        """
        Browse domains by TLD with statistics.

        Args:
            page: Page number
            per_page: Results per page

        Returns:
            Dictionary with TLD stats and pagination
        """
        per_page = min(per_page, 200)
        offset = (page - 1) * per_page

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                # Get total count
                cursor.execute("SELECT COUNT(*) FROM tld_statistics")
                total = cursor.fetchone()[0]

                # Get TLD stats
                cursor.execute("""
                    SELECT * FROM tld_statistics
                    ORDER BY domain_count DESC
                    LIMIT %s OFFSET %s
                """, (per_page, offset))

                tlds = [dict(row) for row in cursor.fetchall()]

                total_pages = (total + per_page - 1) // per_page if total > 0 else 0

                return {
                    'tlds': tlds,
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                }
        finally:
            self.db.return_connection(conn)

    def browse_tld_domains(
        self,
        tld: str,
        page: int = 1,
        per_page: int = 50,
        sort_by: str = 'last_checked'
    ) -> Dict:
        """
        Get all domains for a specific TLD.

        Args:
            tld: Top-level domain (e.g., 'com', 'org')
            page: Page number
            per_page: Results per page
            sort_by: Sort column

        Returns:
            Dictionary with domains and pagination
        """
        per_page = min(per_page, 200)
        offset = (page - 1) * per_page

        # Validate sort column
        valid_sorts = ['domain_name', 'last_checked', 'first_checked']
        if sort_by not in valid_sorts:
            sort_by = 'last_checked'

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                # Get total count
                cursor.execute("""
                    SELECT COUNT(*)
                    FROM domains
                    WHERE domain_name LIKE %s
                """, (f"%.{tld}",))
                total = cursor.fetchone()[0]

                # Get domains
                query = f"""
                    SELECT
                        d.id,
                        d.domain_name,
                        d.first_checked,
                        d.last_checked,
                        d.ssl_grade,
                        ls.dnssec_enabled,
                        ls.spf_valid,
                        ls.security_score,
                        ls.security_grade
                    FROM domains d
                    LEFT JOIN latest_scans ls ON d.domain_name = ls.domain_name
                    WHERE d.domain_name LIKE %s
                    ORDER BY d.{sort_by} DESC NULLS LAST
                    LIMIT %s OFFSET %s
                """

                cursor.execute(query, (f"%.{tld}", per_page, offset))
                domains = [dict(row) for row in cursor.fetchall()]

                total_pages = (total + per_page - 1) // per_page if total > 0 else 0

                return {
                    'tld': tld,
                    'domains': domains,
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                }
        finally:
            self.db.return_connection(conn)

    def browse_ssl_status(
        self,
        status: str,
        page: int = 1,
        per_page: int = 50
    ) -> Dict:
        """
        Browse domains by SSL status/grade.

        Args:
            status: SSL grade (A+, A, A-, B, C, D, F, or 'none')
            page: Page number
            per_page: Results per page

        Returns:
            Dictionary with domains and pagination
        """
        per_page = min(per_page, 200)
        offset = (page - 1) * per_page

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                if status == 'none':
                    where_clause = "d.ssl_grade IS NULL"
                else:
                    where_clause = "d.ssl_grade = %s"

                # Get total count
                if status == 'none':
                    cursor.execute(f"SELECT COUNT(*) FROM domains d WHERE {where_clause}")
                    total = cursor.fetchone()[0]
                else:
                    cursor.execute(f"SELECT COUNT(*) FROM domains d WHERE {where_clause}", (status,))
                    total = cursor.fetchone()[0]

                # Get domains
                query = f"""
                    SELECT
                        d.id,
                        d.domain_name,
                        d.ssl_grade,
                        d.last_checked,
                        ls.security_score,
                        lc.subject_cn,
                        lc.issuer_cn,
                        lc.not_after,
                        lc.days_until_expiry
                    FROM domains d
                    LEFT JOIN latest_scans ls ON d.domain_name = ls.domain_name
                    LEFT JOIN latest_certificates lc ON d.domain_name = lc.domain_name AND lc.port = 443
                    WHERE {where_clause}
                    ORDER BY d.last_checked DESC NULLS LAST
                    LIMIT %s OFFSET %s
                """

                if status == 'none':
                    cursor.execute(query, (per_page, offset))
                else:
                    cursor.execute(query, (status, per_page, offset))

                domains = [dict(row) for row in cursor.fetchall()]

                total_pages = (total + per_page - 1) // per_page if total > 0 else 0

                return {
                    'ssl_status': status,
                    'domains': domains,
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                }
        finally:
            self.db.return_connection(conn)

    def browse_threat_intel(
        self,
        severity: str = None,
        page: int = 1,
        per_page: int = 50
    ) -> Dict:
        """
        Browse threat intelligence data.

        Args:
            severity: Filter by severity (critical, high, medium, low)
            page: Page number
            per_page: Results per page

        Returns:
            Dictionary with threat data and pagination
        """
        per_page = min(per_page, 200)
        offset = (page - 1) * per_page

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                where_clause = "ti.is_active = TRUE"
                params = []

                if severity:
                    where_clause += " AND ti.severity = %s"
                    params.append(severity)

                # Get total count
                cursor.execute(f"""
                    SELECT COUNT(*)
                    FROM threat_indicators ti
                    WHERE {where_clause}
                """, params)
                total = cursor.fetchone()[0]

                # Get threat data
                cursor.execute(f"""
                    SELECT
                        d.domain_name,
                        ti.threat_type,
                        ti.severity,
                        ti.source,
                        ti.description,
                        ti.first_seen,
                        ti.last_seen,
                        ti.confidence_score,
                        ti.is_active
                    FROM threat_indicators ti
                    JOIN domains d ON ti.domain_id = d.id
                    WHERE {where_clause}
                    ORDER BY ti.last_seen DESC
                    LIMIT %s OFFSET %s
                """, params + [per_page, offset])

                threats = [dict(row) for row in cursor.fetchall()]

                total_pages = (total + per_page - 1) // per_page if total > 0 else 0

                return {
                    'severity': severity,
                    'threats': threats,
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                }
        finally:
            self.db.return_connection(conn)

    def browse_blacklists(
        self,
        blacklist: str = None,
        page: int = 1,
        per_page: int = 50
    ) -> Dict:
        """
        Browse blacklist data.

        Args:
            blacklist: Filter by blacklist name
            page: Page number
            per_page: Results per page

        Returns:
            Dictionary with blacklist data and pagination
        """
        per_page = min(per_page, 200)
        offset = (page - 1) * per_page

        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                where_clause = "db.is_active = TRUE"
                params = []

                if blacklist:
                    where_clause += " AND db.blacklist_name = %s"
                    params.append(blacklist)

                # Get total count
                cursor.execute(f"""
                    SELECT COUNT(*)
                    FROM domain_blacklists db
                    WHERE {where_clause}
                """, params)
                total = cursor.fetchone()[0]

                # Get blacklist data
                cursor.execute(f"""
                    SELECT
                        d.domain_name,
                        db.blacklist_name,
                        db.reason,
                        db.listed_since,
                        db.last_checked,
                        db.severity
                    FROM domain_blacklists db
                    JOIN domains d ON db.domain_id = d.id
                    WHERE {where_clause}
                    ORDER BY db.listed_since DESC
                    LIMIT %s OFFSET %s
                """, params + [per_page, offset])

                blacklists = [dict(row) for row in cursor.fetchall()]

                total_pages = (total + per_page - 1) // per_page if total > 0 else 0

                return {
                    'blacklist': blacklist,
                    'blacklists': blacklists,
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                }
        finally:
            self.db.return_connection(conn)

    def get_domain_complete_profile(self, domain: str) -> Optional[Dict]:
        """
        Get COMPLETE domain profile with all historical data.

        Args:
            domain: Domain name

        Returns:
            Complete domain profile dictionary
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                # Get basic domain info
                cursor.execute("""
                    SELECT * FROM domains WHERE domain_name = %s
                """, (domain.lower(),))
                domain_info = cursor.fetchone()

                if not domain_info:
                    return None

                profile = dict(domain_info)
                domain_id = profile['id']

                # Get latest scan
                cursor.execute("""
                    SELECT * FROM latest_scans WHERE domain_name = %s
                """, (domain.lower(),))
                latest_scan = cursor.fetchone()
                profile['latest_scan'] = dict(latest_scan) if latest_scan else None

                # Get scan history (last 100)
                cursor.execute("""
                    SELECT * FROM scan_history
                    WHERE domain_id = %s
                    ORDER BY scan_timestamp DESC
                    LIMIT 100
                """, (domain_id,))
                profile['scan_history'] = [dict(row) for row in cursor.fetchall()]

                # Get latest certificates
                cursor.execute("""
                    SELECT * FROM latest_certificates
                    WHERE domain_name = %s
                """, (domain.lower(),))
                profile['certificates'] = [dict(row) for row in cursor.fetchall()]

                # Get certificate history
                cursor.execute("""
                    SELECT * FROM certificate_history
                    WHERE domain_id = %s
                    ORDER BY scan_timestamp DESC
                    LIMIT 50
                """, (domain_id,))
                profile['certificate_history'] = [dict(row) for row in cursor.fetchall()]

                # Get threat indicators
                cursor.execute("""
                    SELECT * FROM threat_indicators
                    WHERE domain_id = %s
                    ORDER BY last_seen DESC
                """, (domain_id,))
                profile['threats'] = [dict(row) for row in cursor.fetchall()]

                # Get blacklist status
                cursor.execute("""
                    SELECT * FROM domain_blacklists
                    WHERE domain_id = %s AND is_active = TRUE
                    ORDER BY listed_since DESC
                """, (domain_id,))
                profile['blacklists'] = [dict(row) for row in cursor.fetchall()]

                # Get GeoIP data
                cursor.execute("""
                    SELECT * FROM geoip_data
                    WHERE domain_id = %s
                    ORDER BY last_updated DESC
                    LIMIT 1
                """, (domain_id,))
                geoip = cursor.fetchone()
                profile['geoip'] = dict(geoip) if geoip else None

                # Get Web3 data
                cursor.execute("""
                    SELECT w3d.*, w3n.network_name, w3n.blockchain
                    FROM web3_domains w3d
                    JOIN web3_networks w3n ON w3d.network_id = w3n.id
                    WHERE w3d.domain_name = %s
                """, (domain.lower(),))
                profile['web3'] = [dict(row) for row in cursor.fetchall()]

                # Get DNS records
                cursor.execute("""
                    SELECT * FROM dns_records
                    WHERE domain_id = %s
                    ORDER BY last_updated DESC
                    LIMIT 100
                """, (domain_id,))
                profile['dns_records'] = [dict(row) for row in cursor.fetchall()]

                # Parse JSON fields
                for cert in profile.get('certificates', []):
                    if cert.get('san'):
                        try:
                            cert['san'] = json.loads(cert['san'])
                        except:
                            cert['san'] = []

                return profile
        finally:
            self.db.return_connection(conn)

    def get_ip_complete_profile(self, ip: str) -> Optional[Dict]:
        """
        Get COMPLETE IP profile with all data.

        Args:
            ip: IP address

        Returns:
            Complete IP profile dictionary
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                profile = {
                    'ip_address': ip,
                    'reverse_dns': None,
                    'geoip': None,
                    'asn': None,
                    'threats': [],
                    'blacklists': [],
                    'associated_domains': [],
                    'ports': []
                }

                # Get reverse DNS
                cursor.execute("""
                    SELECT * FROM reverse_dns
                    WHERE ip_address = %s
                    ORDER BY last_checked DESC
                    LIMIT 1
                """, (ip,))
                rdns = cursor.fetchone()
                profile['reverse_dns'] = dict(rdns) if rdns else None

                # Get GeoIP data
                cursor.execute("""
                    SELECT * FROM geoip_data
                    WHERE ip_address = %s
                    ORDER BY last_updated DESC
                    LIMIT 1
                """, (ip,))
                geoip = cursor.fetchone()
                profile['geoip'] = dict(geoip) if geoip else None

                # Get ASN data
                cursor.execute("""
                    SELECT * FROM asn_data
                    WHERE ip_address = %s
                    ORDER BY last_updated DESC
                    LIMIT 1
                """, (ip,))
                asn = cursor.fetchone()
                profile['asn'] = dict(asn) if asn else None

                # Get threat indicators
                cursor.execute("""
                    SELECT * FROM ip_threat_indicators
                    WHERE ip_address = %s AND is_active = TRUE
                    ORDER BY last_seen DESC
                """, (ip,))
                profile['threats'] = [dict(row) for row in cursor.fetchall()]

                # Get blacklist status
                cursor.execute("""
                    SELECT * FROM ip_blacklists
                    WHERE ip_address = %s AND is_active = TRUE
                    ORDER BY listed_since DESC
                """, (ip,))
                profile['blacklists'] = [dict(row) for row in cursor.fetchall()]

                # Get associated domains
                cursor.execute("""
                    SELECT DISTINCT d.domain_name, d.last_checked
                    FROM domains d
                    JOIN dns_records dr ON d.id = dr.domain_id
                    WHERE dr.record_value = %s
                    ORDER BY d.last_checked DESC
                    LIMIT 100
                """, (ip,))
                profile['associated_domains'] = [dict(row) for row in cursor.fetchall()]

                # Get port scan results
                cursor.execute("""
                    SELECT * FROM port_scan_results
                    WHERE ip_address = %s
                    ORDER BY scan_timestamp DESC
                    LIMIT 1
                """, (ip,))
                port_scan = cursor.fetchone()
                if port_scan:
                    profile['ports'] = json.loads(port_scan['open_ports']) if port_scan.get('open_ports') else []

                return profile
        finally:
            self.db.return_connection(conn)

    def get_timeline(self, domain: str, limit: int = 100) -> List[Dict]:
        """
        Get timeline of all changes for a domain.

        Args:
            domain: Domain name
            limit: Max events

        Returns:
            List of timeline events
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                # Get domain ID
                cursor.execute("SELECT id FROM domains WHERE domain_name = %s", (domain.lower(),))
                row = cursor.fetchone()
                if not row:
                    return []

                domain_id = row['id']

                timeline = []

                # Scan events
                cursor.execute("""
                    SELECT
                        'scan' as event_type,
                        scan_timestamp as timestamp,
                        scan_status as status,
                        security_score,
                        security_grade
                    FROM scan_history
                    WHERE domain_id = %s
                    ORDER BY scan_timestamp DESC
                    LIMIT %s
                """, (domain_id, limit))
                timeline.extend([dict(row) for row in cursor.fetchall()])

                # Certificate events
                cursor.execute("""
                    SELECT
                        'certificate' as event_type,
                        scan_timestamp as timestamp,
                        port,
                        subject_cn,
                        issuer_cn,
                        not_after
                    FROM certificate_history
                    WHERE domain_id = %s
                    ORDER BY scan_timestamp DESC
                    LIMIT %s
                """, (domain_id, limit))
                timeline.extend([dict(row) for row in cursor.fetchall()])

                # Sort combined timeline
                timeline.sort(key=lambda x: x['timestamp'], reverse=True)

                return timeline[:limit]
        finally:
            self.db.return_connection(conn)
