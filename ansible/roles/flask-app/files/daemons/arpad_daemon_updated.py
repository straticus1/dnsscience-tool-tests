#!/usr/bin/env python3
"""
DNS Science - ARPA (Reverse DNS) Monitoring Daemon
Tracks reverse DNS zones and PTR records with comprehensive validation
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from base_daemon import BaseDaemon
import dns.resolver
import dns.reversename
from datetime import datetime
import ipaddress

class ARPADaemon(BaseDaemon):
    """Daemon for comprehensive reverse DNS monitoring"""

    def __init__(self):
        super().__init__('dnsscience_arpad')

    def process_iteration(self):
        """Process reverse DNS checks with comprehensive validation"""
        work_done = False

        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Get domains that need reverse DNS checks (checking 100 at a time)
            cursor.execute("""
                SELECT DISTINCT d.id, d.domain_name, d.last_checked
                FROM domains d
                LEFT JOIN ptr_records p ON d.id = p.domain_id AND p.is_current = TRUE
                WHERE d.is_active = TRUE
                AND (p.id IS NULL OR p.last_seen < NOW() - INTERVAL '7 days')
                ORDER BY d.last_checked DESC
                LIMIT 100
            """)

            domains = cursor.fetchall()

            if not domains:
                self.logger.info("No domains need reverse DNS checking")
                return False

            for domain_id, domain_name, _ in domains:
                try:
                    # Resolve domain to IP addresses (both A and AAAA)
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 5
                    resolver.lifetime = 5

                    ips_checked = 0

                    # Check IPv4 (A records)
                    try:
                        answers = resolver.resolve(domain_name, 'A')
                        for rdata in answers:
                            ip_address = str(rdata)
                            self._check_ptr_record(cursor, domain_id, domain_name, ip_address, 4)
                            ips_checked += 1
                    except Exception as e:
                        self.logger.debug(f"No A records for {domain_name}: {e}")

                    # Check IPv6 (AAAA records)
                    try:
                        answers = resolver.resolve(domain_name, 'AAAA')
                        for rdata in answers:
                            ip_address = str(rdata)
                            self._check_ptr_record(cursor, domain_id, domain_name, ip_address, 6)
                            ips_checked += 1
                    except Exception as e:
                        self.logger.debug(f"No AAAA records for {domain_name}: {e}")

                    if ips_checked > 0:
                        conn.commit()
                        work_done = True
                        self.logger.info(f"✓ {domain_name} - checked {ips_checked} IPs")

                except Exception as e:
                    self.logger.error(f"Error checking reverse DNS for {domain_name}: {e}")
                    conn.rollback()

            cursor.close()

        except Exception as e:
            self.logger.error(f"Error in ARPA processing: {e}")

        return work_done

    def _check_ptr_record(self, cursor, domain_id, domain_name, ip_address, ip_version):
        """Check PTR record for an IP and perform forward confirmation"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            # Generate PTR name
            ip_obj = ipaddress.ip_address(ip_address)
            rev_name = dns.reversename.from_address(ip_address)
            ptr_name = str(rev_name)

            ptr_value = None
            has_ptr = False
            validation_errors = []

            # Try to resolve PTR record
            try:
                rev_answers = resolver.resolve(rev_name, 'PTR')
                if rev_answers:
                    ptr_value = str(rev_answers[0]).rstrip('.')
                    has_ptr = True
            except dns.resolver.NXDOMAIN:
                validation_errors.append('No PTR record found')
            except dns.resolver.NoAnswer:
                validation_errors.append('PTR query returned no answer')
            except Exception as e:
                validation_errors.append(f'PTR lookup failed: {str(e)}')

            # Forward DNS confirmation (FCrDNS)
            forward_matches = False
            forward_lookup_result = None

            if ptr_value:
                try:
                    # Try to resolve the PTR value back to an IP
                    record_type = 'AAAA' if ip_version == 6 else 'A'
                    forward_answers = resolver.resolve(ptr_value, record_type)

                    for fwd_rdata in forward_answers:
                        forward_ip = str(fwd_rdata)
                        if forward_ip == ip_address:
                            forward_matches = True
                            forward_lookup_result = forward_ip
                            break

                    if not forward_matches and forward_answers:
                        forward_lookup_result = str(forward_answers[0])
                        validation_errors.append(f'Forward DNS mismatch: {ptr_value} resolves to {forward_lookup_result}')

                except Exception as e:
                    validation_errors.append(f'Forward DNS lookup failed: {str(e)}')

            # Determine if record is valid
            is_valid = has_ptr and forward_matches

            # Store PTR record with comprehensive validation
            # First, mark any existing current record for this IP as not current
            cursor.execute("""
                UPDATE ptr_records
                SET is_current = FALSE
                WHERE ip_address = %s AND is_current = TRUE
            """, (ip_address,))

            # Then insert the new record
            cursor.execute("""
                INSERT INTO ptr_records (
                    domain_id,
                    ip_address,
                    ip_version,
                    ptr_name,
                    ptr_value,
                    is_valid,
                    validation_errors,
                    forward_matches,
                    forward_lookup_result,
                    is_current,
                    scan_timestamp,
                    first_seen,
                    last_seen
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE, NOW(), NOW(), NOW()
                )
            """, (
                domain_id,
                ip_address,
                ip_version,
                ptr_name,
                ptr_value,
                is_valid,
                validation_errors if validation_errors else None,
                forward_matches,
                forward_lookup_result
            ))

            # Create issues if PTR is invalid
            if not is_valid and has_ptr:
                self._create_reverse_dns_issue(
                    cursor,
                    domain_id,
                    'ptr_forward_mismatch',
                    'high',
                    f'PTR record for {ip_address} does not match forward DNS',
                    f'The PTR record {ptr_value} for IP {ip_address} does not resolve back to the same IP',
                    'Configure your PTR record to match the forward DNS (A/AAAA) record',
                    ip_address,
                    None,
                    ptr_value
                )
            elif not has_ptr:
                self._create_reverse_dns_issue(
                    cursor,
                    domain_id,
                    'missing_ptr',
                    'medium',
                    f'Missing PTR record for {ip_address}',
                    f'No PTR record found for IP {ip_address}. This can affect email deliverability.',
                    'Create a PTR record for this IP address with your hosting provider or ISP',
                    ip_address,
                    domain_name,
                    None
                )

        except Exception as e:
            self.logger.error(f"Error checking PTR for {ip_address}: {e}")

    def _create_reverse_dns_issue(self, cursor, domain_id, issue_type, severity, title, description, recommendation, affected_ip, expected_ptr, actual_ptr):
        """Create or update a reverse DNS issue"""
        # First, try to update existing issue
        cursor.execute("""
            UPDATE reverse_dns_issues
            SET last_detected = NOW(),
                detection_count = detection_count + 1,
                status = CASE
                    WHEN status = 'resolved' THEN 'open'
                    ELSE status
                END
            WHERE domain_id = %s AND issue_type = %s AND affected_ip = %s
        """, (domain_id, issue_type, affected_ip))

        # If no rows were updated, insert new issue
        if cursor.rowcount == 0:
            cursor.execute("""
                INSERT INTO reverse_dns_issues (
                    domain_id,
                    issue_type,
                    severity,
                    title,
                    description,
                    recommendation,
                    affected_ip,
                    expected_ptr,
                    actual_ptr,
                    status,
                    first_detected,
                    last_detected,
                    detection_count
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, 'open', NOW(), NOW(), 1
                )
            """, (
                domain_id,
                issue_type,
                severity,
                title,
                description,
                recommendation,
                affected_ip,
                expected_ptr,
                actual_ptr
            ))

if __name__ == '__main__':
    daemon = ARPADaemon()
    daemon.run()
