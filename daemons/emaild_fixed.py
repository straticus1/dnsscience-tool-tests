#!/usr/bin/env python3
"""
DNS Science - Email Security Daemon
Monitors MX, DKIM, SPF, DMARC, and TLS
FIXED: Removed has_sender_id and sender_id_record columns
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from base_daemon import BaseDaemon
import dns.resolver
from datetime import datetime

class EmailDaemon(BaseDaemon):
    """Daemon for email security monitoring"""

    def __init__(self):
        super().__init__('dnsscience_emaild')

    def process_iteration(self):
        """Check email security records"""
        work_done = False

        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Get domains that need email security checks
            cursor.execute("""
                SELECT d.id, d.domain_name
                FROM domains d
                LEFT JOIN email_security_records e ON d.id = e.domain_id
                WHERE d.is_active = TRUE
                AND (e.last_checked IS NULL
                     OR e.last_checked < NOW() - INTERVAL '7 days')
                LIMIT 50
            """)

            domains = cursor.fetchall()

            for domain_id, domain_name in domains:
                try:
                    email_security = self.check_email_security(domain_name)

                    # FIXED: Removed has_sender_id and sender_id_record columns
                    cursor.execute("""
                        INSERT INTO email_security_records
                        (domain_id, last_checked,
                         has_mx, mx_records, mx_count,
                         has_spf, spf_record, spf_valid,
                         has_dmarc, dmarc_record, dmarc_policy,
                         has_dkim, dkim_selectors)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (domain_id) DO UPDATE
                        SET last_checked = EXCLUDED.last_checked,
                            has_mx = EXCLUDED.has_mx,
                            mx_records = EXCLUDED.mx_records,
                            mx_count = EXCLUDED.mx_count,
                            has_spf = EXCLUDED.has_spf,
                            spf_record = EXCLUDED.spf_record,
                            spf_valid = EXCLUDED.spf_valid,
                            has_dmarc = EXCLUDED.has_dmarc,
                            dmarc_record = EXCLUDED.dmarc_record,
                            dmarc_policy = EXCLUDED.dmarc_policy,
                            has_dkim = EXCLUDED.has_dkim,
                            dkim_selectors = EXCLUDED.dkim_selectors
                    """, (
                        domain_id, datetime.utcnow(),
                        email_security['has_mx'], email_security['mx_records'],
                        email_security['mx_count'],
                        email_security['has_spf'], email_security['spf_record'],
                        email_security['spf_valid'],
                        email_security['has_dmarc'], email_security['dmarc_record'],
                        email_security['dmarc_policy'],
                        email_security['has_dkim'], email_security['dkim_selectors']
                    ))

                    conn.commit()
                    work_done = True

                    self.logger.info(
                        f"Email security for {domain_name}: "
                        f"MX={email_security['has_mx']}, "
                        f"SPF={email_security['has_spf']}, "
                        f"DMARC={email_security['has_dmarc']}, "
                        f"DKIM={email_security['has_dkim']}"
                    )

                except Exception as e:
                    self.logger.error(f"Error checking email security for {domain_name}: {e}")
                    conn.rollback()

            cursor.close()

        except Exception as e:
            self.logger.error(f"Error in email daemon: {e}")

        return work_done

    def check_email_security(self, domain_name):
        """Check all email security records"""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        result = {
            'has_mx': False,
            'mx_records': None,
            'mx_count': 0,
            'has_spf': False,
            'spf_record': None,
            'spf_valid': False,
            'has_dmarc': False,
            'dmarc_record': None,
            'dmarc_policy': None,
            'has_dkim': False,
            'dkim_selectors': None
        }

        # Check MX records
        try:
            mx_answers = resolver.resolve(domain_name, 'MX')
            mx_list = [str(rdata.exchange).rstrip('.') for rdata in mx_answers]
            result['has_mx'] = True
            result['mx_records'] = mx_list  # Store as array
            result['mx_count'] = len(mx_list)
        except:
            pass

        # Check SPF
        try:
            txt_answers = resolver.resolve(domain_name, 'TXT')
            for rdata in txt_answers:
                txt_value = str(rdata).strip('"')
                if txt_value.startswith('v=spf1'):
                    result['has_spf'] = True
                    result['spf_record'] = txt_value
                    result['spf_valid'] = 'all' in txt_value
                    break
        except:
            pass

        # Check DMARC
        try:
            dmarc_domain = f'_dmarc.{domain_name}'
            dmarc_answers = resolver.resolve(dmarc_domain, 'TXT')
            for rdata in dmarc_answers:
                txt_value = str(rdata).strip('"')
                if txt_value.startswith('v=DMARC1'):
                    result['has_dmarc'] = True
                    result['dmarc_record'] = txt_value
                    # Extract policy
                    for part in txt_value.split(';'):
                        if 'p=' in part:
                            result['dmarc_policy'] = part.split('=')[1].strip()
                    break
        except:
            pass

        # Check common DKIM selectors
        dkim_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 's1']
        found_selectors = []
        for selector in dkim_selectors:
            try:
                dkim_domain = f'{selector}._domainkey.{domain_name}'
                resolver.resolve(dkim_domain, 'TXT')
                found_selectors.append(selector)
            except:
                pass

        if found_selectors:
            result['has_dkim'] = True
            result['dkim_selectors'] = found_selectors  # Store as array

        return result

if __name__ == '__main__':
    daemon = EmailDaemon()
    daemon.run()
