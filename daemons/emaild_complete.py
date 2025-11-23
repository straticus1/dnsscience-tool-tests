#!/usr/bin/env python3
"""
DNS Science - Email Security Daemon (COMPLETE VERSION)
Monitors: MX, DKIM, SPF, DMARC, DANE/TLSA, and MTA-STS
UPDATED: 2025-11-15 - Added DANE/TLSA and MTA-STS support
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from base_daemon import BaseDaemon
import dns.resolver
import requests
import binascii
import json
from datetime import datetime

class EmailDaemon(BaseDaemon):
    """Daemon for comprehensive email security monitoring"""

    def __init__(self):
        super().__init__('dnsscience_emaild')
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    def process_iteration(self):
        """Check email security records for domains"""
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

                    # Insert or update email security record with ALL fields
                    cursor.execute("""
                        INSERT INTO email_security_records
                        (domain_id, last_checked,
                         has_mx, mx_records, mx_count,
                         has_spf, spf_record, spf_valid,
                         has_dmarc, dmarc_record, dmarc_policy,
                         has_dkim, dkim_selectors,
                         has_dane, tlsa_records, tlsa_count,
                         has_mta_sts, mta_sts_policy, mta_sts_mode, mta_sts_max_age)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                            dkim_selectors = EXCLUDED.dkim_selectors,
                            has_dane = EXCLUDED.has_dane,
                            tlsa_records = EXCLUDED.tlsa_records,
                            tlsa_count = EXCLUDED.tlsa_count,
                            has_mta_sts = EXCLUDED.has_mta_sts,
                            mta_sts_policy = EXCLUDED.mta_sts_policy,
                            mta_sts_mode = EXCLUDED.mta_sts_mode,
                            mta_sts_max_age = EXCLUDED.mta_sts_max_age
                    """, (
                        domain_id, datetime.utcnow(),
                        email_security['has_mx'], email_security['mx_records'],
                        email_security['mx_count'],
                        email_security['has_spf'], email_security['spf_record'],
                        email_security['spf_valid'],
                        email_security['has_dmarc'], email_security['dmarc_record'],
                        email_security['dmarc_policy'],
                        email_security['has_dkim'], email_security['dkim_selectors'],
                        email_security['has_dane'], json.dumps(email_security['tlsa_records']),
                        email_security['tlsa_count'],
                        email_security['has_mta_sts'], email_security['mta_sts_policy'],
                        email_security['mta_sts_mode'], email_security['mta_sts_max_age']
                    ))

                    conn.commit()
                    work_done = True

                    self.logger.info(
                        f"Email security for {domain_name}: "
                        f"MX={email_security['has_mx']}, "
                        f"SPF={email_security['has_spf']}, "
                        f"DMARC={email_security['has_dmarc']}, "
                        f"DKIM={email_security['has_dkim']}, "
                        f"DANE={email_security['has_dane']}, "
                        f"MTA-STS={email_security['has_mta_sts']}"
                    )

                except Exception as e:
                    self.logger.error(f"Error checking email security for {domain_name}: {e}")
                    conn.rollback()

            cursor.close()

        except Exception as e:
            self.logger.error(f"Error in email daemon: {e}")

        return work_done

    def check_email_security(self, domain_name):
        """Check all email security records for a domain"""
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
            'dkim_selectors': None,
            'has_dane': False,
            'tlsa_records': [],
            'tlsa_count': 0,
            'has_mta_sts': False,
            'mta_sts_policy': None,
            'mta_sts_mode': None,
            'mta_sts_max_age': None
        }

        # Check MX records
        try:
            mx_answers = self.resolver.resolve(domain_name, 'MX')
            mx_list = [str(rdata.exchange).rstrip('.') for rdata in mx_answers]
            result['has_mx'] = True
            result['mx_records'] = mx_list
            result['mx_count'] = len(mx_list)
        except:
            pass

        # Check SPF
        try:
            txt_answers = self.resolver.resolve(domain_name, 'TXT')
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
            dmarc_answers = self.resolver.resolve(dmarc_domain, 'TXT')
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
                self.resolver.resolve(dkim_domain, 'TXT')
                found_selectors.append(selector)
            except:
                pass

        if found_selectors:
            result['has_dkim'] = True
            result['dkim_selectors'] = found_selectors

        # Check DANE/TLSA records
        try:
            tlsa_data = self.check_tlsa_records(domain_name)
            if tlsa_data:
                result['has_dane'] = True
                result['tlsa_records'] = tlsa_data
                result['tlsa_count'] = len(tlsa_data)
        except Exception as e:
            self.logger.debug(f"TLSA check failed for {domain_name}: {e}")

        # Check MTA-STS policy
        try:
            mta_sts_data = self.check_mta_sts(domain_name)
            if mta_sts_data:
                result['has_mta_sts'] = True
                result['mta_sts_policy'] = mta_sts_data.get('full_policy')
                result['mta_sts_mode'] = mta_sts_data.get('mode')
                result['mta_sts_max_age'] = mta_sts_data.get('max_age')
        except Exception as e:
            self.logger.debug(f"MTA-STS check failed for {domain_name}: {e}")

        return result

    def check_tlsa_records(self, domain):
        """
        Check for DANE TLSA records on HTTPS (443) and SMTP (25) ports

        TLSA record format:
        - usage: How certificate is validated (0-3)
        - selector: Which part of certificate is matched (0-1)
        - matching_type: How the certificate association is verified (0-2)
        - cert_data: Certificate data (hex encoded)
        """
        tlsa_records = []

        for port in [443, 25]:  # HTTPS and SMTP
            try:
                query = f"_{port}._tcp.{domain}"
                answers = self.resolver.resolve(query, 'TLSA')

                for rdata in answers:
                    tlsa_records.append({
                        'port': port,
                        'usage': rdata.usage,
                        'selector': rdata.selector,
                        'matching_type': rdata.mtype,
                        # Store first 64 chars of cert data (full can be very long)
                        'cert_data': binascii.hexlify(rdata.cert).decode()[:64]
                    })

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                # No TLSA records for this port - this is expected for most domains
                pass
            except Exception as e:
                self.logger.warning(f"TLSA check error for {domain} port {port}: {e}")

        return tlsa_records

    def check_mta_sts(self, domain):
        """
        Check for MTA-STS policy via DNS and HTTPS

        MTA-STS has two components:
        1. DNS TXT record at _mta-sts.<domain> (version indicator)
        2. HTTPS policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt

        Returns parsed policy or None if not configured
        """
        # Step 1: Check DNS TXT record for _mta-sts
        try:
            txt_query = f"_mta-sts.{domain}"
            answers = self.resolver.resolve(txt_query, 'TXT')

            # Found DNS record, now fetch HTTPS policy
            policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"

            try:
                # Fetch policy with reasonable timeout
                response = requests.get(
                    policy_url,
                    timeout=10,
                    verify=True,  # Verify SSL certificate
                    headers={'User-Agent': 'DNSScience-EmailDaemon/1.0'}
                )

                if response.status_code == 200:
                    return self.parse_mta_sts_policy(response.text)
                else:
                    self.logger.debug(
                        f"MTA-STS policy fetch failed for {domain}: "
                        f"HTTP {response.status_code}"
                    )

            except requests.exceptions.SSLError as e:
                self.logger.warning(
                    f"MTA-STS SSL error for {domain}: {e} "
                    "(ironically, MTA-STS host has SSL issues)"
                )
            except requests.exceptions.Timeout:
                self.logger.debug(f"MTA-STS policy fetch timeout for {domain}")
            except requests.exceptions.RequestException as e:
                self.logger.debug(f"MTA-STS HTTPS fetch failed for {domain}: {e}")

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # No MTA-STS DNS record - not an error, just not configured
            pass
        except Exception as e:
            self.logger.warning(f"MTA-STS DNS check failed for {domain}: {e}")

        return None

    def parse_mta_sts_policy(self, policy_text):
        """
        Parse MTA-STS policy file

        Example policy:
        version: STSv1
        mode: enforce
        mx: mail.example.com
        mx: *.example.com
        max_age: 86400
        """
        policy = {
            'mode': None,
            'max_age': None,
            'mx': [],
            'full_policy': policy_text
        }

        for line in policy_text.split('\n'):
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()

                if key == 'mode':
                    policy['mode'] = value
                elif key == 'max_age':
                    try:
                        policy['max_age'] = int(value)
                    except ValueError:
                        self.logger.warning(f"Invalid max_age in MTA-STS policy: {value}")
                elif key == 'mx':
                    policy['mx'].append(value)

        # Validate required fields
        if not policy['mode'] or not policy['max_age']:
            self.logger.warning(f"Incomplete MTA-STS policy: {policy}")
            return None

        return policy

if __name__ == '__main__':
    daemon = EmailDaemon()
    daemon.run()
