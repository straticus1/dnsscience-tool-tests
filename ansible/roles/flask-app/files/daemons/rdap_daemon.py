#!/usr/bin/env python3
"""
DNS Science - RDAP Daemon

RDAP (Registration Data Access Protocol) - RFC 9082/9083
Modern replacement for WHOIS with structured JSON responses

Collects:
- Domain registration data (registrar, dates, status)
- Contact information (where not privacy-protected)
- Name servers
- DNSSEC delegation info
- Transfer/update/delete policies

Processing Rate: 100 domains/minute (rate-limited)
Workers: 10 parallel workers
Queue: Redis with domain buffer
"""

import os
import sys
import json
import time
import logging
import requests
import concurrent.futures
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import redis
import psycopg2
from psycopg2.extras import execute_batch
from urllib.parse import urljoin

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/dnsscience/rdap.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('RDAP')


class RDAPClient:
    """RDAP client for querying domain registration data"""

    # IANA RDAP Bootstrap Service
    BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

    def __init__(self):
        """Initialize RDAP client"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DNS-Science-RDAP/1.0 (https://dnsscience.io)',
            'Accept': 'application/rdap+json, application/json'
        })

        # Cache of TLD -> RDAP server mappings
        self.rdap_servers = {}
        self.load_rdap_servers()

        # Rate limiting
        self.last_request_time = {}
        self.min_request_interval = 1.0  # 1 second between requests to same server

    def load_rdap_servers(self):
        """Load RDAP server mappings from IANA bootstrap"""
        try:
            response = self.session.get(self.BOOTSTRAP_URL, timeout=10)
            if response.status_code == 200:
                data = response.json()

                # Parse services array
                for service in data.get('services', []):
                    if len(service) >= 2:
                        tlds = service[0]
                        servers = service[1]

                        if servers:
                            rdap_server = servers[0]
                            for tld in tlds:
                                self.rdap_servers[tld.lower()] = rdap_server

                logger.info(f"Loaded {len(self.rdap_servers)} RDAP server mappings")

        except Exception as e:
            logger.error(f"Error loading RDAP bootstrap: {e}")

            # Fallback to hardcoded common servers
            self.rdap_servers = {
                'com': 'https://rdap.verisign.com/com/v1/',
                'net': 'https://rdap.verisign.com/net/v1/',
                'org': 'https://rdap.publicinterestregistry.org/',
                'info': 'https://rdap.afilias-srs.net/rdap/info/',
                'io': 'https://rdap.nic.io/',
                'ai': 'https://rdap.nic.ai/',
                'app': 'https://www.registry.google/rdap/',
                'dev': 'https://www.registry.google/rdap/',
            }

    def get_rdap_server(self, domain: str) -> Optional[str]:
        """Get RDAP server for domain's TLD"""
        tld = domain.split('.')[-1].lower()
        return self.rdap_servers.get(tld)

    def rate_limit(self, server_url: str):
        """Apply rate limiting for RDAP server"""
        if server_url in self.last_request_time:
            elapsed = time.time() - self.last_request_time[server_url]
            if elapsed < self.min_request_interval:
                time.sleep(self.min_request_interval - elapsed)

        self.last_request_time[server_url] = time.time()

    def query_domain(self, domain: str) -> Optional[Dict]:
        """
        Query RDAP for domain information

        Args:
            domain: Domain name to query

        Returns:
            RDAP response data or None
        """
        rdap_server = self.get_rdap_server(domain)
        if not rdap_server:
            logger.warning(f"No RDAP server found for {domain}")
            return None

        try:
            # Apply rate limiting
            self.rate_limit(rdap_server)

            # Construct RDAP query URL
            url = urljoin(rdap_server, f'domain/{domain}')

            start_time = time.time()
            response = self.session.get(url, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            result = {
                'rdap_server_url': rdap_server,
                'http_status_code': response.status_code,
                'response_time_ms': response_time,
                'success': False,
                'data': None,
                'error_message': None
            }

            if response.status_code == 200:
                result['success'] = True
                result['data'] = response.json()
            elif response.status_code == 404:
                result['error_message'] = 'Domain not found in RDAP'
            elif response.status_code == 429:
                result['error_message'] = 'Rate limited by RDAP server'
            else:
                result['error_message'] = f'HTTP {response.status_code}'

            return result

        except requests.exceptions.Timeout:
            return {
                'rdap_server_url': rdap_server,
                'http_status_code': 0,
                'success': False,
                'error_message': 'Request timeout'
            }
        except Exception as e:
            return {
                'rdap_server_url': rdap_server,
                'http_status_code': 0,
                'success': False,
                'error_message': str(e)
            }


class RDAPParser:
    """Parse RDAP JSON responses into structured data"""

    @staticmethod
    def parse_rdap_response(rdap_data: Dict) -> Dict:
        """
        Parse RDAP JSON response

        Args:
            rdap_data: Raw RDAP JSON response

        Returns:
            Parsed structured data
        """
        parsed = {
            'rdap_conformance': rdap_data.get('rdapConformance', []),
            'status': rdap_data.get('status', []),
            'nameservers': [],
            'events': {},
            'registrar': {},
            'secure_dns': {},
            'entities': [],
            'links': rdap_data.get('links', [])
        }

        # Parse nameservers
        for ns in rdap_data.get('nameservers', []):
            if 'ldhName' in ns:
                parsed['nameservers'].append(ns['ldhName'])

        # Parse events (registration, expiration, last changed)
        for event in rdap_data.get('events', []):
            event_action = event.get('eventAction')
            event_date = event.get('eventDate')

            if event_action and event_date:
                parsed['events'][event_action] = event_date

        # Parse entities (registrar, registrant, admin, tech)
        for entity in rdap_data.get('entities', []):
            roles = entity.get('roles', [])
            entity_data = {
                'handle': entity.get('handle'),
                'roles': roles,
                'vcard': entity.get('vcardArray', [None, []])[1] if 'vcardArray' in entity else []
            }

            # Extract vCard data
            vcard_dict = RDAPParser.parse_vcard(entity_data['vcard'])
            entity_data.update(vcard_dict)

            # Special handling for registrar
            if 'registrar' in roles:
                parsed['registrar'] = {
                    'name': entity.get('publicIds', [{}])[0].get('identifier') if entity.get('publicIds') else None,
                    'handle': entity.get('handle'),
                    'url': None,
                    'abuse_email': None,
                    'abuse_phone': None
                }

                # Extract abuse contact
                for sub_entity in entity.get('entities', []):
                    if 'abuse' in sub_entity.get('roles', []):
                        abuse_vcard = RDAPParser.parse_vcard(
                            sub_entity.get('vcardArray', [None, []])[1] if 'vcardArray' in sub_entity else []
                        )
                        parsed['registrar']['abuse_email'] = abuse_vcard.get('email')
                        parsed['registrar']['abuse_phone'] = abuse_vcard.get('phone')

            parsed['entities'].append(entity_data)

        # Parse secureDNS (DNSSEC)
        secure_dns = rdap_data.get('secureDNS', {})
        if secure_dns:
            parsed['secure_dns'] = {
                'delegated': secure_dns.get('zoneSigned', False),
                'zone_signed': secure_dns.get('zoneSigned', False),
                'ds_data': secure_dns.get('dsData', []),
                'key_data': secure_dns.get('keyData', [])
            }

        return parsed

    @staticmethod
    def parse_vcard(vcard_array: List) -> Dict:
        """
        Parse vCard data from RDAP entity

        Args:
            vcard_array: vCard array from RDAP response

        Returns:
            Parsed contact data
        """
        contact = {
            'name': None,
            'organization': None,
            'email': None,
            'phone': None,
            'street': None,
            'city': None,
            'state': None,
            'postal_code': None,
            'country': None
        }

        for field in vcard_array:
            if len(field) < 4:
                continue

            field_name = field[0].lower()
            field_value = field[3]

            if field_name == 'fn':  # Full name
                contact['name'] = field_value
            elif field_name == 'org':
                contact['organization'] = field_value
            elif field_name == 'email':
                contact['email'] = field_value
            elif field_name == 'tel':
                contact['phone'] = field_value
            elif field_name == 'adr':  # Address
                if isinstance(field_value, list) and len(field_value) >= 7:
                    contact['street'] = field_value[2]
                    contact['city'] = field_value[3]
                    contact['state'] = field_value[4]
                    contact['postal_code'] = field_value[5]
                    contact['country'] = field_value[6]

        return contact


class RDAPWorker:
    """Worker that processes RDAP lookups for domains"""

    def __init__(self, worker_id: int, db_config: Dict):
        """
        Initialize RDAP worker

        Args:
            worker_id: Unique worker identifier
            db_config: Database configuration
        """
        self.worker_id = worker_id
        self.db_config = db_config
        self.rdap_client = RDAPClient()
        self.rdap_parser = RDAPParser()

        # Statistics
        self.stats = {
            'domains_processed': 0,
            'successful_queries': 0,
            'failed_queries': 0,
            'rate_limited': 0
        }

    def process_domain(self, domain: str, domain_id: Optional[int] = None) -> Dict:
        """
        Process RDAP lookup for domain

        Args:
            domain: Domain name
            domain_id: Optional database domain ID

        Returns:
            Processing result
        """
        logger.info(f"[Worker {self.worker_id}] Querying RDAP for {domain}")

        result = {
            'domain': domain,
            'domain_id': domain_id,
            'success': False,
            'data': None,
            'error': None
        }

        try:
            # Query RDAP
            rdap_result = self.rdap_client.query_domain(domain)

            if not rdap_result:
                result['error'] = 'No RDAP server available'
                self.stats['failed_queries'] += 1
                return result

            # Log query
            self.log_query(domain, rdap_result)

            if not rdap_result['success']:
                result['error'] = rdap_result.get('error_message', 'Unknown error')

                if rdap_result.get('http_status_code') == 429:
                    self.stats['rate_limited'] += 1
                else:
                    self.stats['failed_queries'] += 1

                return result

            # Parse RDAP data
            parsed_data = self.rdap_parser.parse_rdap_response(rdap_result['data'])

            # Extract key fields
            events = parsed_data.get('events', {})

            result['success'] = True
            result['data'] = {
                'domain_name': domain,
                'domain_id': domain_id,
                'rdap_server_url': rdap_result['rdap_server_url'],
                'rdap_conformance': parsed_data.get('rdap_conformance', []),
                'status': parsed_data.get('status', []),
                'registrar_name': parsed_data.get('registrar', {}).get('name'),
                'registrar_iana_id': None,  # Would need lookup table
                'registrar_url': parsed_data.get('registrar', {}).get('url'),
                'registrar_abuse_email': parsed_data.get('registrar', {}).get('abuse_email'),
                'registrar_abuse_phone': parsed_data.get('registrar', {}).get('abuse_phone'),
                'registration_date': events.get('registration'),
                'expiration_date': events.get('expiration'),
                'last_changed_date': events.get('last changed'),
                'last_update_of_rdap_db': events.get('last update of RDAP database'),
                'nameservers': parsed_data.get('nameservers', []),
                'secure_dns_delegated': parsed_data.get('secure_dns', {}).get('delegated', False),
                'secure_dns_zone_signed': parsed_data.get('secure_dns', {}).get('zone_signed', False),
                'ds_data': json.dumps(parsed_data.get('secure_dns', {}).get('ds_data', [])),
                'key_data': json.dumps(parsed_data.get('secure_dns', {}).get('key_data', [])),
                'registrant_entity': json.dumps(next(
                    (e for e in parsed_data.get('entities', []) if 'registrant' in e.get('roles', [])),
                    None
                )),
                'admin_entity': json.dumps(next(
                    (e for e in parsed_data.get('entities', []) if 'administrative' in e.get('roles', [])),
                    None
                )),
                'tech_entity': json.dumps(next(
                    (e for e in parsed_data.get('entities', []) if 'technical' in e.get('roles', [])),
                    None
                )),
                'raw_response': json.dumps(rdap_result['data']),
                'related_links': json.dumps(parsed_data.get('links', [])),
                'http_status_code': rdap_result['http_status_code']
            }

            self.stats['successful_queries'] += 1
            self.stats['domains_processed'] += 1

            logger.info(f"[Worker {self.worker_id}] ✓ {domain} - Registrar: {result['data'].get('registrar_name')}")

        except Exception as e:
            logger.error(f"[Worker {self.worker_id}] Error processing {domain}: {e}")
            result['error'] = str(e)
            self.stats['failed_queries'] += 1

        return result

    def log_query(self, domain: str, rdap_result: Dict):
        """Log RDAP query to database"""
        try:
            conn = psycopg2.connect(**self.db_config)
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO rdap_query_log (
                        domain_name, rdap_server_url, http_status_code,
                        response_time_ms, success, error_message
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    domain,
                    rdap_result.get('rdap_server_url'),
                    rdap_result.get('http_status_code'),
                    rdap_result.get('response_time_ms'),
                    rdap_result.get('success', False),
                    rdap_result.get('error_message')
                ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug(f"Error logging query for {domain}: {e}")


class RDAPDaemon:
    """
    Main RDAP daemon that manages workers and queue
    """

    def __init__(self, num_workers: int = 10):
        """
        Initialize RDAP daemon

        Args:
            num_workers: Number of parallel workers
        """
        self.num_workers = num_workers

        # Database configuration
        self.db_config = {
            'host': Config.DB_HOST,
            'port': Config.DB_PORT,
            'database': Config.DB_NAME,
            'user': Config.DB_USER,
            'password': Config.DB_PASS
        }

        # Database connection for main thread
        self.db_conn = psycopg2.connect(**self.db_config)

        # Redis connection
        self.redis_client = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=0,
            decode_responses=True
        )

        # Thread pool for workers
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=num_workers)

        # Statistics
        self.stats = {
            'total_processed': 0,
            'total_successful': 0,
            'total_failed': 0,
            'start_time': datetime.utcnow()
        }

    def get_next_domain(self) -> Optional[Tuple[str, int]]:
        """
        Get next domain from database that needs RDAP lookup

        Returns:
            (domain, domain_id) tuple or None
        """
        try:
            with self.db_conn.cursor() as cur:
                # Get domains that have never had RDAP lookup or are stale (>30 days)
                cur.execute("""
                    SELECT d.id, d.domain_name
                    FROM domains d
                    LEFT JOIN rdap_domains r ON d.id = r.domain_id AND r.is_current = TRUE
                    WHERE r.id IS NULL
                       OR r.query_timestamp < NOW() - INTERVAL '30 days'
                    ORDER BY d.last_checked DESC
                    LIMIT 1
                """)

                row = cur.fetchone()
                if row:
                    return row[1], row[0]  # domain_name, domain_id

        except Exception as e:
            logger.error(f"Error getting next domain: {e}")

        return None

    def save_rdap_data(self, rdap_data: Dict):
        """Save RDAP data to database"""
        try:
            with self.db_conn.cursor() as cur:
                # Mark old record as not current
                cur.execute("""
                    UPDATE rdap_domains
                    SET is_current = FALSE
                    WHERE domain_id = %s AND is_current = TRUE
                """, (rdap_data.get('domain_id'),))

                # Insert new record
                cur.execute("""
                    INSERT INTO rdap_domains (
                        domain_id, domain_name, rdap_server_url, rdap_conformance,
                        status, registrar_name, registrar_iana_id, registrar_url,
                        registrar_abuse_email, registrar_abuse_phone,
                        registration_date, expiration_date, last_changed_date,
                        last_update_of_rdap_db, nameservers,
                        secure_dns_delegated, secure_dns_zone_signed,
                        ds_data, key_data, registrant_entity, admin_entity,
                        tech_entity, raw_response, related_links, http_status_code
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s
                    )
                """, (
                    rdap_data.get('domain_id'),
                    rdap_data.get('domain_name'),
                    rdap_data.get('rdap_server_url'),
                    rdap_data.get('rdap_conformance'),
                    rdap_data.get('status'),
                    rdap_data.get('registrar_name'),
                    rdap_data.get('registrar_iana_id'),
                    rdap_data.get('registrar_url'),
                    rdap_data.get('registrar_abuse_email'),
                    rdap_data.get('registrar_abuse_phone'),
                    rdap_data.get('registration_date'),
                    rdap_data.get('expiration_date'),
                    rdap_data.get('last_changed_date'),
                    rdap_data.get('last_update_of_rdap_db'),
                    rdap_data.get('nameservers'),
                    rdap_data.get('secure_dns_delegated'),
                    rdap_data.get('secure_dns_zone_signed'),
                    rdap_data.get('ds_data'),
                    rdap_data.get('key_data'),
                    rdap_data.get('registrant_entity'),
                    rdap_data.get('admin_entity'),
                    rdap_data.get('tech_entity'),
                    rdap_data.get('raw_response'),
                    rdap_data.get('related_links'),
                    rdap_data.get('http_status_code')
                ))

            self.db_conn.commit()
            self.stats['total_successful'] += 1

        except Exception as e:
            logger.error(f"Error saving RDAP data for {rdap_data.get('domain_name')}: {e}")
            self.db_conn.rollback()
            self.stats['total_failed'] += 1

    def run(self):
        """Main daemon loop"""
        logger.info("=" * 80)
        logger.info("DNS Science - RDAP Daemon")
        logger.info(f"Workers: {self.num_workers}")
        logger.info("=" * 80)

        batch = []
        batch_size = self.num_workers

        while True:
            try:
                # Get batch of domains
                for _ in range(batch_size):
                    result = self.get_next_domain()
                    if result:
                        batch.append(result)

                if not batch:
                    logger.info("No domains need RDAP lookup, waiting...")
                    time.sleep(60)
                    continue

                # Process batch in parallel
                logger.info(f"Processing batch of {len(batch)} domains...")

                futures = []
                for domain, domain_id in batch:
                    worker = RDAPWorker(len(futures), self.db_config)
                    future = self.executor.submit(worker.process_domain, domain, domain_id)
                    futures.append((future, domain))

                # Wait for results
                for future, domain in futures:
                    try:
                        result = future.result(timeout=30)
                        if result['success'] and result['data']:
                            self.save_rdap_data(result['data'])
                            self.stats['total_processed'] += 1
                        else:
                            logger.warning(f"Failed to get RDAP for {domain}: {result.get('error')}")
                    except Exception as e:
                        logger.error(f"Error processing {domain}: {e}")

                batch = []

                # Log statistics every 50 domains
                if self.stats['total_processed'] % 50 == 0 and self.stats['total_processed'] > 0:
                    uptime = (datetime.utcnow() - self.stats['start_time']).total_seconds()
                    rate = self.stats['total_processed'] / uptime if uptime > 0 else 0

                    logger.info(f"\nStatistics:")
                    logger.info(f"  Processed: {self.stats['total_processed']:,}")
                    logger.info(f"  Successful: {self.stats['total_successful']:,}")
                    logger.info(f"  Failed: {self.stats['total_failed']:,}")
                    logger.info(f"  Rate: {rate:.2f} domains/sec")
                    logger.info(f"  Uptime: {uptime:.0f} seconds")

                # Rate limiting between batches (60 req/min max)
                time.sleep(6)

            except KeyboardInterrupt:
                logger.info("\nShutting down gracefully...")
                self.executor.shutdown(wait=True)
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}", exc_info=True)
                time.sleep(10)


def main():
    """Main entry point"""
    num_workers = int(os.getenv('RDAP_WORKERS', 10))
    daemon = RDAPDaemon(num_workers=num_workers)
    daemon.run()


if __name__ == '__main__':
    main()
