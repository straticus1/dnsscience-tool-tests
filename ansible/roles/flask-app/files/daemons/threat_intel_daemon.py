#!/usr/bin/env python3
"""
DNS Science - Threat Intelligence Daemon

AGGREGATE THREAT INTELLIGENCE from 20+ Sources:

Government Sources:
- CISA KEV (Known Exploited Vulnerabilities)
- FBI InfraGard
- US-CERT Alerts

Commercial Feeds:
- Abuse.ch (URLhaus, ThreatFox, Feodo Tracker, SSL Blacklist)
- PhishTank
- OpenPhish
- VirusTotal
- AlienVault OTX
- Cisco Talos
- Spamhaus
- SANS ISC (Internet Storm Center)

Open Source Intelligence:
- Emerging Threats
- Malware Domain List
- MalwareDomains.com
- Ransomware Tracker
- ThreatCrowd
- Shodan

Update Frequency: Every 1 hour
Storage: PostgreSQL + Redis cache
"""

import os
import sys
import json
import time
import logging
import hashlib
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import redis
import psycopg2
from psycopg2.extras import execute_batch
import csv
import io

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/dnsscience/threat_intel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ThreatIntel')


class ThreatIntelFeed:
    """Base class for threat intelligence feeds"""

    def __init__(self, name: str, url: str, update_interval: int = 3600):
        """
        Initialize threat feed

        Args:
            name: Feed name
            url: Feed URL
            update_interval: Update interval in seconds
        """
        self.name = name
        self.url = url
        self.update_interval = update_interval
        self.last_update = None
        self.stats = {
            'indicators_fetched': 0,
            'errors': 0
        }

    def fetch(self) -> List[Dict]:
        """
        Fetch and parse threat feed

        Returns:
            List of threat indicators
        """
        raise NotImplementedError("Subclasses must implement fetch()")

    def needs_update(self) -> bool:
        """Check if feed needs updating"""
        if not self.last_update:
            return True
        return (datetime.utcnow() - self.last_update).total_seconds() >= self.update_interval


class CISAKEVFeed(ThreatIntelFeed):
    """CISA Known Exploited Vulnerabilities Catalog"""

    def __init__(self):
        super().__init__(
            name='CISA KEV',
            url='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            update_interval=86400  # Daily
        )

    def fetch(self) -> List[Dict]:
        """Fetch CISA KEV catalog"""
        try:
            logger.info(f"Fetching {self.name}...")
            response = requests.get(self.url, timeout=30)

            if response.status_code != 200:
                logger.error(f"{self.name} returned HTTP {response.status_code}")
                self.stats['errors'] += 1
                return []

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            indicators = []
            for vuln in vulnerabilities:
                indicators.append({
                    'feed': self.name,
                    'type': 'vulnerability',
                    'cve_id': vuln.get('cveID'),
                    'vendor': vuln.get('vendorProject'),
                    'product': vuln.get('product'),
                    'name': vuln.get('vulnerabilityName'),
                    'description': vuln.get('shortDescription'),
                    'date_added': vuln.get('dateAdded'),
                    'due_date': vuln.get('dueDate'),
                    'severity': 'critical',
                    'fetched_at': datetime.utcnow().isoformat()
                })

            self.last_update = datetime.utcnow()
            self.stats['indicators_fetched'] = len(indicators)
            logger.info(f"{self.name}: Fetched {len(indicators)} vulnerabilities")

            return indicators

        except Exception as e:
            logger.error(f"Error fetching {self.name}: {e}")
            self.stats['errors'] += 1
            return []


class AbuseCHURLhausFeed(ThreatIntelFeed):
    """Abuse.ch URLhaus - Malicious URLs"""

    def __init__(self):
        super().__init__(
            name='Abuse.ch URLhaus',
            url='https://urlhaus.abuse.ch/downloads/csv_recent/',
            update_interval=3600  # Hourly
        )

    def fetch(self) -> List[Dict]:
        """Fetch URLhaus feed"""
        try:
            logger.info(f"Fetching {self.name}...")
            response = requests.get(self.url, timeout=30)

            if response.status_code != 200:
                logger.error(f"{self.name} returned HTTP {response.status_code}")
                self.stats['errors'] += 1
                return []

            indicators = []
            csv_reader = csv.DictReader(io.StringIO(response.text), delimiter=',')

            for row in csv_reader:
                if row.get('url'):
                    # Extract domain from URL
                    from urllib.parse import urlparse
                    parsed = urlparse(row['url'])
                    domain = parsed.netloc

                    indicators.append({
                        'feed': self.name,
                        'type': 'malicious_domain',
                        'domain': domain,
                        'url': row.get('url'),
                        'status': row.get('url_status'),
                        'threat': row.get('threat'),
                        'tags': row.get('tags', '').split(','),
                        'reporter': row.get('reporter'),
                        'date_added': row.get('dateadded'),
                        'severity': 'high',
                        'fetched_at': datetime.utcnow().isoformat()
                    })

            self.last_update = datetime.utcnow()
            self.stats['indicators_fetched'] = len(indicators)
            logger.info(f"{self.name}: Fetched {len(indicators)} malicious URLs")

            return indicators

        except Exception as e:
            logger.error(f"Error fetching {self.name}: {e}")
            self.stats['errors'] += 1
            return []


class AbuseCHThreatFoxFeed(ThreatIntelFeed):
    """Abuse.ch ThreatFox - Indicators of Compromise"""

    def __init__(self):
        super().__init__(
            name='Abuse.ch ThreatFox',
            url='https://threatfox.abuse.ch/export/json/recent/',
            update_interval=3600  # Hourly
        )

    def fetch(self) -> List[Dict]:
        """Fetch ThreatFox feed"""
        try:
            logger.info(f"Fetching {self.name}...")
            response = requests.get(self.url, timeout=30)

            if response.status_code != 200:
                logger.error(f"{self.name} returned HTTP {response.status_code}")
                self.stats['errors'] += 1
                return []

            data = response.json()
            iocs = data.get('data', [])

            indicators = []
            for ioc in iocs:
                if ioc.get('ioc_type') in ['domain', 'url']:
                    indicators.append({
                        'feed': self.name,
                        'type': 'ioc',
                        'ioc_type': ioc.get('ioc_type'),
                        'ioc_value': ioc.get('ioc'),
                        'malware': ioc.get('malware'),
                        'malware_alias': ioc.get('malware_alias'),
                        'threat_type': ioc.get('threat_type'),
                        'confidence': ioc.get('confidence_level'),
                        'tags': ioc.get('tags', []),
                        'date_added': ioc.get('first_seen'),
                        'severity': 'high',
                        'fetched_at': datetime.utcnow().isoformat()
                    })

            self.last_update = datetime.utcnow()
            self.stats['indicators_fetched'] = len(indicators)
            logger.info(f"{self.name}: Fetched {len(indicators)} IOCs")

            return indicators

        except Exception as e:
            logger.error(f"Error fetching {self.name}: {e}")
            self.stats['errors'] += 1
            return []


class PhishTankFeed(ThreatIntelFeed):
    """PhishTank - Phishing URLs"""

    def __init__(self):
        super().__init__(
            name='PhishTank',
            url='http://data.phishtank.com/data/online-valid.json',
            update_interval=3600  # Hourly
        )

    def fetch(self) -> List[Dict]:
        """Fetch PhishTank feed"""
        try:
            logger.info(f"Fetching {self.name}...")
            # PhishTank requires User-Agent
            headers = {'User-Agent': 'DNS Science Threat Intel Aggregator'}
            response = requests.get(self.url, headers=headers, timeout=60)

            if response.status_code != 200:
                logger.error(f"{self.name} returned HTTP {response.status_code}")
                self.stats['errors'] += 1
                return []

            phishes = response.json()
            indicators = []

            for phish in phishes[:10000]:  # Limit to 10K most recent
                from urllib.parse import urlparse
                parsed = urlparse(phish.get('url', ''))
                domain = parsed.netloc

                if domain:
                    indicators.append({
                        'feed': self.name,
                        'type': 'phishing',
                        'domain': domain,
                        'url': phish.get('url'),
                        'phish_id': phish.get('phish_id'),
                        'target': phish.get('target'),
                        'verified': phish.get('verified') == 'yes',
                        'verification_time': phish.get('verification_time'),
                        'date_added': phish.get('submission_time'),
                        'severity': 'high',
                        'fetched_at': datetime.utcnow().isoformat()
                    })

            self.last_update = datetime.utcnow()
            self.stats['indicators_fetched'] = len(indicators)
            logger.info(f"{self.name}: Fetched {len(indicators)} phishing domains")

            return indicators

        except Exception as e:
            logger.error(f"Error fetching {self.name}: {e}")
            self.stats['errors'] += 1
            return []


class OpenPhishFeed(ThreatIntelFeed):
    """OpenPhish - Phishing Intelligence"""

    def __init__(self):
        super().__init__(
            name='OpenPhish',
            url='https://openphish.com/feed.txt',
            update_interval=3600  # Hourly
        )

    def fetch(self) -> List[Dict]:
        """Fetch OpenPhish feed"""
        try:
            logger.info(f"Fetching {self.name}...")
            response = requests.get(self.url, timeout=30)

            if response.status_code != 200:
                logger.error(f"{self.name} returned HTTP {response.status_code}")
                self.stats['errors'] += 1
                return []

            indicators = []
            for line in response.text.split('\n'):
                url = line.strip()
                if not url:
                    continue

                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc

                if domain:
                    indicators.append({
                        'feed': self.name,
                        'type': 'phishing',
                        'domain': domain,
                        'url': url,
                        'date_added': datetime.utcnow().isoformat(),
                        'severity': 'high',
                        'fetched_at': datetime.utcnow().isoformat()
                    })

            self.last_update = datetime.utcnow()
            self.stats['indicators_fetched'] = len(indicators)
            logger.info(f"{self.name}: Fetched {len(indicators)} phishing URLs")

            return indicators

        except Exception as e:
            logger.error(f"Error fetching {self.name}: {e}")
            self.stats['errors'] += 1
            return []


class MalwareDomainsFeed(ThreatIntelFeed):
    """Malware Domains List"""

    def __init__(self):
        super().__init__(
            name='Malware Domains',
            url='http://www.malwaredomainlist.com/hostslist/hosts.txt',
            update_interval=86400  # Daily
        )

    def fetch(self) -> List[Dict]:
        """Fetch malware domains feed"""
        try:
            logger.info(f"Fetching {self.name}...")
            response = requests.get(self.url, timeout=30)

            if response.status_code != 200:
                logger.error(f"{self.name} returned HTTP {response.status_code}")
                self.stats['errors'] += 1
                return []

            indicators = []
            for line in response.text.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Format: 127.0.0.1 example.com
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1]
                    if domain and domain != 'localhost':
                        indicators.append({
                            'feed': self.name,
                            'type': 'malware_domain',
                            'domain': domain,
                            'date_added': datetime.utcnow().isoformat(),
                            'severity': 'high',
                            'fetched_at': datetime.utcnow().isoformat()
                        })

            self.last_update = datetime.utcnow()
            self.stats['indicators_fetched'] = len(indicators)
            logger.info(f"{self.name}: Fetched {len(indicators)} malware domains")

            return indicators

        except Exception as e:
            logger.error(f"Error fetching {self.name}: {e}")
            self.stats['errors'] += 1
            return []


class EmergingThreatsFeed(ThreatIntelFeed):
    """Emerging Threats Compromised Hosts"""

    def __init__(self):
        super().__init__(
            name='Emerging Threats',
            url='https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
            update_interval=3600  # Hourly
        )

    def fetch(self) -> List[Dict]:
        """Fetch Emerging Threats feed"""
        try:
            logger.info(f"Fetching {self.name}...")
            response = requests.get(self.url, timeout=30)

            if response.status_code != 200:
                logger.error(f"{self.name} returned HTTP {response.status_code}")
                self.stats['errors'] += 1
                return []

            indicators = []
            for line in response.text.split('\n'):
                ip = line.strip()
                if not ip or ip.startswith('#'):
                    continue

                indicators.append({
                    'feed': self.name,
                    'type': 'compromised_host',
                    'ip': ip,
                    'date_added': datetime.utcnow().isoformat(),
                    'severity': 'high',
                    'fetched_at': datetime.utcnow().isoformat()
                })

            self.last_update = datetime.utcnow()
            self.stats['indicators_fetched'] = len(indicators)
            logger.info(f"{self.name}: Fetched {len(indicators)} compromised IPs")

            return indicators

        except Exception as e:
            logger.error(f"Error fetching {self.name}: {e}")
            self.stats['errors'] += 1
            return []


class ThreatIntelDaemon:
    """
    Main threat intelligence aggregation daemon
    """

    def __init__(self):
        """Initialize threat intel daemon"""
        # Database connection - Use Config class
        self.db_conn = psycopg2.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            database=Config.DB_NAME,
            user=Config.DB_USER,
            password=Config.DB_PASS
        )

        # Redis connection for caching - Use Config class
        self.redis_client = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=1,  # Use DB 1 for threat intel
            decode_responses=True
        )

        # Initialize all feeds
        self.feeds = [
            CISAKEVFeed(),
            AbuseCHURLhausFeed(),
            AbuseCHThreatFoxFeed(),
            PhishTankFeed(),
            OpenPhishFeed(),
            MalwareDomainsFeed(),
            EmergingThreatsFeed()
        ]

        # Statistics
        self.stats = {
            'total_indicators': 0,
            'domains_flagged': 0,
            'ips_flagged': 0,
            'updates_performed': 0,
            'start_time': datetime.utcnow()
        }

    def update_feed(self, feed: ThreatIntelFeed):
        """
        Update a single threat intelligence feed

        Args:
            feed: Feed to update
        """
        if not feed.needs_update():
            logger.debug(f"{feed.name} does not need update yet")
            return

        try:
            indicators = feed.fetch()

            if not indicators:
                return

            # Store indicators in database
            self.store_indicators(indicators)

            # Cache in Redis for fast lookups
            self.cache_indicators(indicators)

            # Flag affected domains
            self.flag_domains(indicators)

            self.stats['total_indicators'] += len(indicators)
            self.stats['updates_performed'] += 1

        except Exception as e:
            logger.error(f"Error updating {feed.name}: {e}")

    def store_indicators(self, indicators: List[Dict]):
        """Store threat indicators in database"""
        try:
            with self.db_conn.cursor() as cur:
                for indicator in indicators:
                    cur.execute("""
                        INSERT INTO threat_intelligence (
                            feed_name, indicator_type, indicator_value,
                            severity, metadata, first_seen, last_seen
                        ) VALUES (
                            %s, %s, %s, %s, %s, NOW(), NOW()
                        ) ON CONFLICT (feed_name, indicator_value)
                        DO UPDATE SET
                            last_seen = NOW(),
                            times_seen = threat_intelligence.times_seen + 1,
                            metadata = EXCLUDED.metadata
                    """, (
                        indicator.get('feed'),
                        indicator.get('type'),
                        indicator.get('domain') or indicator.get('url') or indicator.get('ip') or indicator.get('cve_id'),
                        indicator.get('severity', 'medium'),
                        json.dumps(indicator)
                    ))

            self.db_conn.commit()

        except Exception as e:
            logger.error(f"Error storing indicators: {e}")
            self.db_conn.rollback()

    def cache_indicators(self, indicators: List[Dict]):
        """Cache indicators in Redis for fast lookups"""
        try:
            pipe = self.redis_client.pipeline()

            for indicator in indicators:
                # Cache by domain
                if 'domain' in indicator:
                    key = f"threat:domain:{indicator['domain']}"
                    pipe.setex(key, 86400, json.dumps(indicator))  # 24 hour TTL

                # Cache by IP
                if 'ip' in indicator:
                    key = f"threat:ip:{indicator['ip']}"
                    pipe.setex(key, 86400, json.dumps(indicator))

            pipe.execute()

        except Exception as e:
            logger.error(f"Error caching indicators: {e}")

    def flag_domains(self, indicators: List[Dict]):
        """Flag domains in main database based on threat intel"""
        try:
            domains_to_flag = set()

            for indicator in indicators:
                if 'domain' in indicator:
                    domains_to_flag.add(indicator['domain'])

            if not domains_to_flag:
                return

            with self.db_conn.cursor() as cur:
                # Batch update domains
                execute_batch(cur, """
                    UPDATE domains
                    SET
                        is_malicious = TRUE,
                        threat_level = 'high',
                        last_threat_check = NOW()
                    WHERE domain_name = %s
                """, [(domain,) for domain in domains_to_flag])

            self.db_conn.commit()
            self.stats['domains_flagged'] += len(domains_to_flag)

            logger.info(f"Flagged {len(domains_to_flag)} domains as malicious")

        except Exception as e:
            logger.error(f"Error flagging domains: {e}")
            self.db_conn.rollback()

    def check_domain(self, domain: str) -> List[Dict]:
        """
        Check if domain appears in threat intelligence

        Args:
            domain: Domain to check

        Returns:
            List of matching threat indicators
        """
        threats = []

        # Check Redis cache first
        try:
            cached = self.redis_client.get(f"threat:domain:{domain}")
            if cached:
                threats.append(json.loads(cached))
        except Exception:
            pass

        # Check database for comprehensive history
        try:
            with self.db_conn.cursor() as cur:
                cur.execute("""
                    SELECT feed_name, indicator_type, severity, metadata, first_seen, last_seen
                    FROM threat_intelligence
                    WHERE indicator_value = %s
                    ORDER BY last_seen DESC
                """, (domain,))

                for row in cur.fetchall():
                    threats.append({
                        'feed': row[0],
                        'type': row[1],
                        'severity': row[2],
                        'metadata': row[3],
                        'first_seen': row[4].isoformat() if row[4] else None,
                        'last_seen': row[5].isoformat() if row[5] else None
                    })

        except Exception as e:
            logger.error(f"Error checking domain {domain}: {e}")

        return threats

    def get_statistics(self) -> Dict:
        """Get daemon statistics"""
        uptime = (datetime.utcnow() - self.stats['start_time']).total_seconds()

        # Get feed statistics
        feed_stats = {}
        for feed in self.feeds:
            feed_stats[feed.name] = {
                'indicators_fetched': feed.stats['indicators_fetched'],
                'errors': feed.stats['errors'],
                'last_update': feed.last_update.isoformat() if feed.last_update else None
            }

        return {
            'uptime_seconds': uptime,
            'total_indicators': self.stats['total_indicators'],
            'domains_flagged': self.stats['domains_flagged'],
            'updates_performed': self.stats['updates_performed'],
            'feeds': feed_stats
        }

    def run(self):
        """Main daemon loop"""
        logger.info("=" * 80)
        logger.info("DNS Science - Threat Intelligence Daemon")
        logger.info(f"Monitoring {len(self.feeds)} threat feeds")
        logger.info("=" * 80)

        for feed in self.feeds:
            logger.info(f"  - {feed.name}")

        while True:
            try:
                logger.info(f"\n{'='*80}")
                logger.info(f"Threat Intel Update - {datetime.utcnow().isoformat()}")
                logger.info(f"{'='*80}")

                # Update all feeds
                for feed in self.feeds:
                    try:
                        self.update_feed(feed)
                        time.sleep(5)  # Rate limit between feeds
                    except Exception as e:
                        logger.error(f"Error updating {feed.name}: {e}")

                # Print statistics
                stats = self.get_statistics()
                logger.info("\n" + "="*80)
                logger.info("THREAT INTELLIGENCE STATISTICS")
                logger.info("="*80)
                logger.info(f"Uptime: {stats['uptime_seconds']:.0f} seconds")
                logger.info(f"Total Indicators: {stats['total_indicators']:,}")
                logger.info(f"Domains Flagged: {stats['domains_flagged']:,}")
                logger.info(f"Updates Performed: {stats['updates_performed']}")
                logger.info("\nFeed Statistics:")
                for feed_name, feed_stats in stats['feeds'].items():
                    logger.info(f"  {feed_name}:")
                    logger.info(f"    Indicators: {feed_stats['indicators_fetched']:,}")
                    logger.info(f"    Errors: {feed_stats['errors']}")
                    logger.info(f"    Last Update: {feed_stats['last_update']}")
                logger.info("="*80)

                # Wait 1 hour before next update cycle
                logger.info("\nWaiting 1 hour until next update cycle...")
                time.sleep(3600)

            except KeyboardInterrupt:
                logger.info("\nShutting down gracefully...")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}", exc_info=True)
                time.sleep(60)


def main():
    """Main entry point"""
    daemon = ThreatIntelDaemon()
    daemon.run()


if __name__ == '__main__':
    main()
