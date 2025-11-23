"""
Dark Web DNS Monitoring System for DNS Science

This module provides comprehensive dark web monitoring capabilities including:
- Tor hidden service (.onion) detection and analysis
- I2P eepsite (.i2p) monitoring
- Blockchain DNS (Namecoin .bit, Handshake .hns) resolution
- Tor exit node identification
- Certificate transparency analysis for dark web services

LEGAL COMPLIANCE:
- All operations are PASSIVE monitoring only
- No active crawling of illegal content
- Research and security analysis purposes only
- Full audit logging for compliance
- Complies with CFAA and computer fraud laws

Author: DNS Science Team
Created: 2025-11-13
License: Proprietary
"""

import os
import json
import logging
import hashlib
import requests
import socket
import ssl
import time
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
import ipaddress

# PostgreSQL database
import psycopg2
from psycopg2.extras import RealDictCursor, Json

# DNS resolution
import dns.resolver
import dns.exception

# For certificate analysis
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DarkWebMonitor:
    """
    Comprehensive Dark Web DNS Monitoring System

    Provides passive monitoring of dark web infrastructure including Tor,
    I2P, and blockchain DNS systems while maintaining strict legal compliance.
    """

    def __init__(self, db_connection_string: str, config: Optional[Dict] = None):
        """
        Initialize the Dark Web Monitor

        Args:
            db_connection_string: PostgreSQL connection string
            config: Optional configuration dictionary
        """
        self.db_conn_string = db_connection_string
        self.config = config or {}

        # Tor configuration
        self.tor_enabled = self.config.get('TOR_ENABLED', False)
        self.tor_socks_proxy = self.config.get('TOR_SOCKS_PROXY', 'socks5h://127.0.0.1:9050')

        # API endpoints
        self.tor_metrics_api = "https://metrics.torproject.org"
        self.tor_exit_list_url = "https://check.torproject.org/exit-addresses"
        self.ahmia_api = self.config.get('AHMIA_API', 'https://ahmia.fi/api')

        # Certificate Transparency
        self.ct_log_api = "https://crt.sh"

        # Blockchain DNS
        self.namecoin_rpc = self.config.get('NAMECOIN_RPC')
        self.handshake_rpc = self.config.get('HANDSHAKE_RPC')

        # Rate limiting tiers
        self.rate_limits = {
            'anonymous': 3,
            'free': 5,
            'essentials': 25,
            'professional': 100,
            'research': 250,
            'commercial': 500,
            'enterprise': 999999
        }

        # Cache for frequently accessed data
        self._tor_exit_cache = {'data': None, 'expires': None}
        self._onion_mapping_cache = {}

        logger.info("Dark Web Monitor initialized")

    def _get_db_connection(self):
        """Get a new database connection"""
        return psycopg2.connect(self.db_conn_string)

    def _get_user_tier(self, user_id: Optional[int]) -> str:
        """
        Determine user's subscription tier

        Args:
            user_id: User ID or None for anonymous

        Returns:
            Tier name as string
        """
        if user_id is None:
            return 'anonymous'

        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT subscription_tier, subscription_status
                        FROM users
                        WHERE id = %s
                    """, (user_id,))
                    user = cur.fetchone()

                    if not user:
                        return 'free'

                    if user['subscription_status'] == 'active':
                        return user['subscription_tier'] or 'free'

                    return 'free'
        except Exception as e:
            logger.error(f"Error getting user tier: {e}")
            return 'free'

    def check_rate_limit(self, user_id: Optional[int], ip_address: str) -> Dict[str, Any]:
        """
        Check if user/IP has exceeded rate limit for dark web lookups

        Args:
            user_id: User ID or None for anonymous
            ip_address: IP address of requester

        Returns:
            Dictionary with rate limit status:
            {
                'allowed': bool,
                'remaining': int,
                'reset_at': datetime,
                'tier': str,
                'limit': int
            }
        """
        tier = self._get_user_tier(user_id)
        daily_limit = self.rate_limits.get(tier, 3)

        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    # Use PostgreSQL function to check and increment rate limit
                    cur.execute("""
                        SELECT * FROM check_darkweb_rate_limit(%s, %s, %s)
                    """, (user_id, ip_address, tier))

                    result = cur.fetchone()
                    conn.commit()

                    return {
                        'allowed': result['allowed'],
                        'remaining': result['remaining'],
                        'reset_at': result['reset_at'].isoformat() if result['reset_at'] else None,
                        'tier': tier,
                        'limit': daily_limit
                    }
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            # Fail closed - deny access on error
            return {
                'allowed': False,
                'remaining': 0,
                'reset_at': None,
                'tier': tier,
                'limit': daily_limit,
                'error': str(e)
            }

    def log_lookup(self, user_id: Optional[int], ip_address: str, domain: str,
                   lookup_type: str, results: Dict[str, Any],
                   processing_time_ms: int, user_agent: str = None) -> str:
        """
        Log a dark web lookup for audit and compliance

        Args:
            user_id: User ID or None
            ip_address: IP address
            domain: Domain queried
            lookup_type: Type of lookup
            results: Results dictionary
            processing_time_ms: Processing time in milliseconds
            user_agent: User agent string

        Returns:
            Lookup UUID
        """
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    tier = self._get_user_tier(user_id)

                    cur.execute("""
                        INSERT INTO darkweb_lookups
                        (user_id, ip_address, domain, lookup_type, has_onion,
                         has_i2p, has_blockchain_dns, is_tor_exit, results_json,
                         processing_time_ms, rate_limit_tier, user_agent)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING lookup_id::text
                    """, (
                        user_id, ip_address, domain, lookup_type,
                        results.get('has_onion', False),
                        results.get('has_i2p', False),
                        results.get('has_blockchain_dns', False),
                        results.get('is_tor_exit', False),
                        Json(results),
                        processing_time_ms,
                        tier,
                        user_agent
                    ))

                    lookup_id = cur.fetchone()[0]
                    conn.commit()

                    return lookup_id
        except Exception as e:
            logger.error(f"Error logging lookup: {e}")
            return None

    def audit_log(self, event_type: str, user_id: Optional[int], ip_address: str,
                  action: str, target: str, success: bool = True,
                  error_message: str = None, metadata: Dict = None) -> None:
        """
        Create audit log entry for compliance

        Args:
            event_type: Type of event ('lookup', 'report', 'verification', 'admin_action')
            user_id: User ID or None
            ip_address: IP address
            action: Action performed
            target: Target of action (domain, IP, etc.)
            success: Whether action succeeded
            error_message: Error message if failed
            metadata: Additional metadata
        """
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO darkweb_audit_log
                        (event_type, user_id, ip_address, action, target,
                         success, error_message, metadata)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        event_type, user_id, ip_address, action, target,
                        success, error_message, Json(metadata) if metadata else None
                    ))
                    conn.commit()
        except Exception as e:
            logger.error(f"Error creating audit log: {e}")

    # =========================================================================
    # TOR HIDDEN SERVICE (.onion) MONITORING
    # =========================================================================

    def check_onion_alternative(self, domain: str) -> Dict[str, Any]:
        """
        Check if a clearnet domain has a known .onion alternative

        Args:
            domain: Clearnet domain to check

        Returns:
            Dictionary with onion information:
            {
                'has_onion': bool,
                'onion_addresses': [
                    {
                        'address': str,
                        'version': int (2 or 3),
                        'verified': bool,
                        'active': bool,
                        'last_seen': str,
                        'verification_method': str
                    }
                ],
                'source': str
            }
        """
        result = {
            'has_onion': False,
            'onion_addresses': [],
            'source': 'database'
        }

        try:
            # Check database first
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT
                            m.onion_address,
                            o.onion_version,
                            m.verified,
                            m.verification_method,
                            o.is_active,
                            o.last_seen_at,
                            o.reputation_score,
                            o.trust_level,
                            m.source
                        FROM onion_clearnet_mappings m
                        LEFT JOIN onion_addresses o ON m.onion_address = o.onion_address
                        WHERE m.clearnet_domain = %s
                        AND m.is_active = TRUE
                        ORDER BY m.verified DESC, o.last_seen_at DESC
                    """, (domain.lower(),))

                    mappings = cur.fetchall()

                    if mappings:
                        result['has_onion'] = True
                        for mapping in mappings:
                            result['onion_addresses'].append({
                                'address': mapping['onion_address'],
                                'version': mapping['onion_version'],
                                'verified': mapping['verified'],
                                'verification_method': mapping['verification_method'],
                                'active': mapping['is_active'],
                                'last_seen': mapping['last_seen_at'].isoformat() if mapping['last_seen_at'] else None,
                                'reputation_score': mapping['reputation_score'],
                                'trust_level': mapping['trust_level'],
                                'source': mapping['source']
                            })

            # Check for Onion-Location header
            if not result['has_onion']:
                onion_from_header = self._check_onion_location_header(domain)
                if onion_from_header:
                    result['has_onion'] = True
                    result['onion_addresses'].append(onion_from_header)
                    result['source'] = 'onion-location-header'

            # Check Alt-Svc header
            if not result['has_onion']:
                onion_from_altsvc = self._check_alt_svc_header(domain)
                if onion_from_altsvc:
                    result['has_onion'] = True
                    result['onion_addresses'].append(onion_from_altsvc)
                    result['source'] = 'alt-svc-header'

            # Check DNS TXT records for onion announcement
            if not result['has_onion']:
                onion_from_dns = self._check_dns_txt_onion(domain)
                if onion_from_dns:
                    result['has_onion'] = True
                    result['onion_addresses'].append(onion_from_dns)
                    result['source'] = 'dns-txt-record'

        except Exception as e:
            logger.error(f"Error checking onion alternative for {domain}: {e}")
            result['error'] = str(e)

        return result

    def _check_onion_location_header(self, domain: str) -> Optional[Dict]:
        """Check for Onion-Location HTTP header"""
        try:
            response = requests.get(
                f"https://{domain}",
                timeout=5,
                allow_redirects=True,
                headers={'User-Agent': 'DNSScience-DarkWebMonitor/1.0'}
            )

            onion_location = response.headers.get('Onion-Location')
            if onion_location:
                # Extract onion address
                onion_match = re.search(r'([a-z2-7]{16}|[a-z2-7]{56})\.onion', onion_location)
                if onion_match:
                    onion_address = onion_match.group(0)
                    version = 3 if len(onion_match.group(1)) == 56 else 2

                    # Store in database
                    self._store_onion_mapping(domain, onion_address, 'onion-location-header')

                    return {
                        'address': onion_address,
                        'version': version,
                        'verified': False,
                        'verification_method': 'onion-location-header',
                        'active': None,
                        'last_seen': datetime.utcnow().isoformat()
                    }
        except Exception as e:
            logger.debug(f"Error checking Onion-Location header for {domain}: {e}")

        return None

    def _check_alt_svc_header(self, domain: str) -> Optional[Dict]:
        """Check for Alt-Svc HTTP header with onion service"""
        try:
            response = requests.get(
                f"https://{domain}",
                timeout=5,
                allow_redirects=True,
                headers={'User-Agent': 'DNSScience-DarkWebMonitor/1.0'}
            )

            alt_svc = response.headers.get('Alt-Svc')
            if alt_svc and '.onion' in alt_svc:
                # Extract onion address from Alt-Svc
                onion_match = re.search(r'([a-z2-7]{16}|[a-z2-7]{56})\.onion', alt_svc)
                if onion_match:
                    onion_address = onion_match.group(0)
                    version = 3 if len(onion_match.group(1)) == 56 else 2

                    # Store in database
                    self._store_onion_mapping(domain, onion_address, 'alt-svc')

                    return {
                        'address': onion_address,
                        'version': version,
                        'verified': False,
                        'verification_method': 'alt-svc',
                        'active': None,
                        'last_seen': datetime.utcnow().isoformat()
                    }
        except Exception as e:
            logger.debug(f"Error checking Alt-Svc header for {domain}: {e}")

        return None

    def _check_dns_txt_onion(self, domain: str) -> Optional[Dict]:
        """Check DNS TXT records for onion announcement"""
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, 'TXT')

            for rdata in answers:
                txt_string = rdata.to_text().strip('"')

                # Look for onion announcements
                if 'onion=' in txt_string.lower():
                    onion_match = re.search(r'([a-z2-7]{16}|[a-z2-7]{56})\.onion', txt_string)
                    if onion_match:
                        onion_address = onion_match.group(0)
                        version = 3 if len(onion_match.group(1)) == 56 else 2

                        # Store in database
                        self._store_onion_mapping(domain, onion_address, 'dns-txt-record')

                        return {
                            'address': onion_address,
                            'version': version,
                            'verified': False,
                            'verification_method': 'dns-txt-record',
                            'active': None,
                            'last_seen': datetime.utcnow().isoformat()
                        }
        except dns.exception.DNSException as e:
            logger.debug(f"Error checking DNS TXT for {domain}: {e}")

        return None

    def _store_onion_mapping(self, clearnet_domain: str, onion_address: str, source: str) -> None:
        """Store discovered onion mapping in database"""
        try:
            version = 3 if len(onion_address.replace('.onion', '')) == 56 else 2

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    # Insert or update onion address
                    cur.execute("""
                        INSERT INTO onion_addresses
                        (onion_address, onion_version, clearnet_domain,
                         discovered_via, is_active, last_seen_at)
                        VALUES (%s, %s, %s, %s, TRUE, CURRENT_TIMESTAMP)
                        ON CONFLICT (onion_address)
                        DO UPDATE SET
                            last_seen_at = CURRENT_TIMESTAMP,
                            is_active = TRUE
                    """, (onion_address, version, clearnet_domain, source))

                    # Insert mapping
                    cur.execute("""
                        INSERT INTO onion_clearnet_mappings
                        (clearnet_domain, onion_address, verified,
                         verification_method, source, is_active, last_checked)
                        VALUES (%s, %s, FALSE, %s, %s, TRUE, CURRENT_TIMESTAMP)
                        ON CONFLICT (clearnet_domain, onion_address)
                        DO UPDATE SET
                            last_checked = CURRENT_TIMESTAMP,
                            is_active = TRUE
                    """, (clearnet_domain, onion_address, source, source))

                    conn.commit()
        except Exception as e:
            logger.error(f"Error storing onion mapping: {e}")

    def verify_onion_service(self, onion_address: str) -> Dict[str, Any]:
        """
        Verify if an onion service is reachable (requires Tor)

        Args:
            onion_address: The .onion address to verify

        Returns:
            Dictionary with verification status
        """
        result = {
            'reachable': False,
            'response_time_ms': None,
            'error': None
        }

        if not self.tor_enabled:
            result['error'] = 'Tor not enabled'
            return result

        try:
            # Use requests with SOCKS proxy
            proxies = {
                'http': self.tor_socks_proxy,
                'https': self.tor_socks_proxy
            }

            start_time = time.time()
            response = requests.get(
                f"http://{onion_address}",
                proxies=proxies,
                timeout=30,
                headers={'User-Agent': 'DNSScience-DarkWebMonitor/1.0'}
            )
            response_time = (time.time() - start_time) * 1000

            if response.status_code < 500:
                result['reachable'] = True
                result['response_time_ms'] = int(response_time)

                # Update database
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            UPDATE onion_addresses
                            SET verified = TRUE,
                                last_verified_at = CURRENT_TIMESTAMP,
                                verification_method = 'direct-connection',
                                is_active = TRUE,
                                last_seen_at = CURRENT_TIMESTAMP,
                                response_time_ms = %s
                            WHERE onion_address = %s
                        """, (int(response_time), onion_address))
                        conn.commit()
            else:
                result['error'] = f"HTTP {response.status_code}"

        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Error verifying onion service {onion_address}: {e}")

        return result

    # =========================================================================
    # I2P NETWORK (.i2p) MONITORING
    # =========================================================================

    def check_i2p_alternative(self, domain: str) -> Dict[str, Any]:
        """
        Check if a clearnet domain has a known .i2p alternative

        Args:
            domain: Clearnet domain to check

        Returns:
            Dictionary with I2P information
        """
        result = {
            'has_i2p': False,
            'i2p_addresses': [],
            'source': 'database'
        }

        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT
                            i2p_address,
                            i2p_domain,
                            verified,
                            is_active,
                            last_seen_at,
                            addressbook_sources,
                            category,
                            title,
                            description
                        FROM i2p_addresses
                        WHERE clearnet_domain = %s
                        AND is_active = TRUE
                        ORDER BY last_seen_at DESC
                    """, (domain.lower(),))

                    addresses = cur.fetchall()

                    if addresses:
                        result['has_i2p'] = True
                        for addr in addresses:
                            result['i2p_addresses'].append({
                                'address': addr['i2p_address'],
                                'domain': addr['i2p_domain'],
                                'verified': addr['verified'],
                                'active': addr['is_active'],
                                'last_seen': addr['last_seen_at'].isoformat() if addr['last_seen_at'] else None,
                                'addressbook_sources': addr['addressbook_sources'],
                                'category': addr['category'],
                                'title': addr['title'],
                                'description': addr['description']
                            })
        except Exception as e:
            logger.error(f"Error checking I2P alternative for {domain}: {e}")
            result['error'] = str(e)

        return result

    # =========================================================================
    # BLOCKCHAIN DNS MONITORING
    # =========================================================================

    def check_blockchain_dns(self, domain: str) -> Dict[str, Any]:
        """
        Check for blockchain DNS registrations (.bit, .hns, etc.)

        Args:
            domain: Domain to check (can include or exclude blockchain TLD)

        Returns:
            Dictionary with blockchain DNS information:
            {
                'has_blockchain_dns': bool,
                'namecoin': {...},  # .bit domains
                'handshake': {...}, # .hns domains
                'ens': {...},       # .eth domains
                'unstoppable': {...} # .crypto, .nft, etc.
            }
        """
        result = {
            'has_blockchain_dns': False,
            'namecoin': None,
            'handshake': None,
            'ens': None,
            'unstoppable': None
        }

        # Extract base domain name
        base_domain = domain.split('.')[0]

        # Check Namecoin (.bit)
        namecoin_result = self._check_namecoin(base_domain)
        if namecoin_result:
            result['namecoin'] = namecoin_result
            result['has_blockchain_dns'] = True

        # Check Handshake (.hns)
        handshake_result = self._check_handshake(base_domain)
        if handshake_result:
            result['handshake'] = handshake_result
            result['has_blockchain_dns'] = True

        # Check ENS (.eth)
        ens_result = self._check_ens(base_domain)
        if ens_result:
            result['ens'] = ens_result
            result['has_blockchain_dns'] = True

        # Check Unstoppable Domains (.crypto, .nft, etc.)
        unstoppable_result = self._check_unstoppable(base_domain)
        if unstoppable_result:
            result['unstoppable'] = unstoppable_result
            result['has_blockchain_dns'] = True

        return result

    def _check_namecoin(self, domain: str) -> Optional[Dict]:
        """Check Namecoin for .bit domain registration"""
        try:
            # Check database first
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT
                            domain,
                            blockchain_address,
                            resolved_ip,
                            resolved_records,
                            owner_address,
                            registered_at,
                            last_verified_at
                        FROM alternative_dns
                        WHERE dns_type = 'namecoin'
                        AND domain = %s
                        AND verified = TRUE
                        ORDER BY last_verified_at DESC
                        LIMIT 1
                    """, (f"{domain}.bit",))

                    record = cur.fetchone()
                    if record:
                        return {
                            'domain': record['domain'],
                            'exists': True,
                            'blockchain_address': record['blockchain_address'],
                            'resolved_ip': str(record['resolved_ip']) if record['resolved_ip'] else None,
                            'resolved_records': record['resolved_records'],
                            'owner': record['owner_address'],
                            'registered_at': record['registered_at'].isoformat() if record['registered_at'] else None,
                            'last_verified': record['last_verified_at'].isoformat() if record['last_verified_at'] else None
                        }

            # If not in database and RPC available, query Namecoin node
            if self.namecoin_rpc:
                # This would require actual Namecoin RPC integration
                pass

        except Exception as e:
            logger.error(f"Error checking Namecoin for {domain}: {e}")

        return None

    def _check_handshake(self, domain: str) -> Optional[Dict]:
        """Check Handshake for .hns domain registration"""
        try:
            # Check database first
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT
                            domain,
                            blockchain_address,
                            resolved_ip,
                            resolved_records,
                            owner_address,
                            registered_at,
                            last_verified_at
                        FROM alternative_dns
                        WHERE dns_type = 'handshake'
                        AND domain = %s
                        AND verified = TRUE
                        ORDER BY last_verified_at DESC
                        LIMIT 1
                    """, (f"{domain}.hns",))

                    record = cur.fetchone()
                    if record:
                        return {
                            'domain': record['domain'],
                            'exists': True,
                            'blockchain_address': record['blockchain_address'],
                            'resolved_ip': str(record['resolved_ip']) if record['resolved_ip'] else None,
                            'resolved_records': record['resolved_records'],
                            'owner': record['owner_address'],
                            'registered_at': record['registered_at'].isoformat() if record['registered_at'] else None,
                            'last_verified': record['last_verified_at'].isoformat() if record['last_verified_at'] else None
                        }

            # If not in database and RPC available, query Handshake node
            if self.handshake_rpc:
                # This would require actual Handshake RPC integration
                pass

        except Exception as e:
            logger.error(f"Error checking Handshake for {domain}: {e}")

        return None

    def _check_ens(self, domain: str) -> Optional[Dict]:
        """Check Ethereum Name Service for .eth domain"""
        try:
            # Check database
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT
                            domain,
                            blockchain_address,
                            resolved_ip,
                            resolved_records,
                            owner_address,
                            last_verified_at
                        FROM alternative_dns
                        WHERE dns_type = 'ens'
                        AND domain = %s
                        AND verified = TRUE
                        ORDER BY last_verified_at DESC
                        LIMIT 1
                    """, (f"{domain}.eth",))

                    record = cur.fetchone()
                    if record:
                        return {
                            'domain': record['domain'],
                            'exists': True,
                            'blockchain_address': record['blockchain_address'],
                            'resolved_ip': str(record['resolved_ip']) if record['resolved_ip'] else None,
                            'resolved_records': record['resolved_records'],
                            'owner': record['owner_address'],
                            'last_verified': record['last_verified_at'].isoformat() if record['last_verified_at'] else None
                        }
        except Exception as e:
            logger.error(f"Error checking ENS for {domain}: {e}")

        return None

    def _check_unstoppable(self, domain: str) -> Optional[Dict]:
        """Check Unstoppable Domains (.crypto, .nft, .blockchain, etc.)"""
        try:
            # Check database for various Unstoppable TLDs
            unstoppable_tlds = ['.crypto', '.nft', '.blockchain', '.bitcoin', '.dao', '.wallet', '.x', '.888', '.zil']

            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    for tld in unstoppable_tlds:
                        cur.execute("""
                            SELECT
                                domain,
                                blockchain_address,
                                resolved_ip,
                                resolved_records,
                                owner_address,
                                last_verified_at
                            FROM alternative_dns
                            WHERE dns_type = 'unstoppable'
                            AND domain = %s
                            AND verified = TRUE
                            ORDER BY last_verified_at DESC
                            LIMIT 1
                        """, (f"{domain}{tld}",))

                        record = cur.fetchone()
                        if record:
                            return {
                                'domain': record['domain'],
                                'exists': True,
                                'blockchain_address': record['blockchain_address'],
                                'resolved_ip': str(record['resolved_ip']) if record['resolved_ip'] else None,
                                'resolved_records': record['resolved_records'],
                                'owner': record['owner_address'],
                                'last_verified': record['last_verified_at'].isoformat() if record['last_verified_at'] else None
                            }
        except Exception as e:
            logger.error(f"Error checking Unstoppable Domains for {domain}: {e}")

        return None

    # =========================================================================
    # TOR EXIT NODE DETECTION
    # =========================================================================

    def is_tor_exit_node(self, ip: str) -> Dict[str, Any]:
        """
        Check if an IP address is a Tor exit node

        Args:
            ip: IP address to check

        Returns:
            Dictionary with Tor exit node information:
            {
                'is_tor_exit': bool,
                'fingerprint': str,
                'nickname': str,
                'country': str,
                'bandwidth_class': str,
                'exit_policy': str,
                'first_seen': str,
                'last_seen': str
            }
        """
        result = {
            'is_tor_exit': False,
            'details': None
        }

        try:
            # Check database first
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT
                            ip_address,
                            fingerprint,
                            nickname,
                            country_code,
                            country_name,
                            bandwidth_class,
                            exit_policy,
                            allows_http,
                            allows_https,
                            is_active,
                            first_seen,
                            last_seen,
                            contact_info
                        FROM tor_exit_nodes
                        WHERE ip_address = %s
                        AND is_active = TRUE
                    """, (ip,))

                    node = cur.fetchone()

                    if node:
                        result['is_tor_exit'] = True
                        result['details'] = {
                            'fingerprint': node['fingerprint'],
                            'nickname': node['nickname'],
                            'country_code': node['country_code'],
                            'country_name': node['country_name'],
                            'bandwidth_class': node['bandwidth_class'],
                            'exit_policy': node['exit_policy'],
                            'allows_http': node['allows_http'],
                            'allows_https': node['allows_https'],
                            'first_seen': node['first_seen'].isoformat() if node['first_seen'] else None,
                            'last_seen': node['last_seen'].isoformat() if node['last_seen'] else None,
                            'contact_info': node['contact_info']
                        }

            # If not in database, check against live Tor exit list
            if not result['is_tor_exit']:
                if self._check_tor_exit_list(ip):
                    result['is_tor_exit'] = True
                    result['details'] = {
                        'source': 'tor-exit-list',
                        'verified': True
                    }

        except Exception as e:
            logger.error(f"Error checking if {ip} is Tor exit: {e}")
            result['error'] = str(e)

        return result

    def _check_tor_exit_list(self, ip: str) -> bool:
        """Check IP against Tor Project's exit node list"""
        try:
            # Use cached list if available and not expired
            if self._tor_exit_cache['data'] and self._tor_exit_cache['expires']:
                if datetime.utcnow() < self._tor_exit_cache['expires']:
                    return ip in self._tor_exit_cache['data']

            # Fetch fresh list
            response = requests.get(
                self.tor_exit_list_url,
                timeout=10,
                headers={'User-Agent': 'DNSScience-DarkWebMonitor/1.0'}
            )

            if response.status_code == 200:
                # Parse exit addresses
                exit_ips = set()
                for line in response.text.split('\n'):
                    if line.startswith('ExitAddress'):
                        parts = line.split()
                        if len(parts) >= 2:
                            exit_ips.add(parts[1])

                # Cache for 1 hour
                self._tor_exit_cache['data'] = exit_ips
                self._tor_exit_cache['expires'] = datetime.utcnow() + timedelta(hours=1)

                return ip in exit_ips

        except Exception as e:
            logger.error(f"Error checking Tor exit list: {e}")

        return False

    def update_tor_exit_nodes(self) -> Dict[str, int]:
        """
        Update the database with current Tor exit nodes
        (This should be run periodically by a daemon)

        Returns:
            Statistics about the update
        """
        stats = {
            'added': 0,
            'updated': 0,
            'deactivated': 0,
            'errors': 0
        }

        try:
            # Fetch exit addresses
            response = requests.get(
                self.tor_exit_list_url,
                timeout=30,
                headers={'User-Agent': 'DNSScience-DarkWebMonitor/1.0'}
            )

            if response.status_code != 200:
                logger.error(f"Failed to fetch Tor exit list: HTTP {response.status_code}")
                return stats

            # Parse exit node information
            current_exits = {}
            for line in response.text.split('\n'):
                if line.startswith('ExitNode'):
                    parts = line.split()
                    if len(parts) >= 2:
                        fingerprint = parts[1]
                        current_exits[fingerprint] = {'fingerprint': fingerprint}
                elif line.startswith('ExitAddress'):
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[1]
                        timestamp = parts[2]
                        # Find the fingerprint for this IP
                        for fp, data in current_exits.items():
                            if 'ip' not in data:
                                data['ip'] = ip
                                data['last_seen'] = timestamp
                                break

            # Update database
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    current_ips = set()

                    for fingerprint, data in current_exits.items():
                        if 'ip' not in data:
                            continue

                        ip = data['ip']
                        current_ips.add(ip)

                        # Insert or update
                        cur.execute("""
                            INSERT INTO tor_exit_nodes
                            (ip_address, fingerprint, is_active, last_seen)
                            VALUES (%s, %s, TRUE, CURRENT_TIMESTAMP)
                            ON CONFLICT (ip_address)
                            DO UPDATE SET
                                fingerprint = EXCLUDED.fingerprint,
                                is_active = TRUE,
                                last_seen = CURRENT_TIMESTAMP,
                                updated_at = CURRENT_TIMESTAMP
                        """, (ip, fingerprint))

                        if cur.rowcount > 0:
                            stats['added'] += 1
                        else:
                            stats['updated'] += 1

                    # Deactivate nodes not in current list
                    if current_ips:
                        cur.execute("""
                            UPDATE tor_exit_nodes
                            SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                            WHERE ip_address NOT IN %s
                            AND is_active = TRUE
                            AND last_seen < CURRENT_TIMESTAMP - INTERVAL '24 hours'
                        """, (tuple(current_ips),))
                        stats['deactivated'] = cur.rowcount

                    conn.commit()

            logger.info(f"Tor exit nodes updated: {stats}")

        except Exception as e:
            logger.error(f"Error updating Tor exit nodes: {e}")
            stats['errors'] += 1

        return stats

    # =========================================================================
    # CERTIFICATE ANALYSIS
    # =========================================================================

    def analyze_dark_certificates(self, domain: str) -> Dict[str, Any]:
        """
        Analyze certificates for dark web indicators

        Args:
            domain: Domain to analyze certificates for

        Returns:
            Dictionary with certificate analysis:
            {
                'certificates': [],
                'hidden_service_indicators': bool,
                'anomalies': [],
                'risk_score': int
            }
        """
        result = {
            'certificates': [],
            'hidden_service_indicators': False,
            'anomalies': [],
            'risk_score': 0
        }

        try:
            # Query Certificate Transparency logs via crt.sh
            ct_results = self._query_certificate_transparency(domain)

            if ct_results:
                result['certificates'] = ct_results

                # Analyze for dark web indicators
                for cert in ct_results:
                    # Check for .onion in SANs
                    if cert.get('sans'):
                        for san in cert['sans']:
                            if '.onion' in san.lower():
                                result['hidden_service_indicators'] = True
                                result['anomalies'].append({
                                    'type': 'onion-in-san',
                                    'description': f'Certificate contains .onion address: {san}',
                                    'severity': 'high'
                                })

                    # Check for suspicious issuers
                    if cert.get('issuer'):
                        issuer = cert['issuer'].lower()
                        if any(keyword in issuer for keyword in ['self-signed', 'unknown', 'custom']):
                            result['anomalies'].append({
                                'type': 'suspicious-issuer',
                                'description': f'Suspicious certificate issuer: {cert["issuer"]}',
                                'severity': 'medium'
                            })

                    # Check for short validity periods
                    if cert.get('valid_from') and cert.get('valid_to'):
                        validity_days = (cert['valid_to'] - cert['valid_from']).days
                        if validity_days < 30:
                            result['anomalies'].append({
                                'type': 'short-validity',
                                'description': f'Unusually short certificate validity: {validity_days} days',
                                'severity': 'medium'
                            })

                # Calculate risk score based on anomalies
                risk_score = 0
                for anomaly in result['anomalies']:
                    if anomaly['severity'] == 'high':
                        risk_score += 30
                    elif anomaly['severity'] == 'medium':
                        risk_score += 15
                    elif anomaly['severity'] == 'low':
                        risk_score += 5

                result['risk_score'] = min(risk_score, 100)

        except Exception as e:
            logger.error(f"Error analyzing certificates for {domain}: {e}")
            result['error'] = str(e)

        return result

    def _query_certificate_transparency(self, domain: str) -> List[Dict]:
        """Query Certificate Transparency logs via crt.sh"""
        certificates = []

        try:
            # Query crt.sh API
            response = requests.get(
                f"{self.ct_log_api}/?q={domain}&output=json",
                timeout=10,
                headers={'User-Agent': 'DNSScience-DarkWebMonitor/1.0'}
            )

            if response.status_code == 200:
                ct_data = response.json()

                for entry in ct_data[:10]:  # Limit to 10 most recent
                    cert_info = {
                        'id': entry.get('id'),
                        'logged_at': entry.get('entry_timestamp'),
                        'not_before': entry.get('not_before'),
                        'not_after': entry.get('not_after'),
                        'common_name': entry.get('common_name'),
                        'issuer': entry.get('issuer_name'),
                        'sans': entry.get('name_value', '').split('\n')
                    }

                    # Parse dates
                    if cert_info['not_before']:
                        cert_info['valid_from'] = datetime.fromisoformat(cert_info['not_before'].replace('Z', '+00:00'))
                    if cert_info['not_after']:
                        cert_info['valid_to'] = datetime.fromisoformat(cert_info['not_after'].replace('Z', '+00:00'))

                    certificates.append(cert_info)

        except Exception as e:
            logger.error(f"Error querying Certificate Transparency for {domain}: {e}")

        return certificates

    # =========================================================================
    # COMPREHENSIVE LOOKUP
    # =========================================================================

    def comprehensive_lookup(self, domain: str, user_id: Optional[int],
                            ip_address: str, checks: List[str] = None,
                            user_agent: str = None) -> Dict[str, Any]:
        """
        Perform comprehensive dark web lookup

        Args:
            domain: Domain to lookup
            user_id: User ID or None
            ip_address: Requester IP
            checks: List of check types or None for all
            user_agent: User agent string

        Returns:
            Complete dark web analysis results
        """
        start_time = time.time()

        # Default to all checks if not specified
        if checks is None:
            checks = ['onion', 'i2p', 'blockchain', 'tor_nodes', 'certificates']

        # Check rate limit
        rate_limit = self.check_rate_limit(user_id, ip_address)
        if not rate_limit['allowed']:
            return {
                'error': 'Rate limit exceeded',
                'rate_limit': rate_limit
            }

        # Initialize results
        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'checks_performed': checks
        }

        # Perform requested checks
        if 'onion' in checks:
            results['onion'] = self.check_onion_alternative(domain)
            results['has_onion'] = results['onion']['has_onion']

        if 'i2p' in checks:
            results['i2p'] = self.check_i2p_alternative(domain)
            results['has_i2p'] = results['i2p']['has_i2p']

        if 'blockchain' in checks:
            results['blockchain_dns'] = self.check_blockchain_dns(domain)
            results['has_blockchain_dns'] = results['blockchain_dns']['has_blockchain_dns']

        if 'tor_nodes' in checks:
            # Check if domain resolves to Tor exit nodes
            try:
                answers = dns.resolver.resolve(domain, 'A')
                tor_exits = []
                for rdata in answers:
                    ip = str(rdata)
                    tor_check = self.is_tor_exit_node(ip)
                    if tor_check['is_tor_exit']:
                        tor_exits.append({
                            'ip': ip,
                            'details': tor_check['details']
                        })
                results['tor_exit_nodes'] = tor_exits
                results['is_tor_exit'] = len(tor_exits) > 0
            except Exception as e:
                results['tor_exit_nodes'] = []
                results['is_tor_exit'] = False
                logger.debug(f"Error checking Tor exits for {domain}: {e}")

        if 'certificates' in checks:
            results['certificates'] = self.analyze_dark_certificates(domain)

        # Calculate processing time
        processing_time_ms = int((time.time() - start_time) * 1000)
        results['processing_time_ms'] = processing_time_ms

        # Add rate limit info
        results['rate_limit'] = {
            'remaining': rate_limit['remaining'],
            'reset_at': rate_limit['reset_at'],
            'tier': rate_limit['tier']
        }

        # Log the lookup
        lookup_id = self.log_lookup(
            user_id, ip_address, domain, 'comprehensive',
            results, processing_time_ms, user_agent
        )
        results['lookup_id'] = lookup_id

        # Audit log
        self.audit_log(
            'lookup', user_id, ip_address, 'comprehensive_lookup',
            domain, True, None, {'checks': checks}
        )

        return results

    # =========================================================================
    # STATISTICS AND REPORTING
    # =========================================================================

    def get_darkweb_statistics(self) -> Dict[str, Any]:
        """
        Get dark web monitoring statistics

        Returns:
            Dictionary with various statistics
        """
        stats = {}

        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    # Total counts
                    cur.execute("SELECT COUNT(*) as count FROM onion_addresses WHERE is_active = TRUE")
                    stats['active_onion_addresses'] = cur.fetchone()['count']

                    cur.execute("SELECT COUNT(*) as count FROM i2p_addresses WHERE is_active = TRUE")
                    stats['active_i2p_addresses'] = cur.fetchone()['count']

                    cur.execute("SELECT COUNT(*) as count FROM tor_exit_nodes WHERE is_active = TRUE")
                    stats['active_tor_exits'] = cur.fetchone()['count']

                    cur.execute("SELECT COUNT(*) as count FROM alternative_dns WHERE verified = TRUE")
                    stats['verified_blockchain_domains'] = cur.fetchone()['count']

                    # Lookups stats (last 24 hours)
                    cur.execute("""
                        SELECT
                            COUNT(*) as total_lookups,
                            COUNT(DISTINCT user_id) as unique_users,
                            COUNT(DISTINCT ip_address) as unique_ips,
                            AVG(processing_time_ms) as avg_processing_time
                        FROM darkweb_lookups
                        WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'
                    """)
                    lookup_stats = cur.fetchone()
                    # Convert Decimal to float for JSON serialization
                    lookup_stats_dict = dict(lookup_stats)
                    if lookup_stats_dict.get('avg_processing_time'):
                        lookup_stats_dict['avg_processing_time'] = float(lookup_stats_dict['avg_processing_time'])
                    stats['last_24h_lookups'] = lookup_stats_dict

                    # Top countries for Tor exits
                    cur.execute("""
                        SELECT country_code, country_name, COUNT(*) as count
                        FROM tor_exit_nodes
                        WHERE is_active = TRUE
                        GROUP BY country_code, country_name
                        ORDER BY count DESC
                        LIMIT 10
                    """)
                    stats['top_tor_exit_countries'] = [dict(row) for row in cur.fetchall()]

                    # Recently discovered onion addresses
                    cur.execute("""
                        SELECT onion_address, clearnet_domain, discovered_at
                        FROM onion_addresses
                        WHERE discovered_at > CURRENT_TIMESTAMP - INTERVAL '7 days'
                        ORDER BY discovered_at DESC
                        LIMIT 10
                    """)
                    stats['recent_onion_discoveries'] = [dict(row) for row in cur.fetchall()]

        except Exception as e:
            logger.error(f"Error getting dark web statistics: {e}")
            stats['error'] = str(e)

        return stats

    def get_user_lookup_history(self, user_id: int, limit: int = 50) -> List[Dict]:
        """Get lookup history for a user"""
        history = []

        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT
                            lookup_id,
                            domain,
                            lookup_type,
                            has_onion,
                            has_i2p,
                            has_blockchain_dns,
                            is_tor_exit,
                            processing_time_ms,
                            created_at
                        FROM darkweb_lookups
                        WHERE user_id = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (user_id, limit))

                    history = [dict(row) for row in cur.fetchall()]

        except Exception as e:
            logger.error(f"Error getting lookup history: {e}")

        return history


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def validate_onion_address(address: str) -> bool:
    """
    Validate .onion address format

    Args:
        address: The .onion address to validate

    Returns:
        True if valid, False otherwise
    """
    if not address.endswith('.onion'):
        return False

    # Remove .onion suffix
    addr = address[:-6]

    # v2 addresses are 16 characters (base32)
    # v3 addresses are 56 characters (base32)
    if len(addr) not in [16, 56]:
        return False

    # Check if valid base32
    import re
    if not re.match(r'^[a-z2-7]+$', addr):
        return False

    return True


def validate_i2p_address(address: str) -> bool:
    """
    Validate .i2p address format

    Args:
        address: The .i2p address to validate

    Returns:
        True if valid, False otherwise
    """
    if not address.endswith('.i2p'):
        return False

    # I2P addresses can be base32 or human-readable
    # Base32 addresses are 52 characters
    addr = address[:-4]

    # Human-readable can be any valid hostname
    import re
    if re.match(r'^[a-z0-9\-]+$', addr, re.IGNORECASE):
        return True

    return False


def get_onion_version(address: str) -> Optional[int]:
    """
    Get version of .onion address

    Args:
        address: The .onion address

    Returns:
        2 or 3 for version, None if invalid
    """
    if not address.endswith('.onion'):
        return None

    addr = address[:-6]

    if len(addr) == 16:
        return 2
    elif len(addr) == 56:
        return 3

    return None


# ============================================================================
# MAIN - FOR TESTING
# ============================================================================

if __name__ == '__main__':
    # Example usage
    import sys

    if len(sys.argv) < 2:
        print("Usage: python darkweb_monitor.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    # Initialize monitor (would need real database connection)
    config = {
        'TOR_ENABLED': False,
        'TOR_SOCKS_PROXY': 'socks5h://127.0.0.1:9050'
    }

    db_conn_string = os.getenv('DATABASE_URL', 'postgresql://localhost/dnsscience')

    monitor = DarkWebMonitor(db_conn_string, config)

    # Perform comprehensive lookup
    results = monitor.comprehensive_lookup(
        domain=domain,
        user_id=None,
        ip_address='127.0.0.1',
        checks=['onion', 'blockchain', 'certificates']
    )

    print(json.dumps(results, indent=2, default=str))
