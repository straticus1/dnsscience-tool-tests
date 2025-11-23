"""
OpenSRS Integration Module for DNS Science Platform

This module provides a comprehensive Python wrapper around the OpenSRS XML API
for domain registration, SSL certificate provisioning, and DNS management.

OpenSRS API Documentation: https://domains.opensrs.guide/

Author: DNS Science Development Team
Version: 1.0.0
Date: 2025-11-13
"""

import hashlib
import requests
import json
import os
from xml.etree import ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import logging
from cryptography.fernet import Fernet
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES FOR TYPE SAFETY
# =============================================================================

@dataclass
class DomainAvailability:
    """Domain availability result"""
    domain: str
    available: bool
    is_premium: bool = False
    premium_price: Optional[float] = None
    standard_price: Optional[float] = None
    error: Optional[str] = None


@dataclass
class DomainContact:
    """Domain contact information"""
    first_name: str
    last_name: str
    email: str
    phone: str
    address1: str
    city: str
    state: str
    postal_code: str
    country: str
    org: Optional[str] = None
    address2: Optional[str] = None


@dataclass
class DomainRegistrationRequest:
    """Domain registration parameters"""
    domain: str
    years: int
    contacts: DomainContact
    nameservers: List[str]
    auto_renew: bool = True
    whois_privacy: bool = True
    transfer_lock: bool = True


@dataclass
class SSLCertificateOrder:
    """SSL certificate order parameters"""
    product_code: str
    domain: str
    years: int
    csr: str
    validation_method: str  # email, dns, http
    validation_email: Optional[str] = None
    san_domains: Optional[List[str]] = None
    organization: Optional[str] = None


# =============================================================================
# OPENSRS XML PROTOCOL CLIENT
# =============================================================================

class OpenSRSClient:
    """
    Low-level OpenSRS API client handling XML protocol and authentication.

    The OpenSRS API uses a proprietary XML Command Protocol (XCP) with
    MD5 signature-based authentication.
    """

    def __init__(self, username: str, api_key: str, environment: str = 'test'):
        """
        Initialize OpenSRS client.

        Args:
            username: OpenSRS reseller username
            api_key: OpenSRS API key
            environment: 'test' for Horizon or 'production' for live
        """
        self.username = username
        self.api_key = api_key
        self.environment = environment

        # Set API endpoint based on environment
        if environment == 'production':
            self.api_url = 'https://rr-n1-tor.opensrs.net:55443'
        else:
            self.api_url = 'https://horizon.opensrs.net:55443'

        logger.info(f"OpenSRS Client initialized for {environment} environment")

    def _generate_signature(self, xml_content: str) -> str:
        """
        Generate MD5 signature for OpenSRS authentication.

        OpenSRS requires a double MD5 signature:
        1. MD5(xml_content + api_key)
        2. MD5(signature1 + api_key)

        Args:
            xml_content: The XML request body

        Returns:
            Final MD5 signature as hex string
        """
        # First MD5
        first_hash = hashlib.md5(
            (xml_content + self.api_key).encode('utf-8')
        ).hexdigest()

        # Second MD5
        second_hash = hashlib.md5(
            (first_hash + self.api_key).encode('utf-8')
        ).hexdigest()

        return second_hash

    def _build_xml_request(self, action: str, object_type: str,
                          attributes: Dict[str, Any]) -> str:
        """
        Build OpenSRS XML request.

        Args:
            action: OpenSRS action (LOOKUP, SW_REGISTER, MODIFY, etc.)
            object_type: OpenSRS object type (DOMAIN, TRUST_SERVICE, etc.)
            attributes: Dictionary of attributes for the request

        Returns:
            XML request as string
        """
        # Build XML structure
        root = ET.Element('OPS_envelope')

        # Header
        header = ET.SubElement(root, 'header')
        version = ET.SubElement(header, 'version')
        version.text = '0.9'

        # Body
        body = ET.SubElement(root, 'body')
        data_block = ET.SubElement(body, 'data_block')
        dt_assoc = ET.SubElement(data_block, 'dt_assoc')

        # Protocol
        item_protocol = ET.SubElement(dt_assoc, 'item', key='protocol')
        item_protocol.text = 'XCP'

        # Action
        item_action = ET.SubElement(dt_assoc, 'item', key='action')
        item_action.text = action

        # Object
        item_object = ET.SubElement(dt_assoc, 'item', key='object')
        item_object.text = object_type

        # Attributes
        item_attributes = ET.SubElement(dt_assoc, 'item', key='attributes')
        attr_assoc = ET.SubElement(item_attributes, 'dt_assoc')

        # Add attributes recursively
        self._add_attributes_to_xml(attr_assoc, attributes)

        # Convert to string
        xml_string = ET.tostring(root, encoding='unicode')

        # Add DOCTYPE
        xml_with_doctype = f"""<?xml version='1.0' encoding='UTF-8' standalone='no' ?>
<!DOCTYPE OPS_envelope SYSTEM 'ops.dtd'>
{xml_string}"""

        return xml_with_doctype

    def _add_attributes_to_xml(self, parent: ET.Element, attributes: Dict[str, Any]):
        """
        Recursively add attributes to XML element.

        Args:
            parent: Parent XML element
            attributes: Dictionary of attributes
        """
        for key, value in attributes.items():
            if isinstance(value, dict):
                # Nested dictionary -> dt_assoc
                item = ET.SubElement(parent, 'item', key=key)
                nested_assoc = ET.SubElement(item, 'dt_assoc')
                self._add_attributes_to_xml(nested_assoc, value)
            elif isinstance(value, list):
                # List -> dt_array
                item = ET.SubElement(parent, 'item', key=key)
                array = ET.SubElement(item, 'dt_array')
                for idx, list_item in enumerate(value):
                    array_item = ET.SubElement(array, 'item', key=str(idx))
                    if isinstance(list_item, dict):
                        nested_assoc = ET.SubElement(array_item, 'dt_assoc')
                        self._add_attributes_to_xml(nested_assoc, list_item)
                    else:
                        array_item.text = str(list_item)
            else:
                # Simple value
                item = ET.SubElement(parent, 'item', key=key)
                item.text = str(value)

    def _parse_response(self, xml_response: str) -> Dict[str, Any]:
        """
        Parse OpenSRS XML response into Python dictionary.

        Args:
            xml_response: XML response string from OpenSRS

        Returns:
            Parsed response as dictionary

        Raises:
            OpenSRSAPIError: If response indicates error
        """
        try:
            root = ET.fromstring(xml_response)

            # Navigate to response data
            body = root.find('body')
            data_block = body.find('data_block')
            dt_assoc = data_block.find('dt_assoc')

            # Parse into dictionary
            response = self._parse_xml_element(dt_assoc)

            # Check for errors
            # OpenSRS response codes: 200=Success, 210=Domain Available, 211=Domain Taken
            # Codes 210 and 211 are informational, not errors
            response_code = int(response.get('response_code', 0))
            if response_code not in [200, 210, 211]:
                error_text = response.get('response_text', 'Unknown error')
                raise OpenSRSAPIError(
                    f"OpenSRS API Error {response_code}: {error_text}",
                    code=response_code
                )

            return response

        except ET.ParseError as e:
            logger.error(f"Failed to parse OpenSRS XML response: {e}")
            raise OpenSRSAPIError(f"XML Parse Error: {e}")

    def _parse_xml_element(self, element: ET.Element) -> Any:
        """
        Recursively parse XML element into Python types.

        Args:
            element: XML element to parse

        Returns:
            Parsed value (dict, list, or primitive)
        """
        if element.tag == 'dt_assoc':
            # Dictionary
            result = {}
            for item in element.findall('item'):
                key = item.get('key')
                # Check for nested structures
                nested = item.find('dt_assoc') or item.find('dt_array')
                if nested is not None:
                    result[key] = self._parse_xml_element(nested)
                else:
                    result[key] = item.text
            return result

        elif element.tag == 'dt_array':
            # List
            result = []
            for item in element.findall('item'):
                nested = item.find('dt_assoc') or item.find('dt_array')
                if nested is not None:
                    result.append(self._parse_xml_element(nested))
                else:
                    result.append(item.text)
            return result

        else:
            return element.text

    def make_request(self, action: str, object_type: str,
                    attributes: Dict[str, Any],
                    timeout: int = 30) -> Dict[str, Any]:
        """
        Make authenticated request to OpenSRS API.

        Args:
            action: OpenSRS action
            object_type: OpenSRS object type
            attributes: Request attributes
            timeout: Request timeout in seconds

        Returns:
            Parsed response dictionary

        Raises:
            OpenSRSAPIError: On API error
            requests.RequestException: On network error
        """
        # Build XML request
        xml_request = self._build_xml_request(action, object_type, attributes)

        # Generate signature
        signature = self._generate_signature(xml_request)

        # Prepare headers
        headers = {
            'Content-Type': 'text/xml',
            'X-Username': self.username,
            'X-Signature': signature
        }

        # Log request (sanitized)
        logger.info(f"OpenSRS Request: {action} {object_type}")
        logger.debug(f"Request attributes: {json.dumps(attributes, indent=2)}")

        # Make request
        start_time = datetime.now()
        try:
            response = requests.post(
                self.api_url,
                data=xml_request.encode('utf-8'),
                headers=headers,
                timeout=timeout
            )
            response.raise_for_status()

        except requests.RequestException as e:
            logger.error(f"OpenSRS request failed: {e}")
            raise

        # Calculate duration
        duration_ms = (datetime.now() - start_time).total_seconds() * 1000

        # Parse response
        response_data = self._parse_response(response.text)

        logger.info(f"OpenSRS Response: {response_data.get('response_code')} "
                   f"in {duration_ms:.0f}ms")
        logger.debug(f"Response data: {json.dumps(response_data, indent=2)}")

        return response_data


# =============================================================================
# DOMAIN MANAGER
# =============================================================================

class DomainManager:
    """
    High-level domain management operations.
    """

    def __init__(self, client: OpenSRSClient):
        """
        Initialize domain manager.

        Args:
            client: OpenSRS API client
        """
        self.client = client

    def check_availability(self, domains: List[str]) -> List[DomainAvailability]:
        """
        Check availability of one or more domains.

        Args:
            domains: List of domain names to check

        Returns:
            List of DomainAvailability objects
        """
        results = []

        for domain in domains:
            try:
                attributes = {
                    'domain': domain.lower()
                }

                response = self.client.make_request('LOOKUP', 'DOMAIN', attributes)

                # Parse response
                # OpenSRS returns: 210 = Domain Available, 211 = Domain Taken
                response_code = int(response.get('response_code', 0))
                if response_code == 210:
                    available = True
                elif response_code == 211:
                    available = False
                else:
                    # Fallback to status field
                    available = response.get('attributes', {}).get('status') == 'available'

                is_premium = response.get('attributes', {}).get('is_premium', False)

                result = DomainAvailability(
                    domain=domain,
                    available=available,
                    is_premium=is_premium
                )

                results.append(result)

            except OpenSRSAPIError as e:
                logger.error(f"Domain lookup failed for {domain}: {e}")
                results.append(DomainAvailability(
                    domain=domain,
                    available=False,
                    error=str(e)
                ))

        return results

    def get_pricing(self, domain: str) -> Dict[str, float]:
        """
        Get pricing for domain registration.

        Args:
            domain: Domain name

        Returns:
            Dictionary with pricing for different year terms
        """
        try:
            attributes = {
                'domain': domain.lower()
            }

            response = self.client.make_request('GET_PRICE', 'DOMAIN', attributes)

            # Parse pricing from response
            pricing = {}
            prices = response.get('attributes', {}).get('price', {})

            for years in [1, 2, 3, 5, 10]:
                key = f'{years}_year'
                if key in prices:
                    pricing[key] = float(prices[key])

            return pricing

        except OpenSRSAPIError as e:
            logger.error(f"Failed to get pricing for {domain}: {e}")
            return {}

    def register_domain(self, request: DomainRegistrationRequest) -> Dict[str, Any]:
        """
        Register a new domain.

        Args:
            request: Domain registration request object

        Returns:
            Registration response with order ID and domain details

        Raises:
            OpenSRSAPIError: If registration fails
        """
        # Build contact set
        contact_set = {
            'owner': {
                'first_name': request.contacts.first_name,
                'last_name': request.contacts.last_name,
                'email': request.contacts.email,
                'phone': request.contacts.phone,
                'address1': request.contacts.address1,
                'city': request.contacts.city,
                'state': request.contacts.state,
                'postal_code': request.contacts.postal_code,
                'country': request.contacts.country
            }
        }

        # Add optional fields
        if request.contacts.org:
            contact_set['owner']['org_name'] = request.contacts.org
        if request.contacts.address2:
            contact_set['owner']['address2'] = request.contacts.address2

        # Use same contact for admin, billing, tech
        contact_set['admin'] = contact_set['owner']
        contact_set['billing'] = contact_set['owner']
        contact_set['tech'] = contact_set['owner']

        # Build nameserver list
        nameserver_list = [
            {'name': ns} for ns in request.nameservers
        ]

        # Build attributes
        attributes = {
            'domain': request.domain.lower(),
            'period': request.years,
            'contact_set': contact_set,
            'nameserver_list': nameserver_list,
            'auto_renew': 1 if request.auto_renew else 0,
            'f_whois_privacy': 1 if request.whois_privacy else 0,
            'f_lock_domain': 1 if request.transfer_lock else 0
        }

        # Make request
        response = self.client.make_request('SW_REGISTER', 'DOMAIN', attributes)

        return {
            'success': True,
            'order_id': response.get('attributes', {}).get('order_id'),
            'domain': request.domain,
            'registration_expiry': response.get('attributes', {}).get('registration_expiry_date'),
            'response': response
        }

    def transfer_domain(self, domain: str, auth_code: str,
                       contacts: DomainContact,
                       years: int = 1) -> Dict[str, Any]:
        """
        Transfer a domain to our account.

        Args:
            domain: Domain name to transfer
            auth_code: EPP authorization code
            contacts: Contact information
            years: Years to renew during transfer (usually 1)

        Returns:
            Transfer response
        """
        # Build contact set
        contact_set = {
            'owner': {
                'first_name': contacts.first_name,
                'last_name': contacts.last_name,
                'email': contacts.email,
                'phone': contacts.phone,
                'address1': contacts.address1,
                'city': contacts.city,
                'state': contacts.state,
                'postal_code': contacts.postal_code,
                'country': contacts.country
            }
        }

        if contacts.org:
            contact_set['owner']['org_name'] = contacts.org

        # Copy to other contact types
        contact_set['admin'] = contact_set['owner']
        contact_set['billing'] = contact_set['owner']
        contact_set['tech'] = contact_set['owner']

        attributes = {
            'domain': domain.lower(),
            'period': years,
            'contact_set': contact_set,
            'auth_code': auth_code
        }

        response = self.client.make_request('TRANSFER', 'DOMAIN', attributes)

        return {
            'success': True,
            'transfer_id': response.get('attributes', {}).get('transfer_id'),
            'domain': domain,
            'response': response
        }

    def renew_domain(self, domain: str, years: int = 1) -> Dict[str, Any]:
        """
        Renew a domain.

        Args:
            domain: Domain name
            years: Years to renew

        Returns:
            Renewal response
        """
        attributes = {
            'domain': domain.lower(),
            'period': years,
            'current_expiration_year': datetime.now().year
        }

        response = self.client.make_request('RENEW', 'DOMAIN', attributes)

        return {
            'success': True,
            'order_id': response.get('attributes', {}).get('order_id'),
            'domain': domain,
            'new_expiry': response.get('attributes', {}).get('registration_expiry_date'),
            'response': response
        }

    def update_nameservers(self, domain: str,
                          nameservers: List[str]) -> Dict[str, Any]:
        """
        Update nameservers for a domain.

        Args:
            domain: Domain name
            nameservers: List of nameserver hostnames

        Returns:
            Update response
        """
        nameserver_list = [{'name': ns} for ns in nameservers]

        attributes = {
            'domain': domain.lower(),
            'data': 'nameserver_list',
            'nameserver_list': nameserver_list
        }

        response = self.client.make_request('MODIFY', 'DOMAIN', attributes)

        return {
            'success': True,
            'domain': domain,
            'nameservers': nameservers,
            'response': response
        }

    def update_contacts(self, domain: str, contacts: DomainContact) -> Dict[str, Any]:
        """
        Update domain contact information.

        Args:
            domain: Domain name
            contacts: New contact information

        Returns:
            Update response
        """
        contact_set = {
            'owner': {
                'first_name': contacts.first_name,
                'last_name': contacts.last_name,
                'email': contacts.email,
                'phone': contacts.phone,
                'address1': contacts.address1,
                'city': contacts.city,
                'state': contacts.state,
                'postal_code': contacts.postal_code,
                'country': contacts.country
            }
        }

        if contacts.org:
            contact_set['owner']['org_name'] = contacts.org

        attributes = {
            'domain': domain.lower(),
            'data': 'contact_info',
            'contact_set': contact_set
        }

        response = self.client.make_request('MODIFY', 'DOMAIN', attributes)

        return {
            'success': True,
            'domain': domain,
            'response': response
        }

    def set_transfer_lock(self, domain: str, locked: bool) -> Dict[str, Any]:
        """
        Enable or disable transfer lock on domain.

        Args:
            domain: Domain name
            locked: True to lock, False to unlock

        Returns:
            Update response
        """
        attributes = {
            'domain': domain.lower(),
            'data': 'transfer_lock',
            'lock_state': 1 if locked else 0
        }

        response = self.client.make_request('MODIFY', 'DOMAIN', attributes)

        return {
            'success': True,
            'domain': domain,
            'locked': locked,
            'response': response
        }

    def enable_whois_privacy(self, domain: str, enabled: bool) -> Dict[str, Any]:
        """
        Enable or disable WHOIS privacy protection.

        Args:
            domain: Domain name
            enabled: True to enable, False to disable

        Returns:
            Update response
        """
        attributes = {
            'domain': domain.lower(),
            'data': 'whois_privacy',
            'state': 'enable' if enabled else 'disable'
        }

        response = self.client.make_request('MODIFY', 'DOMAIN', attributes)

        return {
            'success': True,
            'domain': domain,
            'whois_privacy': enabled,
            'response': response
        }

    def get_domain_info(self, domain: str) -> Dict[str, Any]:
        """
        Get detailed information about a domain.

        Args:
            domain: Domain name

        Returns:
            Domain information dictionary
        """
        attributes = {
            'domain': domain.lower(),
            'type': 'all_info'
        }

        response = self.client.make_request('GET', 'DOMAIN', attributes)

        return response.get('attributes', {})

    def get_auth_code(self, domain: str) -> str:
        """
        Get EPP authorization code for domain transfer.

        Args:
            domain: Domain name

        Returns:
            Authorization code
        """
        info = self.get_domain_info(domain)
        return info.get('auth_code', '')


# =============================================================================
# SSL MANAGER
# =============================================================================

class SSLManager:
    """
    SSL certificate management operations.
    """

    def __init__(self, client: OpenSRSClient):
        """
        Initialize SSL manager.

        Args:
            client: OpenSRS API client
        """
        self.client = client

    def list_products(self) -> List[Dict[str, Any]]:
        """
        List available SSL certificate products.

        Returns:
            List of SSL product information
        """
        attributes = {}

        response = self.client.make_request('QUERY_PRODUCT_INFO', 'TRUST_SERVICE', attributes)

        products = response.get('attributes', {}).get('product_list', [])
        return products

    def order_certificate(self, order: SSLCertificateOrder) -> Dict[str, Any]:
        """
        Order an SSL certificate.

        Args:
            order: SSL certificate order

        Returns:
            Order response with product ID

        Raises:
            OpenSRSAPIError: If order fails
        """
        attributes = {
            'product_code': order.product_code,
            'period': order.years,
            'csr': order.csr,
            'approver_email': order.validation_email,
            'validation_method': order.validation_method
        }

        # Add organization for OV/EV certificates
        if order.organization:
            attributes['org_name'] = order.organization

        # Add SAN domains if provided
        if order.san_domains:
            attributes['san_domains'] = order.san_domains

        response = self.client.make_request('SW_REGISTER', 'TRUST_SERVICE', attributes)

        return {
            'success': True,
            'product_id': response.get('attributes', {}).get('product_id'),
            'order_id': response.get('attributes', {}).get('order_id'),
            'domain': order.domain,
            'response': response
        }

    def retrieve_certificate(self, product_id: str) -> Dict[str, Any]:
        """
        Retrieve issued SSL certificate.

        Args:
            product_id: OpenSRS product ID

        Returns:
            Certificate data including PEM files
        """
        attributes = {
            'product_id': product_id
        }

        response = self.client.make_request('GET_PRODUCT', 'TRUST_SERVICE', attributes)

        cert_data = response.get('attributes', {})

        return {
            'certificate': cert_data.get('certificate'),
            'ca_bundle': cert_data.get('ca_bundle'),
            'chain': cert_data.get('chain'),
            'status': cert_data.get('status')
        }

    def reissue_certificate(self, product_id: str, csr: str,
                           validation_email: Optional[str] = None) -> Dict[str, Any]:
        """
        Reissue an existing SSL certificate.

        Args:
            product_id: OpenSRS product ID
            csr: New Certificate Signing Request
            validation_email: Validation email (if changed)

        Returns:
            Reissue response
        """
        attributes = {
            'product_id': product_id,
            'csr': csr
        }

        if validation_email:
            attributes['approver_email'] = validation_email

        response = self.client.make_request('REISSUE_SSL', 'TRUST_SERVICE', attributes)

        return {
            'success': True,
            'product_id': product_id,
            'response': response
        }

    def revoke_certificate(self, product_id: str, reason: str = 'unspecified') -> Dict[str, Any]:
        """
        Revoke an SSL certificate.

        Args:
            product_id: OpenSRS product ID
            reason: Revocation reason

        Returns:
            Revocation response
        """
        attributes = {
            'product_id': product_id,
            'reason': reason
        }

        response = self.client.make_request('REVOKE_SSL', 'TRUST_SERVICE', attributes)

        return {
            'success': True,
            'product_id': product_id,
            'response': response
        }


# =============================================================================
# DNS MANAGER
# =============================================================================

class DNSManager:
    """
    DNS zone management operations.
    """

    def __init__(self, client: OpenSRSClient):
        """
        Initialize DNS manager.

        Args:
            client: OpenSRS API client
        """
        self.client = client

    def get_zone(self, domain: str) -> Dict[str, Any]:
        """
        Get DNS zone for a domain.

        Args:
            domain: Domain name

        Returns:
            DNS zone data
        """
        attributes = {
            'domain': domain.lower()
        }

        response = self.client.make_request('GET_DNS_ZONE', 'DOMAIN', attributes)

        return response.get('attributes', {})

    def set_zone(self, domain: str, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Update DNS zone with new records.

        Args:
            domain: Domain name
            records: List of DNS records
                Each record: {type, name, value, ttl, priority (for MX)}

        Returns:
            Update response
        """
        attributes = {
            'domain': domain.lower(),
            'records': records
        }

        response = self.client.make_request('SET_DNS_ZONE', 'DOMAIN', attributes)

        return {
            'success': True,
            'domain': domain,
            'records': records,
            'response': response
        }


# =============================================================================
# CREDENTIAL ENCRYPTION HELPER
# =============================================================================

class CredentialEncryption:
    """
    Encrypt/decrypt OpenSRS credentials for secure storage.
    """

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new encryption key."""
        return Fernet.generate_key()

    @staticmethod
    def encrypt(data: str, key: bytes) -> Tuple[str, str]:
        """
        Encrypt data.

        Args:
            data: Plain text data
            key: Encryption key

        Returns:
            Tuple of (encrypted_data, iv)
        """
        f = Fernet(key)
        encrypted = f.encrypt(data.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8'), ''

    @staticmethod
    def decrypt(encrypted_data: str, key: bytes) -> str:
        """
        Decrypt data.

        Args:
            encrypted_data: Base64 encoded encrypted data
            key: Encryption key

        Returns:
            Decrypted plain text
        """
        f = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted = f.decrypt(encrypted_bytes)
        return decrypted.decode('utf-8')


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class OpenSRSAPIError(Exception):
    """OpenSRS API error exception"""

    def __init__(self, message: str, code: Optional[int] = None,
                 response: Optional[Dict] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.response = response


# =============================================================================
# FACTORY FUNCTION
# =============================================================================

def create_opensrs_client(username: str, api_key: str,
                          environment: str = 'test') -> Tuple[OpenSRSClient, DomainManager, SSLManager, DNSManager]:
    """
    Factory function to create OpenSRS client and managers.

    Args:
        username: OpenSRS username
        api_key: OpenSRS API key
        environment: 'test' or 'production'

    Returns:
        Tuple of (client, domain_manager, ssl_manager, dns_manager)
    """
    client = OpenSRSClient(username, api_key, environment)
    domain_manager = DomainManager(client)
    ssl_manager = SSLManager(client)
    dns_manager = DNSManager(client)

    return client, domain_manager, ssl_manager, dns_manager


# =============================================================================
# USAGE EXAMPLE
# =============================================================================

if __name__ == '__main__':
    # Example usage (not for production)
    import sys

    # Read credentials from file
    if len(sys.argv) > 1:
        cred_file = sys.argv[1]
        with open(cred_file) as f:
            lines = f.readlines()
            username = lines[0].split(':')[1].strip()
            api_key = lines[1].split(':')[1].strip()

        # Create clients
        client, domain_mgr, ssl_mgr, dns_mgr = create_opensrs_client(
            username, api_key, environment='test'
        )

        # Check domain availability
        print("Checking domain availability...")
        results = domain_mgr.check_availability(['example.com', 'example.net'])
        for result in results:
            print(f"{result.domain}: {'Available' if result.available else 'Unavailable'}")

        print("\nOpenSRS Integration Test Complete")
    else:
        print("Usage: python opensrs_integration.py /path/to/credentials")
        sys.exit(1)
