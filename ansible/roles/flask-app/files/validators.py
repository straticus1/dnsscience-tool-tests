#!/usr/bin/env python3
"""
DNS Science - Comprehensive Form & Input Validation
Server-side validation for all user inputs, API requests, and data processing
"""

import re
import ipaddress
import dns.name
import dns.resolver
from typing import Optional, List, Dict, Tuple, Any
from urllib.parse import urlparse
import json


class ValidationError(Exception):
    """Custom exception for validation errors"""
    def __init__(self, field: str, message: str, code: str = None):
        self.field = field
        self.message = message
        self.code = code or "VALIDATION_ERROR"
        super().__init__(f"{field}: {message}")


class Validator:
    """Main validation class for DNS Science"""

    # Regex patterns
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    DOMAIN_REGEX = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$', re.IGNORECASE)
    API_KEY_REGEX = re.compile(r'^sk_(test|live)_[a-zA-Z0-9]{32,}$')
    UUID_REGEX = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.IGNORECASE)

    # Password requirements
    MIN_PASSWORD_LENGTH = 12
    MAX_PASSWORD_LENGTH = 128

    # Domain constraints
    MAX_DOMAIN_LENGTH = 253
    MAX_LABEL_LENGTH = 63

    @staticmethod
    def validate_email(email: str, check_mx: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Validate email address (RFC 5322)

        Args:
            email: Email address to validate
            check_mx: If True, verify MX records exist for domain

        Returns:
            (is_valid, error_message)
        """
        if not email:
            return False, "Email address is required"

        if len(email) > 254:
            return False, "Email address is too long (max 254 characters)"

        if not Validator.EMAIL_REGEX.match(email):
            return False, "Invalid email format"

        # Check for common typos
        common_typos = {
            'gmial.com': 'gmail.com',
            'gmai.com': 'gmail.com',
            'yahooo.com': 'yahoo.com',
            'hotmial.com': 'hotmail.com'
        }

        domain = email.split('@')[1].lower()
        if domain in common_typos:
            return False, f"Did you mean {email.split('@')[0]}@{common_typos[domain]}?"

        if check_mx:
            try:
                resolver = dns.resolver.Resolver()
                resolver.resolve(domain, 'MX')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return False, f"Domain {domain} has no MX records"
            except Exception as e:
                return False, f"Failed to verify domain: {str(e)}"

        return True, None

    @staticmethod
    def validate_domain(domain: str, allow_wildcards: bool = False, check_dns: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Validate DNS domain name (RFC 1035, RFC 1123)

        Args:
            domain: Domain name to validate
            allow_wildcards: Allow wildcard domains (*.example.com)
            check_dns: If True, verify domain exists in DNS

        Returns:
            (is_valid, error_message)
        """
        if not domain:
            return False, "Domain name is required"

        # Strip trailing dot if present (FQDN)
        domain = domain.rstrip('.')

        if len(domain) > Validator.MAX_DOMAIN_LENGTH:
            return False, f"Domain name is too long (max {Validator.MAX_DOMAIN_LENGTH} characters)"

        # Handle wildcards
        if domain.startswith('*.'):
            if not allow_wildcards:
                return False, "Wildcard domains are not allowed"
            domain = domain[2:]  # Remove wildcard for validation

        # Validate using dnspython
        try:
            dns.name.from_text(domain)
        except dns.name.LabelTooLong:
            return False, f"Domain label exceeds {Validator.MAX_LABEL_LENGTH} characters"
        except dns.name.EmptyLabel:
            return False, "Domain contains empty label"
        except Exception as e:
            return False, f"Invalid domain name: {str(e)}"

        # Check each label
        labels = domain.split('.')
        if len(labels) < 2:
            return False, "Domain must have at least two labels (e.g., example.com)"

        for label in labels:
            if len(label) > Validator.MAX_LABEL_LENGTH:
                return False, f"Label '{label}' exceeds {Validator.MAX_LABEL_LENGTH} characters"

            if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', label, re.IGNORECASE):
                return False, f"Invalid label '{label}' (must start and end with alphanumeric)"

        # Validate TLD
        tld = labels[-1].lower()
        if tld.isdigit():
            return False, "TLD cannot be all numeric"

        if check_dns:
            try:
                resolver = dns.resolver.Resolver()
                resolver.resolve(domain, 'A')
            except dns.resolver.NXDOMAIN:
                return False, f"Domain {domain} does not exist (NXDOMAIN)"
            except dns.resolver.NoAnswer:
                # Domain exists but has no A record - that's okay
                pass
            except Exception as e:
                return False, f"Failed to verify domain: {str(e)}"

        return True, None

    @staticmethod
    def validate_ip_address(ip: str, version: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate IP address (IPv4 or IPv6)

        Args:
            ip: IP address string
            version: Expected IP version (4 or 6), or None for either

        Returns:
            (is_valid, error_message)
        """
        if not ip:
            return False, "IP address is required"

        try:
            ip_obj = ipaddress.ip_address(ip)

            if version and ip_obj.version != version:
                return False, f"Expected IPv{version} address, got IPv{ip_obj.version}"

            return True, None

        except ValueError as e:
            return False, f"Invalid IP address: {str(e)}"

    @staticmethod
    def validate_cidr(cidr: str, version: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate CIDR notation (e.g., 192.0.2.0/24)

        Args:
            cidr: CIDR string
            version: Expected IP version (4 or 6), or None for either

        Returns:
            (is_valid, error_message)
        """
        if not cidr:
            return False, "CIDR notation is required"

        try:
            network = ipaddress.ip_network(cidr, strict=False)

            if version and network.version != version:
                return False, f"Expected IPv{version} network, got IPv{network.version}"

            return True, None

        except ValueError as e:
            return False, f"Invalid CIDR notation: {str(e)}"

    @staticmethod
    def validate_url(url: str, require_https: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Validate URL

        Args:
            url: URL string
            require_https: If True, only allow HTTPS URLs

        Returns:
            (is_valid, error_message)
        """
        if not url:
            return False, "URL is required"

        try:
            parsed = urlparse(url)

            if not parsed.scheme:
                return False, "URL must include scheme (http:// or https://)"

            if require_https and parsed.scheme != 'https':
                return False, "URL must use HTTPS"

            if parsed.scheme not in ['http', 'https']:
                return False, f"Unsupported URL scheme: {parsed.scheme}"

            if not parsed.netloc:
                return False, "URL must include hostname"

            # Validate hostname
            hostname = parsed.netloc.split(':')[0]  # Remove port if present
            is_valid, error = Validator.validate_domain(hostname)
            if not is_valid:
                # Could be an IP address
                is_valid_ip, _ = Validator.validate_ip_address(hostname)
                if not is_valid_ip:
                    return False, f"Invalid hostname in URL: {error}"

            return True, None

        except Exception as e:
            return False, f"Invalid URL: {str(e)}"

    @staticmethod
    def validate_password(password: str, username: Optional[str] = None) -> Tuple[bool, List[str]]:
        """
        Validate password strength

        Requirements:
        - 12+ characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        - Not contain username

        Args:
            password: Password to validate
            username: Username (to prevent password == username)

        Returns:
            (is_valid, list_of_errors)
        """
        errors = []

        if not password:
            return False, ["Password is required"]

        if len(password) < Validator.MIN_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {Validator.MIN_PASSWORD_LENGTH} characters")

        if len(password) > Validator.MAX_PASSWORD_LENGTH:
            errors.append(f"Password must be less than {Validator.MAX_PASSWORD_LENGTH} characters")

        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")

        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")

        if not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")

        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':\"\\|,.<>\/?]', password):
            errors.append("Password must contain at least one special character")

        if username and username.lower() in password.lower():
            errors.append("Password cannot contain username")

        # Check for common weak passwords
        common_passwords = [
            'password', 'password123', 'admin123', 'welcome123',
            'qwerty123', 'abc123', 'letmein', 'monkey123'
        ]
        if password.lower() in common_passwords:
            errors.append("Password is too common")

        return len(errors) == 0, errors

    @staticmethod
    def validate_username(username: str) -> Tuple[bool, Optional[str]]:
        """
        Validate username

        Rules:
        - 3-32 characters
        - Alphanumeric, underscore, hyphen only
        - Must start with letter or number
        - Cannot end with hyphen or underscore

        Args:
            username: Username to validate

        Returns:
            (is_valid, error_message)
        """
        if not username:
            return False, "Username is required"

        if len(username) < 3:
            return False, "Username must be at least 3 characters"

        if len(username) > 32:
            return False, "Username must be less than 32 characters"

        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$', username):
            return False, "Username must start and end with alphanumeric, and contain only letters, numbers, hyphens, and underscores"

        # Reserved usernames
        reserved = [
            'admin', 'root', 'system', 'administrator', 'api', 'www',
            'mail', 'support', 'help', 'security', 'noreply', 'postmaster'
        ]
        if username.lower() in reserved:
            return False, "Username is reserved"

        return True, None

    @staticmethod
    def validate_api_key(api_key: str) -> Tuple[bool, Optional[str]]:
        """
        Validate API key format

        Expected format: sk_live_XXXXXXXXXXXXXXXXXXXXX or sk_test_XXXXXXXXXXXXXXXXXXXXX

        Args:
            api_key: API key to validate

        Returns:
            (is_valid, error_message)
        """
        if not api_key:
            return False, "API key is required"

        if not Validator.API_KEY_REGEX.match(api_key):
            return False, "Invalid API key format (expected: sk_live_... or sk_test_...)"

        return True, None

    @staticmethod
    def validate_json_schema(data: Any, schema: Dict) -> Tuple[bool, List[str]]:
        """
        Validate JSON data against a schema

        Args:
            data: Data to validate
            schema: JSON schema definition

        Returns:
            (is_valid, list_of_errors)
        """
        try:
            import jsonschema
            jsonschema.validate(instance=data, schema=schema)
            return True, []
        except jsonschema.ValidationError as e:
            return False, [str(e)]
        except jsonschema.SchemaError as e:
            return False, [f"Invalid schema: {str(e)}"]

    @staticmethod
    def validate_stix_pattern(pattern: str) -> Tuple[bool, Optional[str]]:
        """
        Validate STIX 2.1 pattern syntax

        Args:
            pattern: STIX pattern string

        Returns:
            (is_valid, error_message)
        """
        if not pattern:
            return False, "STIX pattern is required"

        # Basic syntax check
        if not pattern.startswith('[') or not pattern.endswith(']'):
            return False, "STIX pattern must be enclosed in square brackets"

        # Check for valid object types
        valid_objects = [
            'domain-name', 'ipv4-addr', 'ipv6-addr', 'url', 'file',
            'email-addr', 'email-message', 'network-traffic', 'process'
        ]

        found_object = False
        for obj_type in valid_objects:
            if obj_type in pattern:
                found_object = True
                break

        if not found_object:
            return False, f"STIX pattern must contain a valid object type: {', '.join(valid_objects)}"

        # Check for comparison operators
        if ' = ' not in pattern and ' != ' not in pattern and ' LIKE ' not in pattern:
            return False, "STIX pattern must contain a comparison operator (=, !=, LIKE)"

        return True, None

    @staticmethod
    def validate_report_format(format_type: str, tier: str = 'free') -> Tuple[bool, Optional[str]]:
        """
        Validate report format based on subscription tier

        Args:
            format_type: Report format (pdf, html, csv, json)
            tier: Subscription tier

        Returns:
            (is_valid, error_message)
        """
        tier_formats = {
            'anonymous': ['pdf', 'html'],
            'free': ['pdf', 'html'],
            'essentials': ['pdf', 'html', 'csv'],
            'professional': ['pdf', 'html', 'csv', 'json'],
            'commercial': ['pdf', 'html', 'csv', 'json'],
            'research': ['pdf', 'html', 'csv', 'json'],
            'enterprise': ['pdf', 'html', 'csv', 'json']
        }

        tier_lower = tier.lower()

        if tier_lower not in tier_formats:
            return False, f"Invalid tier: {tier}"

        allowed_formats = tier_formats[tier_lower]

        if format_type.lower() not in allowed_formats:
            return False, f"Format '{format_type}' not available for {tier} tier. Available formats: {', '.join(allowed_formats)}"

        return True, None

    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 1000) -> str:
        """
        Sanitize user input to prevent XSS and injection attacks

        Args:
            input_str: Input string to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized string
        """
        if not input_str:
            return ""

        # Truncate to max length
        sanitized = input_str[:max_length]

        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')

        # HTML entity encoding for special characters
        html_escape_table = {
            "&": "&amp;",
            '"': "&quot;",
            "'": "&#x27;",
            ">": "&gt;",
            "<": "&lt;",
        }

        for char, escape in html_escape_table.items():
            sanitized = sanitized.replace(char, escape)

        return sanitized

    @staticmethod
    def validate_scan_options(options: Dict) -> Tuple[bool, List[str]]:
        """
        Validate domain scan options

        Args:
            options: Scan options dictionary

        Returns:
            (is_valid, list_of_errors)
        """
        errors = []

        # Valid scan types
        if 'scan_type' in options:
            valid_types = ['quick', 'standard', 'full']
            if options['scan_type'] not in valid_types:
                errors.append(f"Invalid scan_type. Must be one of: {', '.join(valid_types)}")

        # Boolean options
        boolean_options = [
            'include_subdomains', 'check_dnssec', 'check_ssl',
            'check_email', 'check_reverse_dns', 'threat_intel'
        ]

        for opt in boolean_options:
            if opt in options and not isinstance(options[opt], bool):
                errors.append(f"Option '{opt}' must be boolean (true/false)")

        return len(errors) == 0, errors


# Convenience functions
def validate_domain_list(domains: List[str], max_count: int = 1000) -> Tuple[bool, List[str]]:
    """Validate a list of domains"""
    errors = []

    if not domains:
        return False, ["Domain list is empty"]

    if len(domains) > max_count:
        return False, [f"Too many domains (max {max_count})"]

    validator = Validator()
    for i, domain in enumerate(domains):
        is_valid, error = validator.validate_domain(domain)
        if not is_valid:
            errors.append(f"Domain {i+1} ({domain}): {error}")

    return len(errors) == 0, errors


def validate_registration_form(data: Dict) -> Tuple[bool, Dict[str, str]]:
    """Validate user registration form"""
    errors = {}
    validator = Validator()

    # Username
    if 'username' in data:
        is_valid, error = validator.validate_username(data['username'])
        if not is_valid:
            errors['username'] = error
    else:
        errors['username'] = "Username is required"

    # Email
    if 'email' in data:
        is_valid, error = validator.validate_email(data['email'], check_mx=True)
        if not is_valid:
            errors['email'] = error
    else:
        errors['email'] = "Email is required"

    # Password
    if 'password' in data:
        is_valid, password_errors = validator.validate_password(
            data['password'],
            data.get('username')
        )
        if not is_valid:
            errors['password'] = '; '.join(password_errors)
    else:
        errors['password'] = "Password is required"

    # Password confirmation
    if 'password_confirm' in data:
        if data.get('password') != data['password_confirm']:
            errors['password_confirm'] = "Passwords do not match"
    else:
        errors['password_confirm'] = "Password confirmation is required"

    return len(errors) == 0, errors


# Example usage
if __name__ == '__main__':
    validator = Validator()

    print("=" * 80)
    print("DNS Science - Validation Examples")
    print("=" * 80)

    # Test domain validation
    print("\n1. Domain Validation:")
    test_domains = ['example.com', 'invalid..com', '*.example.com', 'a' * 300]
    for domain in test_domains:
        is_valid, error = validator.validate_domain(domain, allow_wildcards=True)
        status = "✓" if is_valid else "✗"
        print(f"  {status} {domain}: {error or 'Valid'}")

    # Test email validation
    print("\n2. Email Validation:")
    test_emails = ['user@example.com', 'invalid@', 'user@gmial.com']
    for email in test_emails:
        is_valid, error = validator.validate_email(email)
        status = "✓" if is_valid else "✗"
        print(f"  {status} {email}: {error or 'Valid'}")

    # Test IP validation
    print("\n3. IP Address Validation:")
    test_ips = ['192.0.2.1', '2001:db8::1', '999.999.999.999', 'not-an-ip']
    for ip in test_ips:
        is_valid, error = validator.validate_ip_address(ip)
        status = "✓" if is_valid else "✗"
        print(f"  {status} {ip}: {error or 'Valid'}")

    # Test password validation
    print("\n4. Password Validation:")
    test_passwords = ['WeakPass', 'StrongP@ssw0rd123!', 'password123']
    for pwd in test_passwords:
        is_valid, errors = validator.validate_password(pwd)
        status = "✓" if is_valid else "✗"
        print(f"  {status} {pwd}: {errors if errors else 'Valid'}")

    # Test STIX pattern validation
    print("\n5. STIX Pattern Validation:")
    test_patterns = [
        "[domain-name:value = 'evil.com']",
        "[ipv4-addr:value = '192.0.2.1']",
        "invalid pattern"
    ]
    for pattern in test_patterns:
        is_valid, error = validator.validate_stix_pattern(pattern)
        status = "✓" if is_valid else "✗"
        print(f"  {status} {pattern}: {error or 'Valid'}")
