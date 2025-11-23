"""DNS Science Configuration"""
import os
from pathlib import Path

# Load .env file if it exists (WSGI should have already loaded .env.production)
# This is mainly for local development or CLI usage
try:
    from dotenv import load_dotenv
    # Get the directory containing this config file
    BASE_DIR = Path(__file__).resolve().parent

    # Try .env.production first (production), then .env (development)
    ENV_PRODUCTION = BASE_DIR / '.env.production'
    ENV_DEV = BASE_DIR / '.env'

    if ENV_PRODUCTION.exists():
        load_dotenv(ENV_PRODUCTION)
    elif ENV_DEV.exists():
        load_dotenv(ENV_DEV)
except ImportError:
    # python-dotenv not installed, rely on system environment variables
    pass

class Config:
    """Application configuration"""

    # Database configuration - MUST be provided via environment variables
    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = int(os.getenv('DB_PORT', '5432'))
    DB_NAME = os.getenv('DB_NAME', 'dnsscience')
    DB_USER = os.getenv('DB_USER')
    DB_PASS = os.getenv('DB_PASS')

    # Validate required database credentials at class definition time
    # This will fail fast if environment variables are not set
    if not DB_HOST:
        raise ValueError(
            "DB_HOST environment variable is required. "
            "Ensure .env.production exists or environment variables are set."
        )
    if not DB_USER:
        raise ValueError(
            "DB_USER environment variable is required. "
            "Ensure .env.production exists or environment variables are set."
        )
    if not DB_PASS:
        raise ValueError(
            "DB_PASS environment variable is required. "
            "Ensure .env.production exists or environment variables are set."
        )

    # Redis configuration - MUST be provided via environment variables
    REDIS_HOST = os.getenv('REDIS_HOST')
    REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))

    # Validate required Redis configuration
    if not REDIS_HOST:
        raise ValueError("REDIS_HOST environment variable is required")

    # Application settings
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

    # DNS scanning settings
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', '5'))
    DEFAULT_DNS_TIMEOUT = 5
    MAX_CONCURRENT_SCANS = 10

    # Common DKIM selectors to check (expanded brute-force list)
    DKIM_SELECTORS = [
        # Generic/Default
        'default', 'mail', 'dkim', 'smtp', 'email', 'mx', 'key', 'sig',

        # Numbered patterns
        'k1', 'k2', 'k3', 'k4', 'k5', 'k6', 'k7', 'k8', 'k9', 'k10',
        's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10',
        'selector1', 'selector2', 'selector3', 'selector4', 'selector5',
        'mail1', 'mail2', 'mail3', 'smtp1', 'smtp2', 'smtp3',

        # Major Email Providers
        'google', 'gmail', 'googlemail', 'gsuite', 'workspace',
        'microsoft', 'office365', 'outlook', 'o365', 'exchange',
        'yahoo', 'ymail', 'rocketmail',
        'apple', 'icloud', 'me',
        'protonmail', 'pm', 'tutanota',

        # Email Service Providers (ESPs)
        'amazonses', 'ses', 'mailgun', 'mg', 'sendgrid', 'sg',
        'mandrill', 'sparkpost', 'postmarkapp', 'postmark',
        'mailchimp', 'mc', 'constantcontact', 'sendinblue', 'sib',
        'sendpulse', 'mailjet', 'mj1', 'mj2',
        'elasticemail', 'pepipost', 'socketlabs',

        # Enterprise Mail Servers
        'mxvault', 'postfix', 'exim', 'zimbra', 'qmail',
        'domino', 'notes', 'groupwise', 'mdaemon',
        'kerio', 'axigen', 'smartermail', 'hmailserver',

        # Year-based selectors (2020-2025)
        '2020', '2021', '2022', '2023', '2024', '2025',
        'dkim2020', 'dkim2021', 'dkim2022', 'dkim2023', 'dkim2024', 'dkim2025',
        'key2020', 'key2021', 'key2022', 'key2023', 'key2024', 'key2025',

        # Month-based selectors
        'jan', 'feb', 'mar', 'apr', 'may', 'jun',
        'jul', 'aug', 'sep', 'oct', 'nov', 'dec',
        'january', 'february', 'march', 'april', 'june', 'july',
        'august', 'september', 'october', 'november', 'december',

        # Marketing/Transactional
        'marketing', 'newsletter', 'promo', 'notification',
        'transactional', 'system', 'noreply', 'auto',

        # Security/Auth
        'dmarc', 'spf', 'auth', 'secure', 'verified',

        # Regional/Language
        'uk', 'us', 'eu', 'asia', 'apac', 'emea',
        'prod', 'production', 'live', 'primary', 'main'
    ]

    # SSL/TLS settings
    SSL_VERIFY = True
    SSL_TIMEOUT = 10

    # SMTP settings
    SMTP_TIMEOUT = 10

    # HTTP settings
    HTTP_TIMEOUT = 10

    # Rate limiting
    RATE_LIMIT_ENABLED = True
    DEFAULT_RATE_LIMIT = 1000  # requests per hour

    # External API Keys
    CLOUDFLARE_API_TOKEN = os.getenv('CLOUDFLARE_API_TOKEN')
    CLOUDFLARE_ACCOUNT_ID = os.getenv('CLOUDFLARE_ACCOUNT_ID')
    IPINFO_TOKEN = os.getenv('IPINFO_TOKEN')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')

    # OpenSRS Domain Registration API
    OPENSRS_USERNAME = os.getenv('OPENSRS_USERNAME')
    OPENSRS_API_KEY = os.getenv('OPENSRS_API_KEY')
    OPENSRS_ENVIRONMENT = os.getenv('OPENSRS_ENVIRONMENT', 'test')  # 'test' or 'production'
