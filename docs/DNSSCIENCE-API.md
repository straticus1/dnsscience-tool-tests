# DNSScience.io Platform API Integration

## Overview

dnsscience-util now includes full integration with the DNSScience.io platform API, providing cloud-based DNS security scanning, domain tracking, and comprehensive analysis capabilities.

## Features

- **Comprehensive Security Scanning**: DNSSEC, SPF, DKIM, DMARC, MTA-STS, SMTP STARTTLS, SSL certificates
- **Domain Tracking**: Monitor multiple domains with historical data
- **Search Capabilities**: Find domains by name or pattern
- **Secure Key Management**: API keys stored with restrictive permissions
- **Rate Limits**:
  - Free Tier: 100 requests/hour
  - Authenticated Users: 1,000 requests/hour
  - Premium Users: 10,000 requests/hour

## Quick Start

### 1. Get Your API Key

If you don't have an API key yet, visit [dnsscience.io](https://dnsscience.io) to sign up.

### 2. Configure API Key (One-Time Setup)

```bash
# Add your API key
./dnsscience-util.py --api-add-key dns_live_YOUR_API_KEY

# Test the connection
./dnsscience-util.py --api-test
```

Your API key is securely stored at `~/.dnsscience/config.json` with restrictive permissions (0600).

### 3. Start Using the API

```bash
# Scan a domain
./dnsscience-util.py --api-scan example.com

# Get domain information
./dnsscience-util.py --api-info example.com
```

## API Key Management

### Add or Update API Key

```bash
./dnsscience-util.py --api-add-key dns_live_YOUR_API_KEY
```

Output:
```
✓ API key added successfully
Stored in: /Users/username/.dnsscience/config.json

Test your connection with: dnsscience-util --api-test
```

### Show Current API Key (Masked)

```bash
./dnsscience-util.py --api-show-key
```

Output:
```
API Key (masked): dns_live_c8e...6a7b8c9d0e1f
Stored in: /Users/username/.dnsscience/config.json
```

### Test API Connection

```bash
./dnsscience-util.py --api-test
```

Output:
```
Testing connection to https://dnsscience.com/api...
✓ Connection successful
API key: dns_live_c8e...6a7b8c9d0e1f
```

### Remove API Key

```bash
./dnsscience-util.py --api-remove-key
```

Output:
```
✓ API key removed
```

## API Commands

### Domain Scanning

Perform comprehensive security scan including DNSSEC, SPF, DKIM, DMARC, MTA-STS, STARTTLS, and SSL certificates.

```bash
./dnsscience-util.py --api-scan example.com
```

**Response Example:**
```json
{
  "domain": "example.com",
  "scan_id": "abc123",
  "timestamp": "2025-11-10T18:00:00Z",
  "results": {
    "dnssec": {
      "status": "enabled",
      "valid": true,
      "details": "..."
    },
    "spf": {
      "status": "pass",
      "record": "v=spf1 ...",
      "details": "..."
    },
    "dkim": {
      "status": "configured",
      "selectors": ["default", "mail"],
      "details": "..."
    },
    "dmarc": {
      "status": "enforced",
      "policy": "quarantine",
      "record": "v=DMARC1; ...",
      "details": "..."
    },
    "mtasts": {
      "status": "enabled",
      "mode": "enforce",
      "details": "..."
    },
    "ssl": {
      "status": "valid",
      "issuer": "Let's Encrypt",
      "expiration": "2026-01-15T00:00:00Z",
      "details": "..."
    }
  },
  "security_score": 95
}
```

### Get Domain Information

Retrieve latest scan results for a domain.

```bash
./dnsscience-util.py --api-info example.com
```

**Response Example:**
```json
{
  "domain": "example.com",
  "last_scan": "2025-11-10T18:00:00Z",
  "status": "active",
  "security_score": 95,
  "issues": [],
  "summary": {
    "dnssec": "enabled",
    "spf": "configured",
    "dkim": "configured",
    "dmarc": "enforced"
  }
}
```

### Get Domain History

View historical scan data with trend analysis.

```bash
./dnsscience-util.py --api-history example.com
```

**Response Example:**
```json
{
  "domain": "example.com",
  "scans": [
    {
      "scan_id": "scan_123",
      "timestamp": "2025-11-10T18:00:00Z",
      "security_score": 95
    },
    {
      "scan_id": "scan_122",
      "timestamp": "2025-11-09T18:00:00Z",
      "security_score": 92
    }
  ],
  "trend": "improving",
  "total_scans": 45
}
```

### List Tracked Domains

Show all domains being monitored.

```bash
./dnsscience-util.py --api-list
```

**Response Example:**
```json
{
  "domains": [
    {
      "domain": "example.com",
      "security_score": 95,
      "last_scan": "2025-11-10T18:00:00Z",
      "status": "active"
    },
    {
      "domain": "example.org",
      "security_score": 88,
      "last_scan": "2025-11-10T17:30:00Z",
      "status": "active"
    }
  ],
  "total": 2
}
```

### Search Domains

Search for domains by name or pattern.

```bash
./dnsscience-util.py --api-search "example"
```

**Response Example:**
```json
{
  "query": "example",
  "results": [
    {
      "domain": "example.com",
      "security_score": 95,
      "last_scan": "2025-11-10T18:00:00Z"
    },
    {
      "domain": "example.org",
      "security_score": 88,
      "last_scan": "2025-11-10T17:30:00Z"
    }
  ],
  "total_results": 2
}
```

## Integration Examples

### Python Script Integration

```python
from dnsscience_util import DNSScienceAPI, Logger

# Initialize with API key
logger = Logger()
api = DNSScienceAPI(api_key='dns_live_YOUR_API_KEY', logger=logger)

# Test connection
if api.test_connection():
    print("Connected successfully!")

# Scan a domain
result = api.scan_domain('example.com')
print(f"Security score: {result['security_score']}")

# Get domain info
info = api.get_domain_info('example.com')
print(f"Last scan: {info['last_scan']}")

# Search domains
results = api.search_domains('example')
print(f"Found {results['total_results']} domains")
```

### Automated Monitoring Script

```bash
#!/bin/bash
# monitor-domains.sh - Daily domain security monitoring

DOMAINS=(
    "example.com"
    "example.org"
    "example.net"
)

for domain in "${DOMAINS[@]}"; do
    echo "Scanning $domain..."
    ./dnsscience-util.py --api-scan "$domain" --json > "scan-$domain.json"

    # Extract security score
    score=$(jq '.security_score' "scan-$domain.json")

    # Alert if score drops below threshold
    if [ "$score" -lt 80 ]; then
        echo "WARNING: $domain security score is $score"
        # Send alert (email, Slack, etc.)
    fi
done
```

### CI/CD Integration

```yaml
# .github/workflows/dns-security.yml
name: DNS Security Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'

      - name: Install dnsscience-util
        run: pip install -r requirements.txt

      - name: Configure API Key
        run: |
          ./dnsscience-util.py --api-add-key ${{ secrets.DNSSCIENCE_API_KEY }}

      - name: Scan Domains
        run: |
          ./dnsscience-util.py --api-scan example.com > scan-results.json

      - name: Check Security Score
        run: |
          score=$(jq '.security_score' scan-results.json)
          if [ "$score" -lt 80 ]; then
            echo "Security score below threshold: $score"
            exit 1
          fi

      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: scan-results
          path: scan-results.json
```

## Security Best Practices

### API Key Storage

1. **Never commit API keys to version control**
   - Add `.dnsscience/` to `.gitignore`
   - Use environment variables for CI/CD
   - Use secrets management in production

2. **File permissions**
   - Config file is automatically set to 0600 (owner read/write only)
   - Directory permissions: 0700

3. **Key rotation**
   ```bash
   # Remove old key
   ./dnsscience-util.py --api-remove-key

   # Add new key
   ./dnsscience-util.py --api-add-key dns_live_NEW_KEY
   ```

### Rate Limiting

Monitor your API usage to stay within rate limits:

- **Free Tier**: 100 requests/hour
- **Authenticated**: 1,000 requests/hour
- **Premium**: 10,000 requests/hour

Implement exponential backoff for rate limit errors:

```python
import time

def scan_with_retry(domain, max_retries=3):
    for attempt in range(max_retries):
        try:
            return api.scan_domain(domain)
        except Exception as e:
            if 'rate limit' in str(e).lower():
                wait_time = 2 ** attempt  # Exponential backoff
                print(f"Rate limited, waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise
    raise Exception("Max retries exceeded")
```

## Troubleshooting

### API Key Not Found

```
Error: API key required. Use 'api add-key <key>' to configure.
```

**Solution**: Add your API key first
```bash
./dnsscience-util.py --api-add-key dns_live_YOUR_API_KEY
```

### Connection Failed

```
✗ Connection failed
Please check your API key and internet connection
```

**Solutions**:
1. Verify API key is correct
2. Check internet connectivity
3. Verify firewall allows HTTPS to dnsscience.com
4. Check API status at status.dnsscience.io

### Rate Limit Exceeded

```
Error: Rate limit exceeded. Please try again later.
```

**Solutions**:
1. Wait for rate limit window to reset (hourly)
2. Upgrade to higher tier for increased limits
3. Implement rate limiting in your scripts

### Invalid API Key

```
Error: Authentication failed. Invalid API key.
```

**Solutions**:
1. Verify key is copied correctly (no extra spaces)
2. Check key hasn't expired
3. Generate new key from dashboard

## API Reference

### Base URL
```
https://dnsscience.com/api
```

### Authentication
Include API key in Authorization header:
```
Authorization: Bearer dns_live_YOUR_API_KEY
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan` | Scan domain |
| GET | `/domain/{domain}` | Get domain info |
| GET | `/domain/{domain}/history` | Get scan history |
| GET | `/domains` | List tracked domains |
| GET | `/search?q={pattern}` | Search domains |

### Response Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad Request |
| 401 | Unauthorized (invalid API key) |
| 404 | Domain not found |
| 429 | Rate limit exceeded |
| 500 | Server error |

## Support

- **Documentation**: https://www.dnsscience.io/docs
- **API Status**: https://status.dnsscience.io
- **Support**: support@dnsscience.io
- **Community**: https://community.dnsscience.io

## Enterprise Features

For enterprise customers, additional features are available:

- **Custom Scan Types**: Define custom security checks
- **Webhook Notifications**: Real-time alerts
- **Bulk Operations**: Scan thousands of domains
- **Priority Support**: Dedicated support team
- **SLA Guarantees**: 99.9% uptime guarantee

Contact enterprise@dnsscience.io for more information.
