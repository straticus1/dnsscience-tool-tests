# DNSScience CLI - Complete Guide

The comprehensive command-line interface for DNSScience.io - Advanced DNS Intelligence Platform.

## Features

- **DNS Auto-Detection** - Detect your IP, resolver, EDNS support, and security score
- **Email Security Analysis** - Complete DMARC, SPF, DKIM, DANE, MTA-STS analysis
- **Domain Valuation** - AI-powered domain value estimation
- **SSL Certificate Analysis** - Certificate chain, expiry, and security validation
- **RDAP Lookup** - Registration data, nameservers, and domain events
- **Threat Intelligence** - Multi-source IP reputation and threat scoring
- **Visual Traceroute** - Network path visualization with geolocation
- **Batch Processing** - Process multiple domains with parallel checks
- **Multiple Output Formats** - Table, JSON, YAML, and CSV output

## Installation

### Method 1: pip install (Recommended)

```bash
pip install dnsscience-cli
```

### Method 2: From source

```bash
git clone https://github.com/dnsscience/cli.git
cd cli
pip install -r requirements.txt
pip install -e .
```

### Method 3: Direct execution

```bash
chmod +x dnsscience.py
./dnsscience.py --help
```

## Quick Start

### 1. Auto-Detect Your DNS Configuration

```bash
dnsscience autodetect
```

**Output:**
```
============================================================
DNS AUTO-DETECTION RESULTS
============================================================

IP Information:
  IP Address: 203.45.67.89
  Location: San Francisco, US
  ISP: Comcast Cable Communications

DNS Resolver:
  Server: 8.8.8.8
  Provider: Google Public DNS
  DNSSEC: Enabled

EDNS Information:
  Support: Yes
  Client Subnet: 203.45.67.0/24

Security Score: 85/100
```

### 2. Email Security Analysis

```bash
dnsscience email example.com
```

**Output:**
```
============================================================
EMAIL SECURITY ANALYSIS: example.com
============================================================

DMARC:
  Policy: quarantine
  Subdomain Policy: reject
  Percentage: 100%
  Status: ✓ PASS

SPF:
  Record: v=spf1 include:_spf.google.com ~all
  Status: ✓ PASS

DKIM:
  Selectors Found: 2
  Status: ✓ PASS

MTA-STS:
  Mode: enforce
  Status: ✓ ENABLED

Overall Security Score: 92/100
```

### 3. Domain Valuation

```bash
dnsscience value premium-domain.com
```

### 4. SSL Certificate Analysis

```bash
dnsscience ssl example.com
```

### 5. RDAP Lookup

```bash
dnsscience rdap example.com
```

### 6. Threat Intelligence

```bash
dnsscience threat 1.2.3.4
```

### 7. Visual Traceroute

```bash
dnsscience trace example.com
```

**Output:**
```
============================================================
TRACEROUTE: example.com
============================================================

+-----+----------------+------------------------+---------+----------------------+
| Hop | IP             | Hostname               | Latency | Location             |
+=====+================+========================+=========+======================+
| 1   | 192.168.1.1    | gateway.local          | 2.34ms  | San Francisco, US    |
| 2   | 10.45.67.1     | core-router.isp.net    | 5.67ms  | Oakland, US          |
| 3   | 203.45.78.2    | border.isp.net         | 12.45ms | Los Angeles, US      |
| 4   | 93.184.216.34  | example.com            | 45.23ms | Ashburn, US          |
+-----+----------------+------------------------+---------+----------------------+

Total Hops: 4
Total Latency: 65.69ms
Countries Traversed: 1
```

## Advanced Usage

### Batch Processing

Process multiple domains from a file:

```bash
# Create domains file
cat > domains.txt <<EOF
example.com
google.com
cloudflare.com
EOF

# Run batch checks
dnsscience batch domains.txt --checks email,ssl,rdap --output results.json
```

**Options:**
- `--checks` - Comma-separated: `email,ssl,rdap,threat,value`
- `--output` - Save to file
- `--format` - Output format: `json` or `csv`

### Output Formats

All commands support multiple output formats:

```bash
# JSON output
dnsscience email example.com --format json

# YAML output
dnsscience email example.com --format yaml

# CSV output (for batch operations)
dnsscience batch domains.txt --format csv --output results.csv

# Table output (default)
dnsscience email example.com --format table
```

### Configuration

Save your API key and preferences:

```bash
# Set API key (for authenticated features)
dnsscience config --api-key YOUR_API_KEY_HERE

# Set custom API URL (for self-hosted instances)
dnsscience config --api-url https://your-instance.com

# Set default output format
dnsscience config --format json

# Show current configuration
dnsscience config --show
```

Configuration is saved in `~/.dnsscience.conf`

## Complete Command Reference

### autodetect

Detect your DNS configuration automatically.

```bash
dnsscience autodetect [--format FORMAT]
```

**Options:**
- `--format`, `-f` - Output format: `table`, `json`, `yaml`, `csv`

**Returns:**
- IP address and geolocation
- DNS resolver information
- EDNS support and client subnet
- DNS security score

---

### email

Comprehensive email security analysis.

```bash
dnsscience email <domain> [--format FORMAT]
```

**Arguments:**
- `domain` - Domain name to analyze

**Options:**
- `--format`, `-f` - Output format

**Checks:**
- DMARC policy and configuration
- SPF record validation
- DKIM selector discovery
- DANE TLSA records
- MTA-STS policy
- BIMI records

---

### value

Estimate domain valuation using AI analysis.

```bash
dnsscience value <domain> [--format FORMAT]
```

**Arguments:**
- `domain` - Domain name to valuate

**Returns:**
- Estimated market value
- Confidence level
- Valuation factors (age, traffic, keywords, etc.)

---

### ssl

Analyze SSL/TLS certificate.

```bash
dnsscience ssl <domain> [--format FORMAT]
```

**Arguments:**
- `domain` - Domain name

**Returns:**
- Certificate details (subject, issuer, dates)
- Certificate chain
- Security validation
- Days until expiry
- Cipher suite information

---

### rdap

RDAP (Registration Data Access Protocol) lookup.

```bash
dnsscience rdap <domain> [--format FORMAT]
```

**Arguments:**
- `domain` - Domain name

**Returns:**
- Registration data
- Nameservers
- Domain status
- Important events (registration, expiry, updates)
- Registrar information

---

### threat

Multi-source threat intelligence lookup.

```bash
dnsscience threat <ip> [--format FORMAT]
```

**Arguments:**
- `ip` - IP address

**Returns:**
- Threat score (0-100)
- Results from multiple threat feeds
- Geolocation
- ASN information
- Reputation data

**Threat Feeds:**
- AbuseIPDB
- SpamHaus
- URLhaus
- Emerging Threats
- Custom feeds

---

### trace

Network path traceroute with geolocation.

```bash
dnsscience trace <target> [--max-hops HOPS] [--format FORMAT]
```

**Arguments:**
- `target` - Domain or IP address

**Options:**
- `--max-hops`, `-m` - Maximum hops (default: 30)
- `--format`, `-f` - Output format

**Returns:**
- Hop-by-hop path
- IP and hostname for each hop
- Latency measurements
- Geographic location of each hop
- ISP/organization information

---

### batch

Process multiple domains with parallel checks.

```bash
dnsscience batch <file> [OPTIONS]
```

**Arguments:**
- `file` - Text file with one domain per line

**Options:**
- `--checks`, `-c` - Checks to perform (default: `email,ssl,rdap`)
  - Available: `email`, `ssl`, `rdap`, `threat`, `value`
- `--output`, `-o` - Output file path
- `--format`, `-f` - Output format: `json` or `csv`

**Example:**
```bash
dnsscience batch domains.txt \
  --checks email,ssl,threat \
  --output results.json \
  --format json
```

---

### config

Configure CLI settings.

```bash
dnsscience config [OPTIONS]
```

**Options:**
- `--api-key` - Set API authentication key
- `--api-url` - Set API endpoint URL
- `--format` - Set default output format
- `--show` - Display current configuration

**Examples:**
```bash
# Set API key
dnsscience config --api-key sk_live_xxxxxxxxxxxxx

# Set custom instance
dnsscience config --api-url https://dns.company.com

# View config
dnsscience config --show
```

## Examples

### Example 1: Complete Domain Audit

```bash
#!/bin/bash
DOMAIN="example.com"

echo "Email Security:"
dnsscience email $DOMAIN

echo -e "\nSSL Certificate:"
dnsscience ssl $DOMAIN

echo -e "\nRDAP Info:"
dnsscience rdap $DOMAIN

echo -e "\nDomain Value:"
dnsscience value $DOMAIN
```

### Example 2: Batch Email Security Audit

```bash
# Create list of company domains
cat > company_domains.txt <<EOF
company.com
mail.company.com
shop.company.com
blog.company.com
EOF

# Run email security check on all
dnsscience batch company_domains.txt \
  --checks email \
  --output email_audit.json \
  --format json
```

### Example 3: Monitor Multiple IPs for Threats

```bash
# Create IP list
cat > ips.txt <<EOF
1.2.3.4
5.6.7.8
9.10.11.12
EOF

# Check threat intel
dnsscience batch ips.txt \
  --checks threat \
  --output threat_report.csv \
  --format csv
```

### Example 4: Export to JSON for Further Processing

```bash
dnsscience email example.com --format json | jq '.dmarc.policy'
```

## Integration with Other Tools

### Pipe to jq for JSON processing

```bash
dnsscience email example.com -f json | jq '.security_score'
```

### Pipe to grep for filtering

```bash
dnsscience trace example.com | grep -i "ashburn"
```

### Integration in shell scripts

```bash
#!/bin/bash
SCORE=$(dnsscience email $1 -f json | jq '.security_score')

if [ $SCORE -lt 70 ]; then
    echo "Warning: Low security score for $1"
    # Send alert
fi
```

## Troubleshooting

### API Connection Issues

```bash
# Test API connectivity
dnsscience config --show

# Try with explicit API URL
dnsscience config --api-url https://dnsscience.io
dnsscience autodetect
```

### Rate Limiting

The CLI respects API rate limits. If you hit limits:

1. Use `--api-key` with an authenticated account for higher limits
2. Add delays between batch requests
3. Use caching when possible

### Certificate Errors

If you encounter SSL certificate verification errors:

```bash
# Use custom CA bundle (if needed)
export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.crt
dnsscience email example.com
```

## API Key Benefits

Free tier: 100 requests/day
With API key:
- 10,000 requests/day
- Priority processing
- Advanced features
- Historical data access

Get your API key at: https://dnsscience.io/account/api

## Support

- Documentation: https://dnsscience.io/docs
- GitHub: https://github.com/dnsscience/cli
- Issues: https://github.com/dnsscience/cli/issues
- Email: support@dnsscience.io

## License

MIT License - See LICENSE file for details

## Version

Current Version: 1.0.0

Last Updated: 2025-11-15
