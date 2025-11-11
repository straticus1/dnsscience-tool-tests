# DNSScience Utility

**The World's Most Advanced DNS Analysis, Security, Testing, and Debugging Tool**

[![Version](https://img.shields.io/badge/version-3.1.0-blue.svg)](https://github.com/dnsscience/dnsscience-util)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

DNSScience Utility combines the power of `dig`, `ldns`, and advanced DNS security analysis into a single, comprehensive command-line tool. Whether you're troubleshooting DNS issues, auditing DNSSEC configurations, testing global DNS propagation, or performing security analysis, dnsscience-util has you covered.

## Key Features

### Core DNS Operations
- **All dig Features**: Query any record type, trace delegation paths, DNSSEC validation, zone transfers
- **All ldns Features**: Zone walking, DANE validation, EDNS testing, RRSIG analysis
- **Multiple Output Formats**: Text (dig-style), JSON, YAML, short format
- **Encrypted DNS**: DoH (DNS over HTTPS) and DoT (DNS over TLS) support

### DNSScience.io Platform Integration
- **Cloud-Based Scanning**: Comprehensive domain security scans via DNSScience.io API
- **Domain Enrichment**: Complete domain intelligence with DNS, WHOIS, security, and reputation data
- **RDAP/WHOIS Lookup**: Modern registration data access
- **Web3 Domain Support**: Blockchain domain resolution (.eth, .crypto, ENS)
- **Multi-Protocol Validation**: DNSSEC, SPF, DKIM, DMARC, MTA-STS, STARTTLS, SSL certificates
- **Domain Tracking**: Monitor multiple domains with historical trend analysis
- **Secure Key Management**: API keys stored with restrictive permissions
- **Enterprise Features**: Advanced scanning, webhooks, bulk operations, SLA guarantees

### Advanced Analysis
- **Global Resolver Testing**: Test domains across 258+ DNS resolvers worldwide
- **DNSSEC Analysis**: Complete chain validation, RRSIG expiration warnings, key analysis
- **Zone Walking**: NSEC and NSEC3 chain enumeration for security testing
- **DANE/TLSA Validation**: Certificate pinning validation via DNS

### Security Features
- **DNS Hijacking Detection**: Identify suspicious resolver behavior
- **Cache Poisoning Assessment**: Evaluate vulnerability to cache poisoning attacks
- **Anomaly Detection**: Detect inconsistencies in DNS responses
- **Security Scoring**: Comprehensive security analysis with recommendations

### Testing & Debugging
- **EDNS Capability Testing**: Comprehensive EDNS support validation
- **Response Time Analysis**: Global performance metrics and heatmaps
- **Resolver Fingerprinting**: Identify DNS server software and versions
- **Dynamic Updates**: RFC 2136 DNS UPDATE support with TSIG

## Installation

### Requirements
- Python 3.8 or higher
- pip (Python package manager)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Quick Start

```bash
# Make executable
chmod +x dnsscience-util.py

# Basic query
./dnsscience-util.py example.com

# Query with specific nameserver
./dnsscience-util.py example.com @8.8.8.8

# DNSSEC validation
./dnsscience-util.py example.com +dnssec

# Global testing across 258+ resolvers
./dnsscience-util.py --global-test example.com

# Security analysis
./dnsscience-util.py --security-analyze example.com
```

## Usage Examples

### Basic DNS Queries

```bash
# A record query
./dnsscience-util.py example.com

# MX records
./dnsscience-util.py example.com MX

# Query specific nameserver
./dnsscience-util.py example.com @1.1.1.1

# Multiple record types
./dnsscience-util.py example.com TXT
./dnsscience-util.py _dmarc.example.com TXT

# Reverse lookup
./dnsscience-util.py -x 8.8.8.8
```

### DNSSEC Analysis

```bash
# Request DNSSEC records
./dnsscience-util.py example.com +dnssec

# Validate DNSSEC chain
./dnsscience-util.py --validate example.com

# Analyze RRSIG expiration
./dnsscience-util.py --rrsig-analyze example.com

# Check DNSSEC with JSON output
./dnsscience-util.py example.com DNSKEY +json
```

### Zone Operations

```bash
# Trace delegation path
./dnsscience-util.py --trace example.com

# Zone transfer (AXFR)
./dnsscience-util.py --axfr example.com @ns1.example.com

# NSEC zone walking
./dnsscience-util.py --nsec-walk example.com @ns1.example.com

# NSEC3 analysis
./dnsscience-util.py --nsec3-analyze example.com @ns1.example.com
```

### Security Testing

```bash
# Comprehensive security analysis
./dnsscience-util.py --security-analyze example.com

# DANE/TLSA validation for SMTP
./dnsscience-util.py --dane-validate mail.example.com 25

# DANE/TLSA validation for HTTPS
./dnsscience-util.py --dane-validate www.example.com 443

# EDNS capability testing
./dnsscience-util.py --edns-test 8.8.8.8
```

### Global Resolver Testing

```bash
# Test across all global resolvers
./dnsscience-util.py --global-test example.com

# Test specific region
./dnsscience-util.py --global-test example.com --region europe

# Test specific country
./dnsscience-util.py --global-test example.com --country US

# Test with MX records
./dnsscience-util.py --global-test example.com MX
```

### Encrypted DNS

```bash
# DNS over HTTPS (DoH)
./dnsscience-util.py --doh https://cloudflare-dns.com/dns-query example.com

# DNS over TLS (DoT)
./dnsscience-util.py --dot 1.1.1.1 cloudflare-dns.com example.com

# DoH with Google DNS
./dnsscience-util.py --doh https://dns.google/dns-query example.com
```

### Output Formats

```bash
# JSON output
./dnsscience-util.py example.com +json

# YAML output
./dnsscience-util.py example.com +yaml

# Short format (answers only)
./dnsscience-util.py example.com +short

# Save to file
./dnsscience-util.py example.com --output-file result.txt
```

### DNSScience.io Platform API

```bash
# Add your API key (one-time setup)
./dnsscience-util.py --api-add-key dns_live_YOUR_API_KEY

# Test API connection
./dnsscience-util.py --api-test

# Show current API key (masked)
./dnsscience-util.py --api-show-key

# Comprehensive domain security scan
./dnsscience-util.py --api-scan example.com

# Get domain information
./dnsscience-util.py --api-info example.com

# Get domain scan history
./dnsscience-util.py --api-history example.com

# List all tracked domains
./dnsscience-util.py --api-list

# Search domains
./dnsscience-util.py --api-search "example"

# Complete domain enrichment (comprehensive intelligence)
./dnsscience-util.py --enrich example.com
./dnsscience-util.py --enrichment example.com --json

# RDAP/WHOIS lookup (modern registration data)
./dnsscience-util.py --rdap example.com
./dnsscience-util.py --whois example.com

# Web3 domain lookup (blockchain domains)
./dnsscience-util.py --web3 vitalik.eth
./dnsscience-util.py --web3 example.crypto

# Remove API key
./dnsscience-util.py --api-remove-key
```

### Advanced Options

```bash
# TCP instead of UDP
./dnsscience-util.py example.com +tcp

# Custom timeout
./dnsscience-util.py example.com +timeout=10

# Disable colors
./dnsscience-util.py example.com +nocolor

# Enable logging
./dnsscience-util.py --log-file dns.log --log-level DEBUG example.com

# Use configuration file
./dnsscience-util.py --config myconfig.yaml example.com
```

## Feature Comparison

| Feature | dig | ldns | dnsscience-util |
|---------|-----|------|-----------------|
| Basic DNS queries | ✅ | ✅ | ✅ |
| DNSSEC queries | ✅ | ✅ | ✅ |
| Trace mode | ✅ | ✅ | ✅ |
| Zone transfers | ✅ | ✅ | ✅ |
| NSEC/NSEC3 walking | ❌ | ✅ | ✅ |
| DANE/TLSA validation | ❌ | ✅ | ✅ |
| EDNS testing | ⚠️ | ✅ | ✅ |
| RRSIG analysis | ❌ | ✅ | ✅ |
| Global resolver testing | ❌ | ❌ | ✅ |
| Security analysis | ❌ | ❌ | ✅ |
| DoH/DoT support | ❌ | ❌ | ✅ |
| DNS hijacking detection | ❌ | ❌ | ✅ |
| Anomaly detection | ❌ | ❌ | ✅ |
| JSON/YAML output | ⚠️ | ❌ | ✅ |
| Configuration files | ❌ | ❌ | ✅ |
| Comprehensive logging | ❌ | ❌ | ✅ |
| DNSScience.io API | ❌ | ❌ | ✅ |
| Cloud-based scanning | ❌ | ❌ | ✅ |

## Architecture

DNSScience Utility is built with a modular architecture:

```
dnsscience-util.py
├── Core DNS Engine
│   ├── DNSQuery (basic queries)
│   ├── DNSTracer (delegation tracing)
│   └── ZoneTransfer (AXFR/IXFR)
├── LDNS Features
│   ├── NSECWalker (zone walking)
│   ├── DANEValidator (TLSA validation)
│   ├── EDNSTester (capability testing)
│   ├── RRSIGAnalyzer (signature analysis)
│   └── DNSUpdateManager (RFC 2136)
├── Security Analysis
│   ├── DNSSecurityAnalyzer (comprehensive)
│   ├── Hijacking detection
│   ├── Cache poisoning assessment
│   └── Anomaly detection
├── Global Testing
│   └── GlobalResolverTester (258+ resolvers)
├── Encrypted DNS
│   ├── DoHResolver (DNS over HTTPS)
│   └── DoTResolver (DNS over TLS)
└── Infrastructure
    ├── Logger (multi-level logging)
    ├── Config (file-based configuration)
    └── OutputFormatter (multiple formats)
```

For detailed architecture documentation, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security Features

DNSScience Utility includes comprehensive security analysis capabilities:

### DNS Hijacking Detection
- Compares responses from multiple resolvers
- Identifies suspicious patterns
- Detects resolver-level manipulation

### Cache Poisoning Assessment
- Evaluates DNSSEC configuration
- Checks for security vulnerabilities
- Provides risk scoring

### Anomaly Detection
- TTL inconsistencies
- Response pattern analysis
- Geographic anomalies

### Security Scoring
- 100-point security score
- Specific recommendations
- Compliance checking

For more details, see [docs/SECURITY-FEATURES.md](docs/SECURITY-FEATURES.md).

## Global Resolver Testing

Test your domain across 258+ DNS resolvers worldwide:

- **Geographic Coverage**: 7 regions, 150+ countries
- **Provider Diversity**: Public resolvers, ISPs, enterprises
- **Performance Metrics**: Response times, availability, consistency
- **Propagation Analysis**: Detect stale caches and propagation delays

### Supported Regions
- North America
- South America
- Europe
- Asia
- Middle East
- Africa
- Oceania
- Russia/CIS

## Configuration

Create a configuration file (JSON or YAML) for custom defaults:

```yaml
# config.yaml
timeout: 5
retries: 2
max_workers: 50
log_level: INFO
output_format: text
color: true
resolvers_file: dns_resolvers.json
default_nameserver: 8.8.8.8
```

Use with:
```bash
./dnsscience-util.py --config config.yaml example.com
```

## Logging

Comprehensive logging for debugging and auditing:

```bash
# Log to file
./dnsscience-util.py --log-file dns.log example.com

# Set log level
./dnsscience-util.py --log-level DEBUG --log-file debug.log example.com

# Available log levels: DEBUG, INFO, WARNING, ERROR
```

## Output Formats

### Text (dig-style)
```
; <<>> DNSScience Utility v3.0.0 <<>> example.com A
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;example.com.                  IN    A

;; ANSWER SECTION:
example.com.          86400   IN    A     93.184.216.34
```

### JSON
```json
{
  "query": {
    "name": "example.com",
    "type": "A"
  },
  "status": "NOERROR",
  "answer": [
    {
      "name": "example.com.",
      "ttl": 86400,
      "type": "A",
      "data": "93.184.216.34"
    }
  ]
}
```

### YAML
```yaml
query:
  name: example.com
  type: A
status: NOERROR
answer:
- name: example.com.
  ttl: 86400
  type: A
  data: 93.184.216.34
```

### Short Format
```
93.184.216.34
```

## Performance

DNSScience Utility is optimized for performance:

- **Parallel Processing**: Concurrent queries across multiple resolvers
- **Connection Pooling**: Efficient resource management
- **Rate Limiting**: Configurable query rate limiting
- **Caching**: Intelligent caching for repeated queries
- **Timeout Management**: Customizable timeouts per operation

## Troubleshooting

### Common Issues

**Import errors**
```bash
pip install -r requirements.txt
```

**Permission denied**
```bash
chmod +x dnsscience-util.py
```

**Timeout errors**
```bash
# Increase timeout
./dnsscience-util.py example.com +timeout=10
```

**No resolvers loaded for global testing**
```bash
# Ensure dns_resolvers.json exists in the same directory
# Or specify custom path
./dnsscience-util.py --config myconfig.yaml --global-test example.com
```

## Contributing

Contributions are welcome! Please see our contributing guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/dnsscience/dnsscience-util.git
cd dnsscience-util

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/

# Run linter
pylint dnsscience-util.py
```

## Documentation

- [Architecture Guide](docs/ARCHITECTURE.md) - Technical architecture and design
- [Security Features](docs/SECURITY-FEATURES.md) - Security analysis capabilities
- [DNSScience.io API](docs/DNSSCIENCE-API.md) - Platform API integration guide
- [API Reference](docs/API-REFERENCE.md) - Programming API documentation
- [Examples](docs/EXAMPLES.md) - Real-world usage scenarios
- [LDNS Comparison](docs/LDNS-VS-DIG-COMPARISON.md) - Feature comparison
- [Changelog](CHANGELOG.md) - Version history and changes

## Comparison with Other Tools

### vs dig
- dig is great for basic queries
- dnsscience-util adds LDNS features, security analysis, global testing
- Better output formats (JSON, YAML)
- Built-in security features

### vs ldns
- ldns provides zone signing and key management (operational features)
- dnsscience-util focuses on analysis and testing
- Easier to use with comprehensive CLI
- Global resolver testing and security analysis

### vs doggo/dog
- Modern alternatives to dig
- dnsscience-util provides more comprehensive feature set
- Enterprise-grade security analysis
- Global propagation testing

## Use Cases

### DNS Administrator
- Validate DNSSEC configurations
- Monitor global DNS propagation
- Test resolver performance
- Audit zone configurations

### Security Researcher
- Test for DNS hijacking
- Validate DANE/TLSA records
- Perform zone enumeration
- Assess cache poisoning risks

### DevOps Engineer
- Automate DNS testing in CI/CD
- Monitor DNS health
- Debug resolution issues
- Validate infrastructure changes

### Network Engineer
- Troubleshoot DNS problems
- Test EDNS compatibility
- Validate DNS infrastructure
- Perform capacity planning

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Credits

- **dnspython**: Core DNS library
- **requests**: HTTP library for DoH
- **PyYAML**: YAML parsing
- DNS community and standards (RFCs)

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/dnsscience/dnsscience-util/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dnsscience/dnsscience-util/discussions)

## Version

Current version: **3.1.0**

### What's New in 3.1.0
- **Domain Enrichment**: Complete domain intelligence via `--enrich`
- **RDAP Lookup**: Modern WHOIS replacement via `--rdap`
- **Web3 Domains**: Blockchain domain support via `--web3`

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

## Author

DNSScience Team

---

**Made with expertise in DNS, security, and network engineering.**
