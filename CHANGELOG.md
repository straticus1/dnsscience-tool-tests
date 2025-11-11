# Changelog

All notable changes to DNSScience Utility will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2025-11-10

### Added - Major Feature Release

#### LDNS-Equivalent Features
- **NSEC/NSEC3 Zone Walking**: Complete `ldns-walk` equivalent for zone enumeration
  - Walk NSEC chains to discover all records in a signed zone
  - NSEC3 analysis with hash collection and parameter detection
  - Safety limits and intelligent chain following
  
- **DANE/TLSA Validation**: Full `ldns-dane` equivalent
  - Validate TLS certificates against TLSA DNS records
  - Support for all TLSA usage, selector, and matching types
  - Certificate retrieval and validation
  - SMTP, HTTPS, and custom port validation

- **EDNS Capability Testing**: `ldns-test-edns` equivalent
  - Comprehensive EDNS0 support detection
  - DNSSEC OK bit testing
  - NSID (Name Server Identifier) support
  - TCP fallback capability testing
  - Maximum UDP payload detection

- **RRSIG Expiration Analysis**: `ldns-rrsig` equivalent
  - Analyze all RRSIG records for a domain
  - Expiration warnings (critical, urgent, warning levels)
  - Signature validity checking
  - Multi-record type analysis (A, AAAA, MX, NS, DNSKEY)

- **Dynamic DNS Updates**: RFC 2136 `ldns-update` equivalent
  - Send DNS UPDATE messages
  - TSIG authentication support
  - Add, delete, and replace operations
  - Response code validation

#### Security Features
- **DNS Hijacking Detection**: Multi-resolver comparison for suspicious patterns
- **Cache Poisoning Assessment**: DNSSEC configuration and vulnerability analysis
- **Anomaly Detection**: TTL inconsistencies and response pattern analysis
- **Security Scoring**: 100-point security score with specific recommendations

#### DNSScience.io Platform Integration
- **API Client**: Full integration with DNSScience.io platform API
  - Secure API key management (stored in ~/.dnsscience/config.json)
  - Domain security scanning (DNSSEC, SPF, DKIM, DMARC, MTA-STS, SSL)
  - Domain information retrieval
  - Historical scan data access
  - Domain tracking and search
  - Connection testing and authentication
  - Commands: `--api-scan`, `--api-info`, `--api-history`, `--api-list`, `--api-search`
  - Key management: `--api-add-key`, `--api-show-key`, `--api-remove-key`, `--api-test`

#### Global Testing
- **Global Resolver Testing**: Test domains across 258+ worldwide resolvers
  - Geographic filtering (region, country)
  - Consistency score calculation
  - Response time metrics
  - Propagation lag detection

#### Encrypted DNS
- **DNS over HTTPS (DoH)**: Full RFC 8484 support
  - POST and GET methods
  - Multiple provider support
  - Custom URL support

- **DNS over TLS (DoT)**: RFC 7858 support
  - TLS 1.2+ with certificate validation
  - SNI support
  - Custom port support

#### Infrastructure
- **Comprehensive Logging**: Multi-level logging with file and console output
- **Configuration Files**: JSON and YAML configuration support
- **Multiple Output Formats**: dig-style, JSON, YAML, short format
- **Enhanced CLI**: dig-compatible syntax with extended options
- **Type Hints**: Full type annotation throughout codebase
- **Error Handling**: Comprehensive exception handling with detailed messages

### Changed
- Complete architectural redesign with modular class structure
- Improved performance with parallel processing
- Enhanced DNSSEC validation with full chain checking
- Better error messages and user feedback
- Optimized memory usage for large-scale testing

### Improved
- Documentation: Comprehensive README, architecture guide, examples
- Code quality: 100% type hints, extensive comments
- Testing: Better test coverage and validation
- Performance: Parallel queries, connection pooling
- Usability: Intuitive CLI, helpful error messages

## [2.0.0] - Previous Version

### Features
- Basic DNS query functionality (dig-style)
- DNSSEC validation
- Zone transfers (AXFR/IXFR)
- DNS tracing
- CHAOS class queries
- Multiple output formats
- Color-coded output

## [1.0.0] - Initial Release

### Features
- Basic DNS queries
- Multiple record types
- Nameserver selection
- Simple output formatting

---

## Version History Summary

| Version | Date | Major Changes |
|---------|------|---------------|
| 3.0.0 | 2025-11-10 | Complete rewrite with LDNS features, security analysis, global testing |
| 2.0.0 | Previous | Enhanced dig functionality with DNSSEC |
| 1.0.0 | Initial | Basic DNS query tool |

## Migration Guide

### From 2.x to 3.0

**New Features Available:**
```bash
# NSEC/NSEC3 zone walking
dnsscience-util.py --nsec-walk example.com @ns1.example.com
dnsscience-util.py --nsec3-analyze example.com @ns1.example.com

# DANE/TLSA validation
dnsscience-util.py --dane-validate mail.example.com 25

# Security analysis
dnsscience-util.py --security-analyze example.com

# Global testing
dnsscience-util.py --global-test example.com

# EDNS testing
dnsscience-util.py --edns-test 8.8.8.8

# RRSIG analysis
dnsscience-util.py --rrsig-analyze example.com
```

**Breaking Changes:**
- None - All 2.x functionality preserved with backward compatibility

**New Dependencies:**
- PyYAML (for YAML config support)
- requests (for DoH support)
- Additional dnspython features

## Roadmap

### Planned for 3.1.0
- Batch query support from file
- Historical trending and comparison
- Webhook notifications
- API server mode
- Graphical heatmaps

### Planned for 3.2.0
- DNSSEC key management tools
- Zone comparison utilities
- DNS packet capture analysis
- Performance benchmarking suite

### Planned for 4.0.0
- Web UI dashboard
- Real-time monitoring
- Alert management
- Database integration for historical data

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Reporting bugs
- Suggesting features
- Submitting pull requests
- Code style and standards

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/dnsscience/dnsscience-util/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dnsscience/dnsscience-util/discussions)

