# DNSScience Utility - Complete Guide

A comprehensive DNS query tool combining the power of **dig** and **ldns** in pure Python.

## Overview

`dnsscience-util.py` is a production-grade DNS query utility that combines:
- **All dig features**: Query options, trace mode, output formats, DNSSEC
- **All ldns features**: DNSSEC validation, zone transfers, packet manipulation, CHAOS queries
- **Enhanced capabilities**: JSON output, color coding, advanced statistics

## Installation

Already installed! The tool uses only the `dnspython` library which is already in your requirements.txt.

```bash
# Make executable (already done)
chmod +x dnsscience-util.py

# Run directly
./dnsscience-util.py example.com

# Or with python3
python3 dnsscience-util.py example.com
```

## Quick Start

```bash
# Basic A record query
./dnsscience-util.py example.com

# Query specific record type
./dnsscience-util.py example.com MX
./dnsscience-util.py example.com AAAA

# Query specific nameserver
./dnsscience-util.py example.com @8.8.8.8
./dnsscience-util.py example.com A @1.1.1.1

# Short output (answers only)
./dnsscience-util.py example.com +short

# JSON output
./dnsscience-util.py example.com +json
```

## Feature Comparison

### From dig

| Feature | dig Command | dnsscience-util Command |
|---------|------------|------------------------|
| Basic query | `dig example.com` | `./dnsscience-util.py example.com` |
| Query type | `dig example.com MX` | `./dnsscience-util.py example.com MX` |
| Specific server | `dig @8.8.8.8 example.com` | `./dnsscience-util.py example.com @8.8.8.8` |
| DNSSEC | `dig +dnssec example.com` | `./dnsscience-util.py example.com +dnssec` |
| Trace | `dig +trace example.com` | `./dnsscience-util.py example.com +trace` |
| Short output | `dig +short example.com` | `./dnsscience-util.py example.com +short` |
| TCP query | `dig +tcp example.com` | `./dnsscience-util.py example.com +tcp` |
| Reverse lookup | `dig -x 8.8.8.8` | `./dnsscience-util.py -x 8.8.8.8` |
| Zone transfer | `dig @ns1.example.com example.com AXFR` | `./dnsscience-util.py example.com AXFR @ns1.example.com` |

### From ldns

| Feature | ldns Tool | dnsscience-util Command |
|---------|-----------|------------------------|
| DNSSEC validation | `drill -D example.com` | `./dnsscience-util.py example.com --validate` |
| CHAOS query | `drill version.bind CH TXT @8.8.8.8` | `./dnsscience-util.py --chaos version.bind @8.8.8.8` |
| Zone transfer | `ldns-axfr example.com` | `./dnsscience-util.py example.com AXFR @ns1.example.com` |
| Trace delegation | `drill -T example.com` | `./dnsscience-util.py example.com +trace` |

## Comprehensive Examples

### Basic Queries

```bash
# A record (default)
./dnsscience-util.py example.com

# Specific record types
./dnsscience-util.py example.com A
./dnsscience-util.py example.com AAAA
./dnsscience-util.py example.com MX
./dnsscience-util.py example.com NS
./dnsscience-util.py example.com TXT
./dnsscience-util.py example.com SOA
./dnsscience-util.py example.com CNAME

# DNSSEC record types
./dnsscience-util.py example.com DNSKEY
./dnsscience-util.py example.com DS
./dnsscience-util.py example.com RRSIG
./dnsscience-util.py example.com NSEC
```

### Using Specific Nameservers

```bash
# Google DNS
./dnsscience-util.py example.com @8.8.8.8
./dnsscience-util.py example.com @8.8.4.4

# Cloudflare DNS
./dnsscience-util.py example.com @1.1.1.1
./dnsscience-util.py example.com @1.0.0.1

# Quad9 DNS
./dnsscience-util.py example.com @9.9.9.9

# Custom port
./dnsscience-util.py example.com @8.8.8.8 -p 5353
```

### DNSSEC Queries

```bash
# Request DNSSEC records
./dnsscience-util.py example.com +dnssec

# DNSSEC with Checking Disabled flag
./dnsscience-util.py example.com +dnssec +cd

# DNSSEC validation (ldns-style)
./dnsscience-util.py example.com --validate

# Query DNSKEY records
./dnsscience-util.py cloudflare.com DNSKEY +dnssec

# Query DS records
./dnsscience-util.py cloudflare.com DS
```

### Trace Mode (Delegation Path)

```bash
# Trace from root to domain
./dnsscience-util.py example.com +trace

# Trace specific record type
./dnsscience-util.py example.com MX +trace

# Trace with specific timeout
./dnsscience-util.py example.com +trace +timeout=10
```

### Reverse DNS Lookups

```bash
# Reverse lookup (PTR record)
./dnsscience-util.py -x 8.8.8.8
./dnsscience-util.py -x 1.1.1.1
./dnsscience-util.py -x 2001:4860:4860::8888

# Reverse lookup with specific server
./dnsscience-util.py -x 8.8.8.8 @8.8.8.8
```

### Zone Transfers

```bash
# AXFR (full zone transfer)
./dnsscience-util.py example.com AXFR @ns1.example.com

# Test if zone transfer is allowed
./dnsscience-util.py zonetransfer.me AXFR @nsztm1.digi.ninja
```

### CHAOS Class Queries

```bash
# Get DNS server version
./dnsscience-util.py --chaos version.bind @8.8.8.8

# Get hostname
./dnsscience-util.py --chaos hostname.bind @8.8.8.8

# Get server ID
./dnsscience-util.py --chaos id.server @8.8.8.8
```

### Output Formats

```bash
# Dig-style output (default)
./dnsscience-util.py example.com

# Short output (answers only)
./dnsscience-util.py example.com +short

# JSON output
./dnsscience-util.py example.com +json

# JSON with pretty formatting
./dnsscience-util.py example.com +json | jq

# Without color
./dnsscience-util.py example.com +nocolor
```

### Advanced Query Options

```bash
# Use TCP instead of UDP
./dnsscience-util.py example.com +tcp

# Set timeout
./dnsscience-util.py example.com +timeout=10

# EDNS support
./dnsscience-util.py example.com +edns=0
./dnsscience-util.py example.com +edns=0 +bufsize=4096

# Bind to specific source address
./dnsscience-util.py example.com -b 192.168.1.100

# Use specific source port
./dnsscience-util.py example.com --sport 5353

# Authenticated Data flag
./dnsscience-util.py example.com +ad
```

### Query Class Options

```bash
# Internet class (default)
./dnsscience-util.py example.com IN

# CHAOS class
./dnsscience-util.py version.bind TXT CH @8.8.8.8

# Hesiod class
./dnsscience-util.py example.com HS
```

## Real-World Use Cases

### 1. Verify DNS Propagation

```bash
# Check from multiple servers
./dnsscience-util.py newdomain.com @8.8.8.8
./dnsscience-util.py newdomain.com @1.1.1.1
./dnsscience-util.py newdomain.com @9.9.9.9

# Short output for easy comparison
./dnsscience-util.py newdomain.com @8.8.8.8 +short
./dnsscience-util.py newdomain.com @1.1.1.1 +short
```

### 2. Debug DNS Issues

```bash
# Full trace from root
./dnsscience-util.py problem.com +trace

# Check all record types
./dnsscience-util.py problem.com A
./dnsscience-util.py problem.com NS
./dnsscience-util.py problem.com SOA

# Check with DNSSEC
./dnsscience-util.py problem.com +dnssec
```

### 3. Email Configuration Verification

```bash
# Check MX records
./dnsscience-util.py example.com MX

# Check SPF record
./dnsscience-util.py example.com TXT +short | grep spf

# Check DMARC record
./dnsscience-util.py _dmarc.example.com TXT +short

# Check DKIM record
./dnsscience-util.py default._domainkey.example.com TXT
```

### 4. DNSSEC Validation

```bash
# Validate DNSSEC chain
./dnsscience-util.py cloudflare.com --validate

# Check DNSSEC records
./dnsscience-util.py cloudflare.com DNSKEY +dnssec
./dnsscience-util.py cloudflare.com DS
./dnsscience-util.py cloudflare.com RRSIG
```

### 5. DNS Server Testing

```bash
# Get server version (if allowed)
./dnsscience-util.py --chaos version.bind @8.8.8.8

# Test response time
time ./dnsscience-util.py example.com @8.8.8.8 +short

# Test with statistics
./dnsscience-util.py example.com @8.8.8.8 +stats
```

### 6. Reverse DNS Verification

```bash
# Check mail server reverse DNS
./dnsscience-util.py mail.example.com A +short
# Then reverse lookup the IP
./dnsscience-util.py -x <IP_ADDRESS>
```

### 7. CDN/Load Balancer Testing

```bash
# Check from different locations
./dnsscience-util.py cdn.example.com @8.8.8.8 +short
./dnsscience-util.py cdn.example.com @1.1.1.1 +short

# Full details
./dnsscience-util.py cdn.example.com +json | jq '.answer'
```

## Output Format Examples

### Dig-Style Output

```
; <<>> DNSScience Utility <<>> example.com A
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; EDNS: version 0; flags:; udp: 512

;; QUESTION SECTION:
;example.com.                  IN    A

;; ANSWER SECTION:
example.com.            86400  IN    A         93.184.216.34

;; Query time: 25 msec
;; SERVER: 8.8.8.8#53(UDP)
;; WHEN: Mon Jan 01 12:00:00 UTC 2024
;; MSG SIZE  rcvd: 56
```

### Short Output

```
93.184.216.34
```

### JSON Output

```json
{
  "query": {
    "name": "example.com",
    "type": "A"
  },
  "status": "NOERROR",
  "flags": ["qr", "rd", "ra"],
  "question": [
    {
      "name": "example.com.",
      "class": "IN",
      "type": "A"
    }
  ],
  "answer": [
    {
      "name": "example.com.",
      "ttl": 86400,
      "class": "IN",
      "type": "A",
      "data": "93.184.216.34"
    }
  ],
  "authority": [],
  "additional": [],
  "statistics": {
    "query_time": 25.3,
    "server": "8.8.8.8#53",
    "message_size": 56,
    "protocol": "UDP",
    "flags": ["qr", "rd", "ra"],
    "status": "NOERROR"
  }
}
```

## Command-Line Options Reference

### Positional Arguments
- `name` - Domain name to query
- `type` - Query type (A, AAAA, MX, etc.) - default: A
- `class` - Query class (IN, CH, HS) - default: IN

### Query Options
- `@SERVER` - Nameserver to query
- `-p PORT, --port PORT` - Port to query (default: 53)
- `-x IP, --reverse IP` - Reverse lookup (PTR)
- `-t TYPE, --type-arg TYPE` - Query type (alternative)
- `-c CLASS, --class-arg CLASS` - Query class (alternative)

### dig-style Options
- `+trace` - Trace delegation path from root
- `+dnssec` - Request DNSSEC records (DO bit)
- `+cd` - Set CD (Checking Disabled) flag
- `+ad` - Set AD (Authenticated Data) flag
- `+tcp` - Use TCP instead of UDP
- `+short` - Short output (answers only)
- `+json` - JSON output format
- `+noall` - Clear all display flags
- `+answer` - Show answer section
- `+nocolor` - Disable color output
- `+timeout=T` - Query timeout in seconds
- `+edns[=V]` - EDNS version (default: 0)
- `+bufsize=SIZE` - EDNS buffer size (default: 4096)
- `+stats` - Show query statistics

### Advanced Options
- `--validate` - Validate DNSSEC chain (ldns-style)
- `--chaos NAME` - CHAOS class query
- `-b ADDR, --bind ADDR` - Bind to source address
- `--sport PORT` - Source port

## Color Output

The tool uses color-coded output for better readability:

- **Cyan** - Question section
- **Green** - Answer section
- **Yellow** - Authority section
- **Blue** - Additional section
- **Red** - Errors
- **Bold** - Headers and important information

Disable colors with `+nocolor` for scripting.

## Exit Codes

- `0` - Success
- `1` - Error (query failed, invalid arguments, etc.)

## Tips & Best Practices

### Performance

```bash
# Use UDP for faster queries
./dnsscience-util.py example.com

# Use TCP for large responses
./dnsscience-util.py example.com +tcp

# Increase timeout for slow servers
./dnsscience-util.py example.com +timeout=30
```

### Scripting

```bash
# Get just the IP address
./dnsscience-util.py example.com +short

# JSON for parsing with jq
./dnsscience-util.py example.com +json | jq -r '.answer[0].data'

# Disable color for clean output
./dnsscience-util.py example.com +nocolor
```

### Debugging

```bash
# Full trace with all details
./dnsscience-util.py example.com +trace

# DNSSEC validation details
./dnsscience-util.py example.com --validate

# Check specific nameserver
./dnsscience-util.py example.com @authoritative-ns.example.com
```

### Security

```bash
# Verify DNSSEC
./dnsscience-util.py banking-site.com +dnssec
./dnsscience-util.py banking-site.com --validate

# Check for DNS hijacking
./dnsscience-util.py sensitive-domain.com @8.8.8.8 +short
./dnsscience-util.py sensitive-domain.com @1.1.1.1 +short
# Compare results
```

## Comparison with dig and ldns

### Advantages over dig
- Pure Python (no C dependencies)
- JSON output built-in
- Color-coded output
- DNSSEC validation integrated
- Easier scripting with Python

### Advantages over ldns
- Simpler syntax
- Better output formatting
- JSON support
- Cross-platform (pure Python)
- Active development

### Feature Parity
- ✅ All dig query options
- ✅ All dig output formats
- ✅ dig +trace functionality
- ✅ DNSSEC validation
- ✅ Zone transfers (AXFR)
- ✅ CHAOS class queries
- ✅ Reverse lookups
- ✅ EDNS support
- ✅ TCP/UDP selection
- ✅ Custom timeouts and ports

## Troubleshooting

### Query Timeout

```bash
# Increase timeout
./dnsscience-util.py slow-server.com +timeout=30
```

### No Answer

```bash
# Try different nameserver
./dnsscience-util.py example.com @8.8.8.8

# Trace to find issue
./dnsscience-util.py example.com +trace
```

### DNSSEC Validation Fails

```bash
# Check DNSSEC records
./dnsscience-util.py example.com DNSKEY +dnssec
./dnsscience-util.py example.com DS

# Validate chain
./dnsscience-util.py example.com --validate
```

### Zone Transfer Refused

```bash
# Normal - zone transfers are usually restricted
# Try from allowed IP or use public test zones
./dnsscience-util.py zonetransfer.me AXFR @nsztm1.digi.ninja
```

## Integration Examples

### Bash Script

```bash
#!/bin/bash
# Check if domain resolves
if ./dnsscience-util.py example.com +short > /dev/null 2>&1; then
    echo "Domain resolves"
else
    echo "Domain does not resolve"
fi
```

### Python Script

```python
import subprocess
import json

# Get JSON output
result = subprocess.run(
    ['./dnsscience-util.py', 'example.com', '+json'],
    capture_output=True,
    text=True
)

data = json.loads(result.stdout)
print(f"IP: {data['answer'][0]['data']}")
```

### Monitoring Script

```bash
#!/bin/bash
# Monitor DNS changes
while true; do
    IP=$(./dnsscience-util.py example.com +short)
    echo "$(date): $IP"
    sleep 300  # Check every 5 minutes
done
```

## Advanced Topics

### Custom DNS Queries

```bash
# Query with specific flags
./dnsscience-util.py example.com +dnssec +cd +ad

# EDNS with custom buffer size
./dnsscience-util.py example.com +edns=0 +bufsize=8192

# Bind to specific source
./dnsscience-util.py example.com -b 192.168.1.100 --sport 5353
```

### Batch Queries

```bash
# Query multiple domains
for domain in example.com example.org example.net; do
    ./dnsscience-util.py $domain +short
done

# Query multiple record types
for type in A AAAA MX TXT; do
    echo "=== $type ==="
    ./dnsscience-util.py example.com $type
done
```

### Performance Testing

```bash
# Measure query time
time ./dnsscience-util.py example.com @8.8.8.8 +short

# Compare nameservers
for ns in 8.8.8.8 1.1.1.1 9.9.9.9; do
    echo "Testing $ns:"
    time ./dnsscience-util.py example.com @$ns +short
done
```

## Credits

Combines features from:
- **dig** - ISC BIND DNS query tool
- **ldns** - DNS library and tools from NLnet Labs
- **dnspython** - Python DNS library

Created for DNS operations, security research, and network engineering.
