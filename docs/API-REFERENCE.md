# DNSScience Utility - API Reference

## Overview

This document provides a reference for using DNSScience Utility's classes and functions programmatically in Python scripts.

## Core Classes

### DNSQuery

Basic DNS query engine with full control over query parameters.

```python
from dnsscience_util import DNSQuery

# Create query instance
query = DNSQuery(
    nameserver='8.8.8.8',
    port=53,
    timeout=5,
    use_tcp=False,
    use_edns=True,
    dnssec=True
)

# Perform query
response, stats = query.query('example.com', 'A', 'IN')
print(f"Query time: {stats['query_time']}ms")
```

**Parameters**:
- `nameserver` (str): Nameserver IP address
- `port` (int): Port number (default: 53)
- `timeout` (int): Query timeout in seconds
- `use_tcp` (bool): Use TCP instead of UDP
- `use_edns` (bool): Enable EDNS
- `dnssec` (bool): Request DNSSEC records

### NSECWalker

NSEC/NSEC3 zone walking for zone enumeration.

```python
from dnsscience_util import NSECWalker

walker = NSECWalker('ns1.example.com', timeout=5)

# Walk NSEC chain
records = walker.walk_nsec('example.com')
print(f"Found {len(records)} records")

# Analyze NSEC3
nsec3_data = walker.walk_nsec3('example.com')
print(nsec3_data)
```

### DANEValidator

DANE/TLSA certificate validation.

```python
from dnsscience_util import DANEValidator

validator = DANEValidator(timeout=5)
result = validator.validate_tlsa('mail.example.com', port=25, protocol='tcp')

if result['validation_status'] == 'VALID':
    print("DANE validation successful")
else:
    print(f"Errors: {result['errors']}")
```

### GlobalResolverTester

Test domains across global DNS resolvers.

```python
from dnsscience_util import GlobalResolverTester

tester = GlobalResolverTester(
    resolvers_file='dns_resolvers.json',
    timeout=5,
    max_workers=50
)

result = tester.test_domain('example.com', 'A')
print(f"Consistency: {result['consistency_score']}%")
print(f"Successful: {result['successful']}/{result['total_resolvers']}")
```

## LDNS Feature Classes

### EDNSTester
```python
from dnsscience_util import EDNSTester

tester = EDNSTester(timeout=5)
result = tester.test_resolver('8.8.8.8')
print(f"EDNS0: {result['edns0_support']}")
print(f"DNSSEC OK: {result['dnssec_ok']}")
```

### RRSIGAnalyzer
```python
from dnsscience_util import RRSIGAnalyzer

analyzer = RRSIGAnalyzer(timeout=5)
result = analyzer.analyze_rrsig('example.com')
for sig in result['signatures']:
    print(f"{sig['type_covered']}: expires in {sig['days_until_expiration']} days")
```

### DNSSecurityAnalyzer
```python
from dnsscience_util import DNSSecurityAnalyzer

analyzer = DNSSecurityAnalyzer(timeout=5)
resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
result = analyzer.analyze_domain('example.com', resolvers)
print(f"Security Score: {result['security_score']}/100")
```

## Encrypted DNS Classes

### DoHResolver
```python
from dnsscience_util import DoHResolver

resolver = DoHResolver('https://cloudflare-dns.com/dns-query', timeout=5)
result = resolver.query('example.com', 'A')
print(f"Answers: {result['answers']}")
```

### DoTResolver
```python
from dnsscience_util import DoTResolver

resolver = DoTResolver('1.1.1.1', 'cloudflare-dns.com', port=853, timeout=5)
result = resolver.query('example.com', 'A')
print(f"Response time: {result['response_time']}ms")
```

## Utility Classes

### Logger
```python
from dnsscience_util import Logger

logger = Logger(
    name='myapp',
    level='INFO',
    log_file='dns.log',
    console=True
)

logger.info("Starting DNS query")
logger.error("Query failed")
```

### Config
```python
from dnsscience_util import Config

config = Config(config_file='config.yaml')
timeout = config.get('timeout', default=5)
config.set('max_workers', 100)
```

### OutputFormatter
```python
from dnsscience_util import OutputFormatter

formatter = OutputFormatter(color=True, style='json')
output = formatter.format_response(response, stats, 'example.com', 'A')
print(output)
```

## Complete Example Script

```python
#!/usr/bin/env python3
"""
Example script using DNSScience Utility classes
"""

from dnsscience_util import (
    DNSQuery, 
    GlobalResolverTester,
    DNSSecurityAnalyzer,
    RRSIGAnalyzer,
    Logger
)

def main():
    # Initialize logger
    logger = Logger('dns-analysis', 'INFO', log_file='analysis.log')
    
    domain = 'example.com'
    logger.info(f"Analyzing {domain}")
    
    # Basic query
    query = DNSQuery(timeout=5, dnssec=True, logger=logger)
    try:
        response, stats = query.query(domain, 'A')
        logger.info(f"Query successful: {stats['query_time']}ms")
    except Exception as e:
        logger.error(f"Query failed: {e}")
        return 1
    
    # Global testing
    logger.info("Starting global resolver test")
    tester = GlobalResolverTester(timeout=5, logger=logger)
    global_result = tester.test_domain(domain, 'A')
    logger.info(f"Global consistency: {global_result['consistency_score']}%")
    
    # Security analysis
    logger.info("Running security analysis")
    analyzer = DNSSecurityAnalyzer(timeout=5, logger=logger)
    test_resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    security_result = analyzer.analyze_domain(domain, test_resolvers)
    logger.info(f"Security score: {security_result['security_score']}/100")
    
    # RRSIG analysis
    logger.info("Analyzing RRSIG records")
    rrsig_analyzer = RRSIGAnalyzer(timeout=5, logger=logger)
    rrsig_result = rrsig_analyzer.analyze_rrsig(domain)
    logger.info(f"Found {len(rrsig_result['signatures'])} signatures")
    
    if rrsig_result['warnings']:
        for warning in rrsig_result['warnings']:
            logger.warning(warning)
    
    logger.info("Analysis complete")
    return 0

if __name__ == '__main__':
    exit(main())
```

## Integration Examples

### Flask Web API

```python
from flask import Flask, jsonify, request
from dnsscience_util import DNSQuery, GlobalResolverTester

app = Flask(__name__)

@app.route('/query/<domain>')
def query_domain(domain):
    record_type = request.args.get('type', 'A')
    nameserver = request.args.get('ns')
    
    query = DNSQuery(nameserver=nameserver)
    response, stats = query.query(domain, record_type)
    
    answers = [str(rdata) for rrset in response.answer for rdata in rrset]
    
    return jsonify({
        'domain': domain,
        'type': record_type,
        'answers': answers,
        'query_time': stats['query_time']
    })

@app.route('/global-test/<domain>')
def global_test(domain):
    tester = GlobalResolverTester()
    result = tester.test_domain(domain, 'A')
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
```

### Async Operations

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dnsscience_util import DNSQuery

async def async_query(domain, record_type='A'):
    loop = asyncio.get_event_loop()
    query = DNSQuery()
    
    with ThreadPoolExecutor() as pool:
        response, stats = await loop.run_in_executor(
            pool, query.query, domain, record_type
        )
    
    return response, stats

async def main():
    domains = ['example.com', 'google.com', 'github.com']
    tasks = [async_query(domain) for domain in domains]
    results = await asyncio.gather(*tasks)
    
    for domain, (response, stats) in zip(domains, results):
        print(f"{domain}: {stats['query_time']}ms")

if __name__ == '__main__':
    asyncio.run(main())
```

## Error Handling

```python
from dnsscience_util import DNSQuery, Logger

logger = Logger('dns-app', 'DEBUG')
query = DNSQuery(timeout=5, logger=logger)

try:
    response, stats = query.query('example.com', 'A')
except dns.exception.Timeout:
    logger.error("Query timeout - check network connectivity")
except dns.resolver.NXDOMAIN:
    logger.error("Domain does not exist")
except dns.resolver.NoAnswer:
    logger.warning("Domain exists but no A record found")
except Exception as e:
    logger.critical(f"Unexpected error: {e}")
```

## Performance Optimization

```python
from dnsscience_util import GlobalResolverTester, Config

# Configure for high performance
config = Config()
config.set('max_workers', 100)  # More concurrent queries
config.set('timeout', 2)         # Shorter timeout

tester = GlobalResolverTester(
    timeout=config.get('timeout'),
    max_workers=config.get('max_workers')
)

# Batch processing
domains = ['example1.com', 'example2.com', 'example3.com']
results = []

for domain in domains:
    result = tester.test_domain(domain, 'A')
    results.append(result)

# Analyze results
for result in results:
    if result['consistency_score'] < 95:
        print(f"Warning: {result['domain']} has low consistency")
```

## Type Hints

All classes and functions include comprehensive type hints:

```python
from typing import Dict, List, Optional, Tuple, Any
from dns.message import Message

def query(
    self,
    qname: str,
    qtype: str = 'A',
    qclass: str = 'IN'
) -> Tuple[Message, Dict[str, Any]]:
    ...
```

## Testing

```python
import unittest
from dnsscience_util import DNSQuery

class TestDNSQuery(unittest.TestCase):
    def test_basic_query(self):
        query = DNSQuery(timeout=5)
        response, stats = query.query('example.com', 'A')
        
        self.assertIsNotNone(response)
        self.assertIn('query_time', stats)
        self.assertGreater(stats['query_time'], 0)
    
    def test_dnssec_query(self):
        query = DNSQuery(dnssec=True)
        response, stats = query.query('cloudflare.com', 'DNSKEY')
        
        # Check for DNSSEC records
        has_dnskey = any(
            rrset.rdtype == dns.rdatatype.DNSKEY 
            for rrset in response.answer
        )
        self.assertTrue(has_dnskey)

if __name__ == '__main__':
    unittest.main()
```

## Conclusion

DNSScience Utility provides a comprehensive Python API for DNS operations, from basic queries to advanced security analysis. All classes follow consistent patterns and include proper error handling, logging, and type hints.

For more information:
- [README.md](../README.md) - User guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - Design details
- [EXAMPLES.md](EXAMPLES.md) - Usage examples
