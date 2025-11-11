# DNSScience Utility - Architecture Guide

## Overview

DNSScience Utility is designed as a modular, extensible DNS analysis platform that combines the best features of traditional DNS tools (dig, ldns) with modern security analysis and global testing capabilities.

## Design Principles

### 1. Modularity
Each feature is implemented as an independent class that can be used separately or combined with others.

### 2. Extensibility
New features can be added without modifying existing code through clear interfaces and inheritance.

### 3. Performance
Parallel processing, connection pooling, and intelligent caching ensure efficient operation at scale.

### 4. Reliability
Comprehensive error handling, logging, and retry logic ensure robust operation in production environments.

### 5. Usability
Intuitive CLI design with dig-compatible syntax and multiple output formats for integration with other tools.

## Core Components

### 1. DNS Query Engine (`DNSQuery`)

**Purpose**: Core DNS query functionality with full control over query parameters.

**Features**:
- UDP and TCP transport
- EDNS support with configurable parameters
- DNSSEC query capabilities (DO bit, CD flag, AD flag)
- Source address/port binding
- Comprehensive statistics collection

**Implementation Details**:
```python
class DNSQuery:
    - query() -> Response + Statistics
    - Handles timeouts and retries
    - Collects performance metrics
    - Supports all DNS classes and types
```

### 2. LDNS-Equivalent Features

#### NSECWalker
**Purpose**: Zone enumeration via NSEC/NSEC3 chain walking.

**Algorithm**:
1. Query domain for A record with DNSSEC
2. Extract NSEC record from authority section
3. Follow "next" pointer to next name
4. Repeat until loop detected or limit reached
5. Deduplicate and return unique names

**Complexity**: O(n) where n is number of records in zone  
**Safety**: 10,000 record limit to prevent infinite loops

#### DANEValidator
**Purpose**: Validate TLS certificates against TLSA DNS records.

**Validation Process**:
1. Construct TLSA query: `_port._protocol.hostname`
2. Query for TLSA records with DNSSEC
3. Connect to service and retrieve certificate
4. Hash certificate according to TLSA parameters
5. Compare hash with TLSA record data
6. Return validation status

**Supported Configurations**:
- Usage: 0-3 (CA constraint, service cert constraint, trust anchor, domain-issued)
- Selector: 0-1 (full cert, SubjectPublicKeyInfo)
- Matching Type: 0-2 (exact, SHA-256, SHA-512)

#### EDNSTester
**Purpose**: Comprehensive EDNS capability testing.

**Tests Performed**:
1. EDNS0 basic support
2. Maximum UDP payload size
3. DNSSEC OK bit support
4. NSID (Name Server Identifier)
5. TCP fallback capability

#### RRSIGAnalyzer
**Purpose**: Analyze DNSSEC signatures for expiration and validity.

**Analysis Process**:
1. Query multiple record types (A, AAAA, MX, NS, DNSKEY)
2. Extract RRSIG records from answers and authority sections
3. Parse inception and expiration timestamps
4. Calculate days until expiration
5. Generate warnings based on thresholds:
   - CRITICAL: Expired
   - URGENT: < 24 hours
   - WARNING: < 7 days

#### DNSUpdateManager
**Purpose**: Send RFC 2136 DNS UPDATE messages.

**Operations**:
- Add: Add new RR
- Delete: Remove RR (with or without rdata matching)
- Replace: Delete all then add

**Authentication**: TSIG key support for secure updates

### 3. Security Analysis

#### DNSSecurityAnalyzer
**Purpose**: Comprehensive security analysis of DNS infrastructure.

**Analysis Components**:

**Hijacking Detection**:
- Queries domain from multiple resolvers
- Compares answer sets
- Flags resolvers with divergent answers
- Detects man-in-the-middle attacks

**Cache Poisoning Assessment**:
- Checks DNSSEC configuration
- Evaluates source port randomization
- Assigns risk level: LOW, MEDIUM, HIGH
- Provides mitigation recommendations

**Anomaly Detection**:
- TTL variance analysis
- Response pattern comparison
- Geographic inconsistency detection

**Security Scoring**:
- Starts at 100 points
- Deductions for issues found
- Weighted by severity
- Provides actionable recommendations

### 4. Global Resolver Testing

#### GlobalResolverTester
**Purpose**: Test DNS resolution across 258+ worldwide resolvers.

**Architecture**:
```
Load resolvers from JSON config
    ↓
Filter by region/country/tier (optional)
    ↓
ThreadPoolExecutor (50 workers default)
    ↓
Parallel queries to all selected resolvers
    ↓
Collect responses and statistics
    ↓
Analyze consistency and performance
    ↓
Generate comprehensive report
```

**Metrics Collected**:
- Success/failure counts
- Response times
- Unique answers
- Geographic distribution
- Consistency score (% matching most common answer)

**Performance**: Can test 258 resolvers in < 10 seconds with default settings

### 5. Encrypted DNS

#### DoHResolver (DNS over HTTPS)
**Purpose**: RFC 8484 compliant DoH queries.

**Implementation**:
- POST method (primary)
- GET method (optional, base64url encoded)
- Wire format DNS messages
- Standard HTTP headers

**Providers Supported**:
- Cloudflare, Google, Quad9, AdGuard, CleanBrowsing, NextDNS
- Custom URLs supported

#### DoTResolver (DNS over TLS)
**Purpose**: RFC 7858 compliant DoT queries.

**Implementation**:
- TLS 1.2+ required
- Certificate validation
- SNI (Server Name Indication) support
- Standard port 853

### 6. Infrastructure Components

#### Logger
**Purpose**: Multi-level logging with flexible output.

**Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL

**Outputs**:
- Console (stdout)
- File (with rotation support)
- Multiple simultaneous outputs

**Format**: ISO 8601 timestamp, logger name, level, message

#### Config
**Purpose**: Centralized configuration management.

**Supported Formats**:
- JSON
- YAML
- Python dict (programmatic)

**Configuration Options**:
- Timeout values
- Retry counts
- Worker pool sizes
- Default nameservers
- Logging preferences
- Output formats

#### OutputFormatter
**Purpose**: Multi-format output generation.

**Formats**:
- **dig-style**: Traditional dig output with colors
- **JSON**: Structured data for programmatic use
- **YAML**: Human-readable structured format
- **short**: Answers only (one per line)

**Features**:
- Syntax highlighting
- Optional color support
- Consistent structure across formats

## Data Flow

### Standard Query Flow
```
User Input (CLI)
    ↓
Argument Parsing
    ↓
Configuration Loading
    ↓
Logger Initialization
    ↓
Feature Selection (query/trace/axfr/etc.)
    ↓
DNS Operation
    ↓
Result Processing
    ↓
Output Formatting
    ↓
Display/File Output
```

### Global Testing Flow
```
User Request
    ↓
Load Resolver Config (258+ resolvers)
    ↓
Apply Filters (region/country/tier)
    ↓
ThreadPoolExecutor Initialization
    ↓
Parallel Query Execution
    ├─> Resolver 1 → Result 1
    ├─> Resolver 2 → Result 2
    ├─> ...
    └─> Resolver N → Result N
    ↓
Result Aggregation
    ↓
Statistical Analysis
    ↓
Report Generation
    ↓
Output
```

### Security Analysis Flow
```
Domain Input
    ↓
Multi-Resolver Queries (parallel)
    ↓
Response Collection
    ↓
Parallel Analysis Threads:
    ├─> Hijacking Detection
    ├─> Cache Poisoning Assessment
    ├─> Anomaly Detection
    └─> DNSSEC Validation
    ↓
Score Calculation
    ↓
Recommendation Generation
    ↓
Comprehensive Report
```

## Performance Optimizations

### 1. Parallel Processing
- ThreadPoolExecutor for concurrent queries
- Configurable worker pool sizes
- Intelligent work distribution

### 2. Connection Reuse
- Socket pooling where applicable
- Persistent TLS connections for DoT
- HTTP session reuse for DoH

### 3. Timeout Management
- Per-query timeouts
- Global operation timeouts
- Intelligent retry logic

### 4. Resource Management
- Automatic cleanup of resources
- Memory-efficient data structures
- Lazy evaluation where possible

### 5. Caching
- DNS response caching (optional)
- Resolver list caching
- Configuration caching

## Error Handling Strategy

### Levels of Error Handling

1. **Network Level**: Socket errors, timeouts, connection refused
2. **Protocol Level**: Malformed responses, invalid data
3. **Application Level**: Invalid arguments, configuration errors
4. **User Level**: Clear error messages, recovery suggestions

### Error Recovery

- Automatic retry with exponential backoff
- Fallback to alternative methods (UDP → TCP)
- Graceful degradation (continue on partial failure)

## Security Considerations

### 1. Input Validation
- Domain name format validation
- IP address validation
- Port range checking
- Record type validation

### 2. Network Security
- Certificate validation for DoT
- DNSSEC validation where requested
- No credentials in logs

### 3. Resource Limits
- Maximum concurrent connections
- Query rate limiting
- Memory usage bounds

## Extension Points

### Adding New Features

1. **New Query Type**: Extend `DNSQuery` class
2. **New Analysis**: Implement analyzer class with standard interface
3. **New Output Format**: Add method to `OutputFormatter`
4. **New Protocol**: Implement resolver class (like `DoHResolver`)

### Plugin Architecture (Future)
```python
class DNSPlugin:
    def init(self, config): pass
    def process(self, query, response): pass
    def output(self, data): pass
```

## Testing Strategy

### Unit Tests
- Individual class methods
- Edge cases and error conditions
- Mock external dependencies

### Integration Tests
- End-to-end query flows
- Multi-component interactions
- Real DNS queries to test domains

### Performance Tests
- Concurrent query handling
- Memory usage under load
- Response time benchmarks

## Deployment Considerations

### Requirements
- Python 3.8+
- DNS network access (UDP 53, TCP 53)
- Optional: HTTPS access for DoH (TCP 443)
- Optional: DoT access (TCP 853)

### Resource Usage
- Memory: ~50MB base + ~1KB per resolver in global test
- CPU: Minimal per query, scales with concurrency
- Network: Proportional to query count

### Scaling
- Horizontal: Multiple instances for different domains
- Vertical: Increase worker pool size
- Geographic: Deploy near target regions for lower latency

## Monitoring and Observability

### Metrics to Track
- Query success rate
- Response times (p50, p95, p99)
- Error rates by type
- Resolver availability (for global testing)

### Logging Best Practices
- Use appropriate log levels
- Include context (domain, resolver, operation)
- Avoid logging sensitive data
- Rotate logs regularly

## Future Architecture Plans

### Version 3.1
- Batch processing engine
- Result caching layer
- Webhook notification system

### Version 3.2
- REST API server mode
- WebSocket real-time updates
- Database backend for history

### Version 4.0
- Distributed query architecture
- Microservices-based design
- Container orchestration support

## Conclusion

DNSScience Utility's architecture balances:
- **Simplicity**: Easy to understand and use
- **Power**: Comprehensive feature set
- **Performance**: Efficient at scale
- **Maintainability**: Clean, modular code
- **Extensibility**: Easy to add new features

This design enables it to serve as both a powerful command-line tool for operators and a solid foundation for building more complex DNS analysis systems.
