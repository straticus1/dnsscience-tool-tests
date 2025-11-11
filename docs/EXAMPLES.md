# DNSScience Utility - Real-World Examples

## Table of Contents
1. [Basic DNS Queries](#basic-dns-queries)
2. [DNSSEC Operations](#dnssec-operations)
3. [Security Testing](#security-testing)
4. [Global Propagation Testing](#global-propagation-testing)
5. [Troubleshooting Scenarios](#troubleshooting-scenarios)
6. [Automation and Scripting](#automation-and-scripting)
7. [Enterprise Use Cases](#enterprise-use-cases)

## Basic DNS Queries

### Example 1: Check Website DNS

```bash
# Check if website is reachable via DNS
./dnsscience-util.py example.com

# Check both IPv4 and IPv6
./dnsscience-util.py example.com A
./dnsscience-util.py example.com AAAA

# Check with specific resolver
./dnsscience-util.py example.com @8.8.8.8
```

### Example 2: Email Server Validation

```bash
# Check MX records
./dnsscience-util.py example.com MX

# Verify SPF configuration
./dnsscience-util.py example.com TXT

# Check DMARC policy
./dnsscience-util.py _dmarc.example.com TXT

# Check DKIM selector
./dnsscience-util.py selector._domainkey.example.com TXT
```

### Example 3: Trace DNS Resolution Path

```bash
# Trace from root to final answer
./dnsscience-util.py --trace example.com

# Save trace to file
./dnsscience-util.py --trace example.com --output-file trace.txt
```

## DNSSEC Operations

### Example 4: Validate DNSSEC Configuration

```bash
# Check if DNSSEC is enabled
./dnsscience-util.py example.com DNSKEY +dnssec

# Validate full DNSSEC chain
./dnsscience-util.py --validate example.com

# Check DS records at parent
./dnsscience-util.py example.com DS @parent-nameserver.com
```

### Example 5: Monitor RRSIG Expiration

```bash
# Analyze all RRSIG records
./dnsscience-util.py --rrsig-analyze example.com +json > rrsig-report.json

# Check expiration warnings
./dnsscience-util.py --rrsig-analyze example.com 2>&1 | grep -i warning

# Set up automated monitoring
watch -n 3600 './dnsscience-util.py --rrsig-analyze example.com'
```

### Example 6: NSEC/NSEC3 Zone Enumeration

```bash
# Walk NSEC chain
./dnsscience-util.py --nsec-walk example.com @ns1.example.com > zone-records.txt

# Analyze NSEC3 parameters
./dnsscience-util.py --nsec3-analyze example.com @ns1.example.com +json
```

## Security Testing

### Example 7: DANE/TLSA Validation for Email

```bash
# Validate SMTP server certificate
./dnsscience-util.py --dane-validate mail.example.com 25

# Check multiple mail servers
for mx in mx1 mx2 mx3; do
    echo "Testing $mx.example.com"
    ./dnsscience-util.py --dane-validate $mx.example.com 25
done
```

### Example 8: Comprehensive Security Audit

```bash
# Run full security analysis
./dnsscience-util.py --security-analyze example.com +json > security-report.json

# Check specific security aspects
./dnsscience-util.py --validate example.com
./dnsscience-util.py --rrsig-analyze example.com
./dnsscience-util.py --edns-test 8.8.8.8
```

### Example 9: Detect DNS Hijacking

```bash
# Test from multiple resolvers
./dnsscience-util.py --global-test example.com

# Compare specific resolvers
./dnsscience-util.py example.com @8.8.8.8 +short
./dnsscience-util.py example.com @1.1.1.1 +short
./dnsscience-util.py example.com @9.9.9.9 +short
```

## Global Propagation Testing

### Example 10: Test DNS Propagation After Change

```bash
# Test globally immediately after DNS change
./dnsscience-util.py --global-test example.com

# Test specific region
./dnsscience-util.py --global-test example.com --region europe

# Monitor propagation over time
for i in {1..12}; do
    echo "Check #$i - $(date)"
    ./dnsscience-util.py --global-test example.com | grep "Consistency"
    sleep 300  # Wait 5 minutes
done
```

### Example 11: Geographic Distribution Analysis

```bash
# Test from all regions
./dnsscience-util.py --global-test example.com --region north_america +json
./dnsscience-util.py --global-test example.com --region europe +json
./dnsscience-util.py --global-test example.com --region asia +json

# Compare results
./dnsscience-util.py --global-test example.com \
    --json-output global-test.json

# Analyze consistency by region
jq '.results | group_by(.region) | map({region: .[0].region, count: length})' global-test.json
```

### Example 12: Test Multiple Domains

```bash
# Create domains file
cat > domains.txt << EOF
example.com
www.example.com
mail.example.com
api.example.com
EOF

# Test each domain
while read domain; do
    echo "Testing $domain"
    ./dnsscience-util.py --global-test $domain --region all
done < domains.txt
```

## Troubleshooting Scenarios

### Example 13: Debug Intermittent DNS Issues

```bash
# Test with logging
./dnsscience-util.py example.com \
    --log-file dns-debug.log \
    --log-level DEBUG

# Test with different protocols
./dnsscience-util.py example.com           # UDP
./dnsscience-util.py example.com +tcp      # TCP

# Test with different EDNS settings
./dnsscience-util.py example.com +edns=0
./dnsscience-util.py example.com +bufsize=512
```

### Example 14: Investigate Slow DNS Resolution

```bash
# Test response times from multiple resolvers
./dnsscience-util.py --global-test example.com --region north_america

# Test specific resolver performance
for i in {1..10}; do
    ./dnsscience-util.py example.com @8.8.8.8 | grep "Query time"
done

# Test with increased timeout
./dnsscience-util.py example.com +timeout=10
```

### Example 15: Verify Zone Transfer Configuration

```bash
# Test AXFR
./dnsscience-util.py --axfr example.com @ns1.example.com

# Check TSIG authentication (if configured)
./dnsscience-util.py --axfr example.com @ns1.example.com \
    --tsig-key keyname:secret

# Test from unauthorized IP (should fail)
./dnsscience-util.py --axfr example.com @ns1.example.com
```

## Automation and Scripting

### Example 16: CI/CD DNS Validation

```bash
#!/bin/bash
# ci-dns-check.sh

DOMAIN="example.com"
MIN_SCORE=90

# Run security analysis
RESULT=$(./dnsscience-util.py --security-analyze $DOMAIN +json)

# Extract security score
SCORE=$(echo $RESULT | jq '.security_score')

if [ $SCORE -lt $MIN_SCORE ]; then
    echo "DNS security score ($SCORE) below minimum ($MIN_SCORE)"
    exit 1
fi

echo "DNS security check passed (score: $SCORE)"
exit 0
```

### Example 17: Automated Monitoring Script

```bash
#!/bin/bash
# monitor-dns.sh

DOMAINS="example.com api.example.com www.example.com"
ALERT_EMAIL="ops@example.com"

for domain in $DOMAINS; do
    # Test global consistency
    RESULT=$(./dnsscience-util.py --global-test $domain +json)
    CONSISTENCY=$(echo $RESULT | jq '.consistency_score')
    
    if [ $(echo "$CONSISTENCY < 95" | bc) -eq 1 ]; then
        # Alert on low consistency
        echo "Alert: $domain consistency only $CONSISTENCY%" | \
            mail -s "DNS Alert: $domain" $ALERT_EMAIL
    fi
    
    # Check DNSSEC
    ./dnsscience-util.py --validate $domain || \
        echo "DNSSEC validation failed for $domain" | \
        mail -s "DNSSEC Alert: $domain" $ALERT_EMAIL
done
```

### Example 18: Batch Processing with JSON Output

```bash
#!/bin/bash
# batch-dns-check.sh

# Read domains from file
DOMAINS_FILE="domains.txt"
OUTPUT_DIR="dns-reports"

mkdir -p $OUTPUT_DIR

while read domain; do
    echo "Processing $domain..."
    
    # Standard query
    ./dnsscience-util.py $domain +json > \
        "$OUTPUT_DIR/${domain}-a-record.json"
    
    # MX records
    ./dnsscience-util.py $domain MX +json > \
        "$OUTPUT_DIR/${domain}-mx-records.json"
    
    # Security analysis
    ./dnsscience-util.py --security-analyze $domain +json > \
        "$OUTPUT_DIR/${domain}-security.json"
    
    # Global test
    ./dnsscience-util.py --global-test $domain +json > \
        "$OUTPUT_DIR/${domain}-global.json"
    
done < $DOMAINS_FILE

# Generate summary report
jq -s '.' $OUTPUT_DIR/*.json > $OUTPUT_DIR/summary.json
```

## Enterprise Use Cases

### Example 19: Pre-Production Validation

```bash
#!/bin/bash
# pre-prod-dns-validation.sh

NEW_DOMAIN="new-service.example.com"
PROD_NAMESERVERS="ns1.example.com ns2.example.com"

echo "Validating DNS configuration for $NEW_DOMAIN"

# Check NS records
echo "Checking nameservers..."
./dnsscience-util.py $NEW_DOMAIN NS

# Verify each nameserver
for ns in $PROD_NAMESERVERS; do
    echo "Testing $ns..."
    ./dnsscience-util.py $NEW_DOMAIN @$ns || exit 1
done

# Test global propagation
echo "Testing global propagation..."
./dnsscience-util.py --global-test $NEW_DOMAIN

# Validate DNSSEC if enabled
echo "Validating DNSSEC..."
./dnsscience-util.py --validate $NEW_DOMAIN

# Test DANE/TLSA if applicable
echo "Testing DANE/TLSA..."
./dnsscience-util.py --dane-validate $NEW_DOMAIN 443

echo "All DNS validation checks passed!"
```

### Example 20: Compliance Audit Report

```bash
#!/bin/bash
# compliance-audit.sh

REPORT_DIR="compliance-reports"
AUDIT_DATE=$(date +%Y-%m-%d)
DOMAINS_FILE="production-domains.txt"

mkdir -p $REPORT_DIR/$AUDIT_DATE

echo "DNS Compliance Audit - $AUDIT_DATE" > \
    $REPORT_DIR/$AUDIT_DATE/summary.txt

while read domain; do
    echo "Auditing $domain..."
    
    # DNSSEC compliance
    ./dnsscience-util.py --validate $domain +json > \
        $REPORT_DIR/$AUDIT_DATE/${domain}-dnssec.json
    
    # Security posture
    ./dnsscience-util.py --security-analyze $domain +json > \
        $REPORT_DIR/$AUDIT_DATE/${domain}-security.json
    
    # Global availability
    ./dnsscience-util.py --global-test $domain +json > \
        $REPORT_DIR/$AUDIT_DATE/${domain}-availability.json
    
    # Extract key metrics
    DNSSEC=$(jq '.validated' $REPORT_DIR/$AUDIT_DATE/${domain}-dnssec.json)
    SECURITY=$(jq '.security_score' $REPORT_DIR/$AUDIT_DATE/${domain}-security.json)
    AVAILABILITY=$(jq '.successful / .total_resolvers * 100' \
        $REPORT_DIR/$AUDIT_DATE/${domain}-availability.json)
    
    # Add to summary
    echo "$domain: DNSSEC=$DNSSEC, Security=$SECURITY, Availability=$AVAILABILITY%" >> \
        $REPORT_DIR/$AUDIT_DATE/summary.txt
    
done < $DOMAINS_FILE

# Generate PDF report (requires pandoc)
pandoc $REPORT_DIR/$AUDIT_DATE/summary.txt \
    -o $REPORT_DIR/$AUDIT_DATE/compliance-report.pdf
```

### Example 21: Disaster Recovery Testing

```bash
#!/bin/bash
# dr-dns-test.sh

PRIMARY_DC_NS="ns1-primary.example.com"
DR_DC_NS="ns1-dr.example.com"
TEST_DOMAINS="example.com www.example.com api.example.com"

echo "DNS Disaster Recovery Test"
echo "=========================="

for domain in $TEST_DOMAINS; do
    echo ""
    echo "Testing $domain"
    
    # Test primary DC
    echo "Primary DC:"
    PRIMARY_RESULT=$(./dnsscience-util.py $domain @$PRIMARY_DC_NS +short)
    echo "  Response: $PRIMARY_RESULT"
    
    # Test DR DC
    echo "DR DC:"
    DR_RESULT=$(./dnsscience-util.py $domain @$DR_DC_NS +short)
    echo "  Response: $DR_RESULT"
    
    # Compare
    if [ "$PRIMARY_RESULT" == "$DR_RESULT" ]; then
        echo "  ✓ Results match"
    else
        echo "  ✗ Results differ!"
        exit 1
    fi
done

echo ""
echo "All DR DNS tests passed!"
```

## Advanced Techniques

### Example 22: Performance Baseline

```bash
#!/bin/bash
# dns-performance-baseline.sh

DOMAIN="example.com"
RESOLVERS="8.8.8.8 1.1.1.1 9.9.9.9 208.67.222.222"
ITERATIONS=100

echo "DNS Performance Baseline for $DOMAIN"
echo "====================================="

for resolver in $RESOLVERS; do
    echo ""
    echo "Testing $resolver..."
    
    total=0
    for i in $(seq 1 $ITERATIONS); do
        time=$(./dnsscience-util.py $DOMAIN @$resolver 2>&1 | \
            grep "Query time" | awk '{print $4}')
        total=$(echo "$total + $time" | bc)
    done
    
    avg=$(echo "scale=2; $total / $ITERATIONS" | bc)
    echo "  Average: ${avg}ms over $ITERATIONS queries"
done
```

### Example 23: DNSSEC Chain Validation

```bash
#!/bin/bash
# validate-dnssec-chain.sh

DOMAIN="example.com"

echo "DNSSEC Chain Validation for $DOMAIN"
echo "===================================="

# Get DNSKEY
echo "1. Checking DNSKEY..."
./dnsscience-util.py $DOMAIN DNSKEY +dnssec

# Get DS from parent
echo "2. Checking DS at parent..."
PARENT=$(echo $DOMAIN | cut -d. -f2-)
./dnsscience-util.py $DOMAIN DS @$(./dnsscience-util.py $PARENT NS +short | head -1)

# Validate chain
echo "3. Validating complete chain..."
./dnsscience-util.py --validate $DOMAIN

# Analyze signatures
echo "4. Analyzing signatures..."
./dnsscience-util.py --rrsig-analyze $DOMAIN
```

## Conclusion

These examples demonstrate the versatility and power of DNSScience Utility across various scenarios:

- **Basic Operations**: Everyday DNS queries and validation
- **Security Testing**: Comprehensive security analysis
- **Automation**: Integration into CI/CD and monitoring systems
- **Troubleshooting**: Systematic problem diagnosis
- **Enterprise**: Production-grade validation and compliance

For more information, see:
- [README.md](../README.md) - Quick start guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical architecture
- [SECURITY-FEATURES.md](SECURITY-FEATURES.md) - Security capabilities
- [API-REFERENCE.md](API-REFERENCE.md) - API documentation
