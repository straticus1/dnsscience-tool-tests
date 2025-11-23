#!/bin/bash
#
# DNS Science Deployment Validation Script
# Validates all aspects of the deployment
#

set -e

INSTANCE_IP="${1:-localhost}"
INSTANCE_ID="i-0fb0c631835188d36"

echo "=========================================================="
echo "DNS SCIENCE DEPLOYMENT VALIDATION"
echo "=========================================================="
echo "Target: $INSTANCE_IP"
echo "Instance: $INSTANCE_ID"
echo "Timestamp: $(date)"
echo "=========================================================="

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "Testing: $test_name... "

    if eval "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "  Command: $test_command"
        return 1
    fi
}

echo -e "\n${YELLOW}1. HEALTH CHECK TESTS${NC}"
echo "----------------------------------------"

run_test "Health endpoint exists" \
    "curl -s -f http://$INSTANCE_IP/health" \
    "200"

run_test "Health returns JSON" \
    "curl -s http://$INSTANCE_IP/health | python3 -m json.tool" \
    "valid"

run_test "Database healthy in health check" \
    "curl -s http://$INSTANCE_IP/health | grep -q '\"database\": \"healthy\"'" \
    "healthy"

echo -e "\n${YELLOW}2. MAIN PAGES TESTS${NC}"
echo "----------------------------------------"

pages=("/" "/tools" "/api/docs" "/explorer" "/visualtrace" "/pricing")

for page in "${pages[@]}"; do
    run_test "Page $page loads" \
        "curl -s -o /dev/null -w '%{http_code}' http://$INSTANCE_IP$page | grep -q 200" \
        "200"
done

echo -e "\n${YELLOW}3. API ENDPOINTS TESTS${NC}"
echo "----------------------------------------"

run_test "API Stats endpoint" \
    "curl -s http://$INSTANCE_IP/api/stats | python3 -m json.tool" \
    "valid"

run_test "IP Reputation API" \
    "curl -s 'http://$INSTANCE_IP/api/ip-reputation?ip=8.8.8.8' | grep -q 'risk_'" \
    "risk data"

run_test "Domain Security API" \
    "curl -s 'http://$INSTANCE_IP/api/domain-security-score?domain=google.com' | grep -q 'score'" \
    "score"

run_test "Geolocation API" \
    "curl -s 'http://$INSTANCE_IP/api/geolocation?ip=8.8.8.8' | grep -q 'country'" \
    "location"

run_test "Threat Intel API" \
    "curl -s -X POST -H 'Content-Type: application/json' -d '{\"ip\":\"1.1.1.1\"}' http://$INSTANCE_IP/api/threat-intel | grep -q 'timestamp'" \
    "response"

echo -e "\n${YELLOW}4. PERFORMANCE TESTS${NC}"
echo "----------------------------------------"

# Test response times
total_time=0
iterations=5

echo "Running $iterations performance tests..."
for i in $(seq 1 $iterations); do
    response_time=$(curl -s -o /dev/null -w '%{time_total}' http://$INSTANCE_IP/health)
    total_time=$(echo "$total_time + $response_time" | bc)
    echo "  Test $i: ${response_time}s"
done

avg_time=$(echo "scale=3; $total_time / $iterations" | bc)
echo "Average response time: ${avg_time}s"

if (( $(echo "$avg_time < 1.0" | bc -l) )); then
    echo -e "${GREEN}✅ Performance: GOOD (< 1s average)${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo -e "${YELLOW}⚠️ Performance: SLOW (> 1s average)${NC}"
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

echo -e "\n${YELLOW}5. ERROR CHECK${NC}"
echo "----------------------------------------"

# Check for 500 errors in logs (if we have SSH access)
if [ "$INSTANCE_IP" != "localhost" ]; then
    echo "Checking remote logs requires SSH access"
else
    if sudo tail -100 /var/log/httpd/access_log 2>/dev/null | grep -q " 500 "; then
        echo -e "${RED}❌ Found 500 errors in access log${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    else
        echo -e "${GREEN}✅ No 500 errors in recent access log${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
fi

echo -e "\n${YELLOW}6. SECURITY HEADERS TEST${NC}"
echo "----------------------------------------"

headers=$(curl -s -I http://$INSTANCE_IP/)

run_test "X-Frame-Options header" \
    "echo '$headers' | grep -q 'X-Frame-Options'" \
    "present"

run_test "X-Content-Type-Options header" \
    "echo '$headers' | grep -q 'X-Content-Type-Options'" \
    "present"

run_test "X-XSS-Protection header" \
    "echo '$headers' | grep -q 'X-XSS-Protection'" \
    "present"

echo -e "\n${YELLOW}7. LOAD BALANCER READINESS${NC}"
echo "----------------------------------------"

# Simulate load balancer health check
health_response=$(curl -s -o /dev/null -w '%{http_code}' http://$INSTANCE_IP/health)
if [ "$health_response" == "200" ]; then
    echo -e "${GREEN}✅ Instance ready for load balancer (HTTP 200)${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo -e "${RED}❌ Instance not ready for load balancer (HTTP $health_response)${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Final Summary
echo ""
echo "=========================================================="
echo "VALIDATION SUMMARY"
echo "=========================================================="
echo "Total Tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

PASS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
echo "Pass Rate: $PASS_RATE%"

echo ""
if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED! Platform is fully operational.${NC}"
    EXIT_CODE=0
elif [ $PASS_RATE -ge 90 ]; then
    echo -e "${GREEN}✅ Platform is operational with minor issues.${NC}"
    EXIT_CODE=0
elif [ $PASS_RATE -ge 70 ]; then
    echo -e "${YELLOW}⚠️ Platform has issues requiring attention.${NC}"
    EXIT_CODE=1
else
    echo -e "${RED}❌ Platform has critical issues.${NC}"
    EXIT_CODE=2
fi

echo "=========================================================="

# Recommendations if there are failures
if [ $FAILED_TESTS -gt 0 ]; then
    echo ""
    echo "RECOMMENDATIONS:"
    echo "1. Check Apache error logs: sudo tail -100 /var/log/httpd/error_log"
    echo "2. Verify Python dependencies: pip3 list"
    echo "3. Test database connection: sudo -u postgres psql -c 'SELECT 1'"
    echo "4. Restart services: sudo systemctl restart httpd"
    echo "5. Run comprehensive fix: ./deploy_comprehensive_stabilization.sh"
fi

exit $EXIT_CODE