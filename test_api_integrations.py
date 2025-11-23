#!/usr/bin/env python3
"""
DNS Science API Integration Test Suite
Tests all API endpoints and validates responses
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple
import sys

class APIIntegrationTester:
    """Comprehensive API testing suite"""

    def __init__(self, base_url: str = "http://localhost"):
        self.base_url = base_url
        self.test_results = []
        self.start_time = datetime.now()

    def test_endpoint(self, name: str, method: str, path: str,
                     params: Dict = None, data: Dict = None) -> Tuple[bool, str, float]:
        """Test a single API endpoint"""
        url = f"{self.base_url}{path}"

        try:
            start = time.time()

            if method == "GET":
                response = requests.get(url, params=params, timeout=10)
            elif method == "POST":
                response = requests.post(url, json=data, timeout=10)
            else:
                return False, f"Unsupported method: {method}", 0

            elapsed = time.time() - start

            if response.status_code == 200:
                try:
                    json_data = response.json()
                    return True, f"Success: {response.status_code}", elapsed
                except:
                    return False, f"Invalid JSON response", elapsed
            else:
                return False, f"HTTP {response.status_code}", elapsed

        except requests.exceptions.Timeout:
            return False, "Request timeout", 10.0
        except requests.exceptions.ConnectionError:
            return False, "Connection failed", 0
        except Exception as e:
            return False, f"Error: {str(e)}", 0

    def run_all_tests(self) -> Dict:
        """Run all API integration tests"""
        print("="*60)
        print("DNS SCIENCE API INTEGRATION TEST SUITE")
        print("="*60)
        print(f"Target: {self.base_url}")
        print(f"Started: {self.start_time.isoformat()}")
        print("-"*60)

        # Test configurations
        tests = [
            # Health check
            ("Health Check", "GET", "/health", None, None),

            # Main pages
            ("Homepage", "GET", "/", None, None),
            ("Tools Page", "GET", "/tools", None, None),
            ("API Docs", "GET", "/api/docs", None, None),
            ("Explorer", "GET", "/explorer", None, None),
            ("Visual Trace", "GET", "/visualtrace", None, None),
            ("Pricing", "GET", "/pricing", None, None),

            # API endpoints
            ("API Stats", "GET", "/api/stats", None, None),
            ("IP Reputation - Google DNS", "GET", "/api/ip-reputation", {"ip": "8.8.8.8"}, None),
            ("IP Reputation - Cloudflare", "GET", "/api/ip-reputation", {"ip": "1.1.1.1"}, None),
            ("Domain Security - Google", "GET", "/api/domain-security-score", {"domain": "google.com"}, None),
            ("Domain Security - GitHub", "GET", "/api/domain-security-score", {"domain": "github.com"}, None),
            ("Geolocation - Google DNS", "GET", "/api/geolocation", {"ip": "8.8.8.8"}, None),
            ("Geolocation - OpenDNS", "GET", "/api/geolocation", {"ip": "208.67.222.222"}, None),
            ("Threat Intel - Test IP", "POST", "/api/threat-intel", None, {"ip": "192.168.1.1"}),
        ]

        # Run tests
        for test_name, method, path, params, data in tests:
            print(f"\nTesting: {test_name}")
            print(f"  Method: {method} {path}")
            if params:
                print(f"  Params: {params}")
            if data:
                print(f"  Data: {data}")

            success, message, elapsed = self.test_endpoint(test_name, method, path, params, data)

            result = {
                "name": test_name,
                "method": method,
                "path": path,
                "success": success,
                "message": message,
                "response_time": elapsed
            }

            self.test_results.append(result)

            # Print result
            status_icon = "✅" if success else "❌"
            print(f"  Result: {status_icon} {message}")
            print(f"  Response Time: {elapsed:.3f}s")

        # Summary
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)

        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r["success"])
        failed_tests = total_tests - passed_tests
        pass_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0

        avg_response_time = sum(r["response_time"] for r in self.test_results) / total_tests

        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Pass Rate: {pass_rate:.1f}%")
        print(f"Average Response Time: {avg_response_time:.3f}s")

        # Failed tests details
        if failed_tests > 0:
            print("\nFailed Tests:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"  - {result['name']}: {result['message']}")

        # Performance warnings
        print("\nPerformance Analysis:")
        slow_tests = [r for r in self.test_results if r["response_time"] > 1.0]
        if slow_tests:
            print("  ⚠️ Slow endpoints (>1s):")
            for result in slow_tests:
                print(f"    - {result['name']}: {result['response_time']:.3f}s")
        else:
            print("  ✅ All endpoints respond within 1 second")

        # Overall status
        print("\n" + "="*60)
        if pass_rate == 100:
            print("🎉 ALL TESTS PASSED! Platform is fully operational.")
        elif pass_rate >= 90:
            print("✅ Platform is operational with minor issues.")
        elif pass_rate >= 70:
            print("⚠️ Platform has significant issues requiring attention.")
        else:
            print("❌ Platform has critical issues. Immediate action required.")
        print("="*60)

        return {
            "summary": {
                "total_tests": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "pass_rate": pass_rate,
                "avg_response_time": avg_response_time
            },
            "results": self.test_results,
            "timestamp": datetime.now().isoformat()
        }

    def test_api_features(self):
        """Test specific API features"""
        print("\n" + "="*60)
        print("API FEATURE TESTS")
        print("="*60)

        # Test IP reputation scoring
        print("\n1. Testing IP Reputation Scoring:")
        test_ips = [
            ("8.8.8.8", "Google DNS", "low"),
            ("1.1.1.1", "Cloudflare DNS", "low"),
            ("208.67.222.222", "OpenDNS", "low")
        ]

        for ip, description, expected_risk in test_ips:
            url = f"{self.base_url}/api/ip-reputation"
            try:
                response = requests.get(url, params={"ip": ip}, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    risk_level = data.get("risk_level", "unknown")
                    print(f"  {ip} ({description}): Risk level = {risk_level} ✅")
                else:
                    print(f"  {ip} ({description}): HTTP {response.status_code} ❌")
            except Exception as e:
                print(f"  {ip} ({description}): Error - {str(e)} ❌")

        # Test domain security scoring
        print("\n2. Testing Domain Security Scoring:")
        test_domains = [
            "google.com",
            "github.com",
            "cloudflare.com"
        ]

        for domain in test_domains:
            url = f"{self.base_url}/api/domain-security-score"
            try:
                response = requests.get(url, params={"domain": domain}, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    score = data.get("score", 0)
                    grade = data.get("grade", "?")
                    checks = data.get("checks", {})

                    print(f"  {domain}:")
                    print(f"    Score: {score}/100 (Grade: {grade})")
                    print(f"    DNSSEC: {'✅' if checks.get('dnssec') else '❌'}")
                    print(f"    SPF: {'✅' if checks.get('spf') else '❌'}")
                    print(f"    DMARC: {'✅' if checks.get('dmarc') else '❌'}")
                    print(f"    CAA: {'✅' if checks.get('caa') else '❌'}")
                else:
                    print(f"  {domain}: HTTP {response.status_code} ❌")
            except Exception as e:
                print(f"  {domain}: Error - {str(e)} ❌")

        # Test geolocation
        print("\n3. Testing Geolocation:")
        for ip, description, _ in test_ips:
            url = f"{self.base_url}/api/geolocation"
            try:
                response = requests.get(url, params={"ip": ip}, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    country = data.get("country", "Unknown")
                    city = data.get("city", "Unknown")
                    print(f"  {ip} ({description}): {city}, {country} ✅")
                else:
                    print(f"  {ip} ({description}): HTTP {response.status_code} ❌")
            except Exception as e:
                print(f"  {ip} ({description}): Error - {str(e)} ❌")

    def generate_report(self, output_file: str = "api_test_report.json"):
        """Generate JSON test report"""
        report = {
            "test_suite": "DNS Science API Integration Tests",
            "timestamp": datetime.now().isoformat(),
            "base_url": self.base_url,
            "results": self.test_results,
            "summary": {
                "total": len(self.test_results),
                "passed": sum(1 for r in self.test_results if r["success"]),
                "failed": sum(1 for r in self.test_results if not r["success"])
            }
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\nTest report saved to: {output_file}")
        return report

def main():
    """Main test execution"""
    import argparse

    parser = argparse.ArgumentParser(description='Test DNS Science API Integrations')
    parser.add_argument('--url', default='http://localhost', help='Base URL to test')
    parser.add_argument('--features', action='store_true', help='Run feature tests')
    parser.add_argument('--report', help='Output report file', default='api_test_report.json')

    args = parser.parse_args()

    tester = APIIntegrationTester(base_url=args.url)

    # Run main tests
    results = tester.run_all_tests()

    # Run feature tests if requested
    if args.features:
        tester.test_api_features()

    # Generate report
    tester.generate_report(args.report)

    # Exit with appropriate code
    if results["summary"]["pass_rate"] == 100:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()