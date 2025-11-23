#!/usr/bin/env python3
"""
DNS4 Network Fingerprinting Suite - Standalone Implementation
Comprehensive network fingerprinting tool for security analysis

Usage:
    python dns4.py tls example.com
    python dns4.py http --user-agent "Mozilla/5.0..."
    python dns4.py cert --cert-file cert.pem
    python dns4.py ssh example.com
    python dns4.py tcp 192.0.2.1
    python dns4.py lat example.com --source-ip 198.51.100.1
    python dns4.py analyze example.com
"""

import argparse
import json
import sys
import socket
import ssl
import hashlib
import struct
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import subprocess


class DNS4Analyzer:
    """Base class for DNS4 fingerprinting operations"""

    def __init__(self, verbose=False):
        self.verbose = verbose

    def log(self, message):
        """Print log message if verbose mode enabled"""
        if self.verbose:
            print(f"[DEBUG] {message}", file=sys.stderr)


class DNS4TLS(DNS4Analyzer):
    """DNS4-TLS: TLS Server Fingerprinting"""

    def analyze(self, target: str, port: int = 443, sni: Optional[str] = None) -> Dict[str, Any]:
        """Fingerprint TLS server"""
        self.log(f"Connecting to {target}:{port} for TLS analysis...")

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get server hello
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=sni or target) as ssock:
                    # Get certificate
                    cert_binary = ssock.getpeercert(binary_form=True)
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Extract features
                    tls_version = self._normalize_tls_version(version)
                    cipher_suite = cipher[0] if cipher else "Unknown"

                    # Generate fingerprint
                    fingerprint = self._generate_fingerprint(
                        tls_version, cipher_suite, cert
                    )

                    # Analyze security
                    security_score = self._calculate_security_score(
                        version, cipher_suite
                    )

                    # Extract certificate info
                    cert_info = self._extract_cert_info(cert, cert_binary)

                    return {
                        "fingerprint": fingerprint,
                        "server_software": self._detect_server_software(cert, cipher_suite),
                        "tls_version": version or "Unknown",
                        "cipher_suite": cipher_suite,
                        "security_score": security_score,
                        "certificate": cert_info,
                        "extensions": [],  # Would require deeper TLS parsing
                        "issues": self._identify_issues(version, cipher_suite),
                        "timestamp": datetime.now().isoformat()
                    }

        except Exception as e:
            self.log(f"Error analyzing TLS: {e}")
            return {
                "error": str(e),
                "fingerprint": None,
                "server_software": "Unknown",
                "tls_version": "Unknown",
                "cipher_suite": "Unknown",
                "security_score": 0,
                "timestamp": datetime.now().isoformat()
            }

    def _normalize_tls_version(self, version: str) -> str:
        """Normalize TLS version to single character"""
        version_map = {
            "TLSv1": "0",
            "TLSv1.1": "1",
            "TLSv1.2": "2",
            "TLSv1.3": "3",
        }
        return version_map.get(version, "x")

    def _generate_fingerprint(self, version: str, cipher: str, cert: dict) -> str:
        """Generate DNS4-TLS fingerprint"""
        # Format: t{version}{cipher_hash}_{cert_hash}
        cipher_hash = hashlib.sha256(cipher.encode()).hexdigest()[:12]

        cert_str = json.dumps(cert, sort_keys=True)
        cert_hash = hashlib.sha256(cert_str.encode()).hexdigest()[:6]

        return f"t{version}_{cipher_hash}_{cert_hash}"

    def _calculate_security_score(self, version: str, cipher: str) -> int:
        """Calculate security score (0-100)"""
        score = 50  # Base score

        # TLS version scoring
        if version == "TLSv1.3":
            score += 30
        elif version == "TLSv1.2":
            score += 20
        elif version == "TLSv1.1":
            score += 5
        else:
            score -= 20

        # Cipher scoring (basic heuristics)
        if "GCM" in cipher:
            score += 15
        if "AES" in cipher and "256" in cipher:
            score += 5
        if "RC4" in cipher or "DES" in cipher:
            score -= 40

        return max(0, min(100, score))

    def _detect_server_software(self, cert: dict, cipher: str) -> str:
        """Attempt to detect server software from cert/cipher patterns"""
        # This is heuristic-based, not definitive
        issuer = cert.get('issuer', ())
        issuer_str = str(issuer).lower()

        if 'let\'s encrypt' in issuer_str:
            return "Unknown (Let's Encrypt)"
        elif 'cloudflare' in issuer_str:
            return "Cloudflare"
        elif 'amazon' in issuer_str or 'aws' in issuer_str:
            return "AWS ALB/CloudFront"
        else:
            return "Unknown"

    def _extract_cert_info(self, cert: dict, cert_binary: bytes) -> dict:
        """Extract certificate information"""
        if not cert:
            return {}

        return {
            "subject": dict(x[0] for x in cert.get('subject', ())),
            "issuer": dict(x[0] for x in cert.get('issuer', ())),
            "version": cert.get('version', 'Unknown'),
            "serial_number": cert.get('serialNumber', 'Unknown'),
            "not_before": cert.get('notBefore', 'Unknown'),
            "not_after": cert.get('notAfter', 'Unknown'),
            "fingerprint_sha256": hashlib.sha256(cert_binary).hexdigest() if cert_binary else None
        }

    def _identify_issues(self, version: str, cipher: str) -> List[str]:
        """Identify security issues"""
        issues = []

        if version in ["SSLv2", "SSLv3", "TLSv1"]:
            issues.append(f"Deprecated TLS version: {version}")

        if "RC4" in cipher:
            issues.append("Weak cipher: RC4")

        if "DES" in cipher:
            issues.append("Weak cipher: DES")

        if "MD5" in cipher:
            issues.append("Weak hash: MD5")

        return issues


class DNS4HTTP(DNS4Analyzer):
    """DNS4-HTTP: HTTP Header Fingerprinting"""

    def analyze(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Fingerprint HTTP client headers"""
        self.log(f"Analyzing HTTP headers...")

        user_agent = headers.get('User-Agent', '')
        accept = headers.get('Accept', '')
        accept_language = headers.get('Accept-Language', '')
        accept_encoding = headers.get('Accept-Encoding', '')

        # Generate fingerprint
        fingerprint = self._generate_fingerprint(headers)

        # Detect client type
        is_bot, bot_type = self._detect_bot(user_agent)
        browser, os = self._parse_user_agent(user_agent)

        # Calculate security score
        security_score = self._calculate_security_score(headers, is_bot)

        return {
            "fingerprint": fingerprint,
            "client_type": "bot" if is_bot else "browser",
            "is_bot": is_bot,
            "bot_type": bot_type,
            "browser": browser,
            "os": os,
            "security_score": security_score,
            "anomalies": self._detect_anomalies(headers),
            "timestamp": datetime.now().isoformat()
        }

    def _generate_fingerprint(self, headers: Dict[str, str]) -> str:
        """Generate DNS4-HTTP fingerprint"""
        # Normalize and hash key headers
        header_str = json.dumps(headers, sort_keys=True)
        hash_val = hashlib.sha256(header_str.encode()).hexdigest()[:16]
        return f"h_{hash_val}"

    def _detect_bot(self, user_agent: str) -> tuple:
        """Detect if User-Agent indicates a bot"""
        ua_lower = user_agent.lower()

        bots = {
            'googlebot': 'Googlebot',
            'bingbot': 'Bingbot',
            'slurp': 'Yahoo Slurp',
            'duckduckbot': 'DuckDuckBot',
            'baiduspider': 'Baiduspider',
            'yandexbot': 'YandexBot',
            'python-requests': 'Python Requests',
            'curl': 'cURL',
            'wget': 'Wget',
            'scrapy': 'Scrapy',
            'selenium': 'Selenium',
            'puppeteer': 'Puppeteer',
            'bot': 'Generic Bot'
        }

        for bot_sig, bot_name in bots.items():
            if bot_sig in ua_lower:
                return True, bot_name

        return False, None

    def _parse_user_agent(self, user_agent: str) -> tuple:
        """Parse browser and OS from User-Agent"""
        ua = user_agent

        # Detect browser
        if 'Chrome' in ua:
            browser = 'Chrome'
        elif 'Firefox' in ua:
            browser = 'Firefox'
        elif 'Safari' in ua and 'Chrome' not in ua:
            browser = 'Safari'
        elif 'Edge' in ua:
            browser = 'Edge'
        elif 'MSIE' in ua or 'Trident' in ua:
            browser = 'Internet Explorer'
        else:
            browser = 'Unknown'

        # Detect OS
        if 'Windows' in ua:
            os_name = 'Windows'
        elif 'Macintosh' in ua or 'Mac OS' in ua:
            os_name = 'macOS'
        elif 'Linux' in ua:
            os_name = 'Linux'
        elif 'Android' in ua:
            os_name = 'Android'
        elif 'iOS' in ua or 'iPhone' in ua or 'iPad' in ua:
            os_name = 'iOS'
        else:
            os_name = 'Unknown'

        return browser, os_name

    def _calculate_security_score(self, headers: Dict[str, str], is_bot: bool) -> int:
        """Calculate security score"""
        score = 70  # Base score

        # Bots are typically lower trust
        if is_bot:
            score -= 30

        # Missing common headers is suspicious
        if not headers.get('Accept'):
            score -= 10
        if not headers.get('Accept-Language'):
            score -= 5

        # Very short User-Agent is suspicious
        if len(headers.get('User-Agent', '')) < 20:
            score -= 15

        return max(0, min(100, score))

    def _detect_anomalies(self, headers: Dict[str, str]) -> List[str]:
        """Detect header anomalies"""
        anomalies = []

        ua = headers.get('User-Agent', '')

        if not ua:
            anomalies.append("Missing User-Agent header")

        if 'sqlmap' in ua.lower() or 'nikto' in ua.lower():
            anomalies.append("Security scanner detected")

        if len(ua) > 500:
            anomalies.append("Unusually long User-Agent")

        return anomalies


class DNS4TCP(DNS4Analyzer):
    """DNS4-TCP: TCP/IP Stack Fingerprinting"""

    def analyze(self, target: str, port: int = 80) -> Dict[str, Any]:
        """Fingerprint TCP/IP stack for OS detection"""
        self.log(f"Analyzing TCP stack on {target}:{port}...")

        try:
            # Basic TCP connection with socket options analysis
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            start_time = time.time()
            sock.connect((target, port))
            latency = (time.time() - start_time) * 1000

            # Get socket options (limited without raw sockets)
            # This is a simplified version - full p0f requires packet capture

            fingerprint = self._generate_fingerprint(target, port)

            # Attempt basic OS detection via heuristics
            os_guess, confidence = self._guess_os(latency, port)

            sock.close()

            return {
                "fingerprint": fingerprint,
                "os": os_guess,
                "os_confidence": confidence,
                "device_type": "server" if port in [80, 443, 22, 25] else "unknown",
                "latency_ms": round(latency, 2),
                "spoofing_detected": False,  # Would require deep packet inspection
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            self.log(f"Error analyzing TCP: {e}")
            return {
                "error": str(e),
                "fingerprint": None,
                "os": "Unknown",
                "os_confidence": 0,
                "timestamp": datetime.now().isoformat()
            }

    def _generate_fingerprint(self, target: str, port: int) -> str:
        """Generate DNS4-TCP fingerprint"""
        fp_str = f"{target}:{port}"
        hash_val = hashlib.sha256(fp_str.encode()).hexdigest()[:16]
        return f"tcp_{hash_val}"

    def _guess_os(self, latency: float, port: int) -> tuple:
        """Basic OS guessing (simplified)"""
        # This is extremely basic - real OS detection requires packet analysis
        # Using p0f or nmap would be much more accurate

        if port == 22:
            return "Linux (SSH server)", 60
        elif port == 3389:
            return "Windows (RDP)", 70
        elif port in [80, 443]:
            if latency < 5:
                return "Linux (Nearby server)", 40
            else:
                return "Unknown Server", 30
        else:
            return "Unknown", 20


class DNS4LAT(DNS4Analyzer):
    """DNS4-LAT: Latency Analysis for VPN/Proxy Detection"""

    def analyze(self, target: str, source_ip: str, claimed_location: Optional[Dict] = None) -> Dict[str, Any]:
        """Analyze latency patterns to detect VPN/proxy"""
        self.log(f"Analyzing latency to {target} from {source_ip}...")

        try:
            # Measure latency
            latency = self._measure_latency(target)

            # Estimate expected latency (simplified - would use GeoIP in production)
            expected_latency = self._estimate_latency(source_ip, target, claimed_location)

            # Calculate delta
            delta = abs(latency - expected_latency)

            # Detect VPN/proxy
            vpn_detected = delta > 100  # More than 100ms difference is suspicious
            vpn_confidence = min(100, int((delta / 100) * 100))

            # Geographic mismatch (simplified)
            geographic_mismatch = claimed_location is not None and delta > 150

            fingerprint = self._generate_fingerprint(latency, source_ip)

            return {
                "fingerprint": fingerprint,
                "latency_ms": round(latency, 2),
                "expected_latency_ms": round(expected_latency, 2),
                "latency_delta_ms": round(delta, 2),
                "vpn_detected": vpn_detected,
                "vpn_confidence": vpn_confidence if vpn_detected else 0,
                "proxy_detected": vpn_detected,  # Simplified
                "geographic_mismatch": geographic_mismatch,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            self.log(f"Error analyzing latency: {e}")
            return {
                "error": str(e),
                "fingerprint": None,
                "timestamp": datetime.now().isoformat()
            }

    def _measure_latency(self, target: str) -> float:
        """Measure TCP latency to target"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            start = time.time()
            sock.connect((target, 443))
            latency = (time.time() - start) * 1000
            sock.close()

            return latency
        except:
            return 9999.0  # Timeout value

    def _estimate_latency(self, source_ip: str, target: str, claimed_location: Optional[Dict]) -> float:
        """Estimate expected latency (simplified)"""
        # In production, this would use GeoIP to calculate distance and estimate latency
        # For now, use a simple heuristic
        return 50.0  # Assume 50ms baseline

    def _generate_fingerprint(self, latency: float, source_ip: str) -> str:
        """Generate DNS4-LAT fingerprint"""
        fp_str = f"{source_ip}:{latency}"
        hash_val = hashlib.sha256(fp_str.encode()).hexdigest()[:16]
        return f"lat_{hash_val}"


class DNS4Suite:
    """Unified DNS4 analysis suite"""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.tls = DNS4TLS(verbose)
        self.http = DNS4HTTP(verbose)
        self.tcp = DNS4TCP(verbose)
        self.lat = DNS4LAT(verbose)

    def analyze(self, domain: str, methods: List[str] = None) -> Dict[str, Any]:
        """Run comprehensive analysis"""
        if methods is None:
            methods = ['tls', 'tcp']

        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "methods": methods
        }

        if 'tls' in methods:
            results['dns4_tls'] = self.tls.analyze(domain)

        if 'tcp' in methods:
            results['dns4_tcp'] = self.tcp.analyze(domain)

        # Calculate overall risk score
        risk_score = self._calculate_risk_score(results)
        results['threat_summary'] = {
            "risk_score": risk_score,
            "is_malicious": risk_score > 70
        }

        return results

    def _calculate_risk_score(self, results: Dict) -> int:
        """Calculate overall risk score"""
        scores = []

        if 'dns4_tls' in results:
            scores.append(100 - results['dns4_tls'].get('security_score', 50))

        if 'dns4_http' in results:
            scores.append(100 - results['dns4_http'].get('security_score', 50))

        if scores:
            return int(sum(scores) / len(scores))
        return 50


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='DNS4 Network Fingerprinting Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--json', action='store_true', help='JSON output')

    subparsers = parser.add_subparsers(dest='command', help='DNS4 command')

    # TLS command
    tls_parser = subparsers.add_parser('tls', help='TLS server fingerprinting')
    tls_parser.add_argument('target', help='Target domain or IP')
    tls_parser.add_argument('--port', type=int, default=443, help='Port (default: 443)')
    tls_parser.add_argument('--sni', help='SNI hostname')

    # HTTP command
    http_parser = subparsers.add_parser('http', help='HTTP header fingerprinting')
    http_parser.add_argument('--user-agent', help='User-Agent header')
    http_parser.add_argument('--headers-file', help='JSON file with headers')

    # TCP command
    tcp_parser = subparsers.add_parser('tcp', help='TCP/IP stack fingerprinting')
    tcp_parser.add_argument('target', help='Target domain or IP')
    tcp_parser.add_argument('--port', type=int, default=80, help='Port (default: 80)')

    # LAT command
    lat_parser = subparsers.add_parser('lat', help='Latency analysis (VPN/proxy detection)')
    lat_parser.add_argument('target', help='Target domain')
    lat_parser.add_argument('--source-ip', required=True, help='Source IP address')
    lat_parser.add_argument('--country', help='Claimed country')
    lat_parser.add_argument('--city', help='Claimed city')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Comprehensive analysis')
    analyze_parser.add_argument('domain', help='Target domain')
    analyze_parser.add_argument('--methods', default='tls,tcp', help='Comma-separated methods')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Execute command
    suite = DNS4Suite(verbose=args.verbose)
    result = None

    try:
        if args.command == 'tls':
            result = suite.tls.analyze(args.target, args.port, args.sni)

        elif args.command == 'http':
            if args.headers_file:
                with open(args.headers_file, 'r') as f:
                    headers = json.load(f)
            elif args.user_agent:
                headers = {'User-Agent': args.user_agent}
            else:
                print("Error: Provide --user-agent or --headers-file", file=sys.stderr)
                sys.exit(1)
            result = suite.http.analyze(headers)

        elif args.command == 'tcp':
            result = suite.tcp.analyze(args.target, args.port)

        elif args.command == 'lat':
            claimed_loc = None
            if args.country or args.city:
                claimed_loc = {}
                if args.country:
                    claimed_loc['country'] = args.country
                if args.city:
                    claimed_loc['city'] = args.city
            result = suite.lat.analyze(args.target, args.source_ip, claimed_loc)

        elif args.command == 'analyze':
            methods = args.methods.split(',')
            result = suite.analyze(args.domain, methods)

        # Output results
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_formatted_result(args.command, result)

    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def print_formatted_result(command: str, result: Dict):
    """Print formatted result"""
    print(f"\n=== DNS4-{command.upper()} Analysis ===")

    if 'error' in result:
        print(f"❌ Error: {result['error']}")
        return

    # Print key fields
    for key, value in result.items():
        if isinstance(value, dict):
            print(f"\n{key.replace('_', ' ').title()}:")
            for k, v in value.items():
                print(f"  {k}: {v}")
        elif isinstance(value, list):
            if value:
                print(f"{key.replace('_', ' ').title()}:")
                for item in value:
                    print(f"  • {item}")
        else:
            print(f"{key.replace('_', ' ').title()}: {value}")


if __name__ == '__main__':
    main()
