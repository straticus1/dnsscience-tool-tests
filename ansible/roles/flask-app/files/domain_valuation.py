"""
Domain Valuation Engine - DNS Science
Provides domain value estimation based on multiple factors.
"""

import re
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional


class DomainValuationEngine:
    """
    Calculate domain value estimates based on various factors:
    - Domain length and structure
    - TLD premium (.com, .net, etc)
    - Domain age (from WHOIS if available)
    - Activity indicators (SSL, email records, DNSSEC)
    - Keyword quality (dictionary words, brandability)
    """

    # TLD premium multipliers (relative value)
    TLD_MULTIPLIERS = {
        'com': 10.0,
        'net': 6.0,
        'org': 5.0,
        'io': 7.0,
        'ai': 8.0,
        'co': 6.5,
        'app': 5.5,
        'dev': 5.5,
        'tech': 4.0,
        'online': 3.0,
        'site': 2.5,
        'xyz': 2.0,
        'info': 2.0,
        'biz': 2.0,
    }

    # Common dictionary words (starter set - can be expanded)
    PREMIUM_KEYWORDS = {
        'app', 'web', 'shop', 'store', 'market', 'cloud', 'data', 'tech',
        'digital', 'smart', 'auto', 'health', 'fitness', 'food', 'travel',
        'money', 'finance', 'crypto', 'blockchain', 'ai', 'learn', 'edu',
        'news', 'media', 'social', 'game', 'play', 'music', 'video', 'photo',
        'design', 'art', 'style', 'fashion', 'beauty', 'home', 'real', 'estate'
    }

    # High-value short words
    HIGH_VALUE_WORDS = {
        'pay', 'buy', 'sell', 'get', 'go', 'car', 'fly', 'run', 'bet',
        'bet', 'loan', 'cash', 'bank', 'code', 'dev', 'api', 'hub', 'lab'
    }

    def __init__(self):
        """Initialize valuation engine"""
        pass

    def calculate_length_score(self, domain_without_tld: str) -> Tuple[int, Dict]:
        """
        Score based on domain length (without TLD).
        Premium: 3-5 characters
        Good: 6-8 characters
        Average: 9-12 characters
        Long: 13+ characters

        Returns: (score 0-100, details dict)
        """
        length = len(domain_without_tld)
        details = {'length': length}

        if length <= 2:
            # Ultra premium (2 char domains)
            score = 100
            details['quality'] = 'ultra_premium'
        elif length <= 5:
            # Premium short domains
            score = 95
            details['quality'] = 'premium'
        elif length <= 8:
            # Good length
            score = 80
            details['quality'] = 'good'
        elif length <= 12:
            # Average
            score = 60
            details['quality'] = 'average'
        elif length <= 15:
            # Below average
            score = 40
            details['quality'] = 'below_average'
        else:
            # Too long
            score = 20
            details['quality'] = 'long'

        # Penalty for hyphens (reduces brandability)
        if '-' in domain_without_tld:
            hyphen_count = domain_without_tld.count('-')
            score = max(0, score - (hyphen_count * 15))
            details['has_hyphens'] = True
            details['hyphen_penalty'] = hyphen_count * 15

        # Penalty for numbers (reduces brandability, unless it's a pure number domain)
        if any(char.isdigit() for char in domain_without_tld):
            if domain_without_tld.isdigit():
                # Pure number domains can be valuable
                details['is_numeric'] = True
            else:
                # Mixed alphanumeric is less valuable
                score = max(0, score - 20)
                details['has_numbers'] = True
                details['number_penalty'] = 20

        return score, details

    def calculate_tld_score(self, tld: str) -> Tuple[int, Dict]:
        """
        Score based on TLD premium.
        .com is most valuable, others scaled accordingly.

        Returns: (score 0-100, details dict)
        """
        tld_lower = tld.lower()
        multiplier = self.TLD_MULTIPLIERS.get(tld_lower, 1.0)

        # Convert multiplier to 0-100 scale (.com = 100)
        score = int((multiplier / 10.0) * 100)
        score = min(100, score)

        details = {
            'tld': tld_lower,
            'multiplier': multiplier,
            'is_premium_tld': multiplier >= 6.0
        }

        return score, details

    def calculate_age_score(self, domain_age_years: Optional[float]) -> Tuple[int, Dict]:
        """
        Score based on domain age.
        Older domains are more established and valuable.

        Returns: (score 0-100, details dict)
        """
        if domain_age_years is None:
            return 50, {'age_years': None, 'note': 'age_unknown'}

        # Scale: 10+ years = 100, 5 years = 75, 1 year = 50, new = 30
        if domain_age_years >= 10:
            score = 100
            quality = 'established'
        elif domain_age_years >= 5:
            score = 75 + int((domain_age_years - 5) * 5)
            quality = 'mature'
        elif domain_age_years >= 2:
            score = 60 + int((domain_age_years - 2) * 5)
            quality = 'moderate'
        elif domain_age_years >= 1:
            score = 50 + int((domain_age_years - 1) * 10)
            quality = 'recent'
        else:
            score = 30 + int(domain_age_years * 20)
            quality = 'new'

        details = {
            'age_years': round(domain_age_years, 2),
            'quality': quality
        }

        return score, details

    def calculate_activity_score(self, scan_data: Optional[Dict]) -> Tuple[int, Dict]:
        """
        Score based on activity indicators:
        - SSL certificate present
        - Email records (SPF, DMARC)
        - DNSSEC enabled
        - Active DNS records

        Returns: (score 0-100, details dict)
        """
        if not scan_data:
            return 30, {'note': 'no_scan_data'}

        score = 0
        details = {}

        # SSL certificate (+30 points)
        if scan_data.get('has_ssl') or scan_data.get('ssl_certificate'):
            score += 30
            details['has_ssl'] = True

        # Email records (+25 points)
        if scan_data.get('spf_record') or scan_data.get('dmarc_record'):
            score += 25
            details['has_email_records'] = True

        # DNSSEC (+20 points)
        if scan_data.get('dnssec_enabled'):
            score += 20
            details['has_dnssec'] = True

        # Multiple DNS records indicate active use (+15 points)
        dns_records = scan_data.get('dns_records', {})
        if isinstance(dns_records, dict) and len(dns_records) > 3:
            score += 15
            details['has_multiple_dns_records'] = True

        # Professional email setup (MTA-STS, DKIM) (+10 points)
        if scan_data.get('mta_sts_enabled') or scan_data.get('dkim_valid'):
            score += 10
            details['has_advanced_email'] = True

        details['total_activity_score'] = score
        return min(100, score), details

    def calculate_keyword_score(self, domain_without_tld: str) -> Tuple[int, Dict]:
        """
        Score based on keyword quality and brandability.
        - Dictionary words
        - Premium keywords
        - Pronounceability
        - Pattern matching

        Returns: (score 0-100, details dict)
        """
        domain_lower = domain_without_tld.lower().replace('-', '')
        score = 50  # Base score
        details = {'keywords': []}

        # Check for premium keywords
        premium_found = []
        for keyword in self.PREMIUM_KEYWORDS:
            if keyword in domain_lower:
                premium_found.append(keyword)
                score += 10

        if premium_found:
            details['premium_keywords'] = premium_found

        # Check for high-value short words
        high_value_found = []
        for word in self.HIGH_VALUE_WORDS:
            if word == domain_lower or domain_lower.startswith(word) or domain_lower.endswith(word):
                high_value_found.append(word)
                score += 15

        if high_value_found:
            details['high_value_words'] = high_value_found

        # Pronounceability (good vowel/consonant ratio)
        vowels = sum(1 for c in domain_lower if c in 'aeiou')
        consonants = sum(1 for c in domain_lower if c.isalpha() and c not in 'aeiou')

        if len(domain_lower) > 0:
            vowel_ratio = vowels / len(domain_lower)
            if 0.3 <= vowel_ratio <= 0.5:
                score += 10
                details['good_pronounceability'] = True

        # Pattern bonuses
        # Repeating patterns (e.g., "papa", "bobo")
        if len(domain_lower) >= 4:
            half = len(domain_lower) // 2
            if domain_lower[:half] == domain_lower[half:2*half]:
                score += 15
                details['repeating_pattern'] = True

        # Alliteration bonus (same starting letters)
        if '-' in domain_without_tld:
            parts = domain_without_tld.lower().split('-')
            if len(parts) == 2 and parts[0][0] == parts[1][0]:
                score += 10
                details['alliteration'] = True

        return min(100, score), details

    def estimate_value(
        self,
        domain_name: str,
        domain_age_years: Optional[float] = None,
        scan_data: Optional[Dict] = None
    ) -> Dict:
        """
        Calculate comprehensive domain valuation.

        Args:
            domain_name: Full domain name (e.g., "example.com")
            domain_age_years: Domain age in years (optional)
            scan_data: Dictionary with scan results (optional)

        Returns:
            Dictionary with valuation details:
            {
                'domain_name': str,
                'estimated_value_low': float,
                'estimated_value_mid': float,
                'estimated_value_high': float,
                'overall_score': int,
                'scores': {...},
                'factors': {...}
            }
        """
        # Parse domain
        parts = domain_name.lower().split('.')
        if len(parts) < 2:
            raise ValueError("Invalid domain name format")

        tld = parts[-1]
        domain_without_tld = '.'.join(parts[:-1])

        # Calculate individual scores
        length_score, length_details = self.calculate_length_score(domain_without_tld)
        tld_score, tld_details = self.calculate_tld_score(tld)
        age_score, age_details = self.calculate_age_score(domain_age_years)
        activity_score, activity_details = self.calculate_activity_score(scan_data)
        keyword_score, keyword_details = self.calculate_keyword_score(domain_without_tld)

        # Calculate weighted overall score
        weights = {
            'length': 0.25,
            'tld': 0.25,
            'age': 0.15,
            'activity': 0.20,
            'keyword': 0.15
        }

        overall_score = int(
            length_score * weights['length'] +
            tld_score * weights['tld'] +
            age_score * weights['age'] +
            activity_score * weights['activity'] +
            keyword_score * weights['keyword']
        )

        # Estimate dollar value based on overall score
        # Base values for different score ranges
        if overall_score >= 90:
            base_value = 5000
            multiplier = 3.0
        elif overall_score >= 80:
            base_value = 2000
            multiplier = 2.5
        elif overall_score >= 70:
            base_value = 1000
            multiplier = 2.0
        elif overall_score >= 60:
            base_value = 500
            multiplier = 1.8
        elif overall_score >= 50:
            base_value = 250
            multiplier = 1.5
        else:
            base_value = 100
            multiplier = 1.2

        # Apply TLD multiplier to value
        tld_multiplier = tld_details['multiplier']
        estimated_mid = int(base_value * (overall_score / 70.0) * (tld_multiplier / 5.0))

        # Create range (±30% for low/high)
        estimated_low = int(estimated_mid * 0.7)
        estimated_high = int(estimated_mid * multiplier)

        return {
            'domain_name': domain_name,
            'estimated_value_low': estimated_low,
            'estimated_value_mid': estimated_mid,
            'estimated_value_high': estimated_high,
            'overall_score': overall_score,
            'scores': {
                'length_score': length_score,
                'tld_score': tld_score,
                'age_score': age_score,
                'activity_score': activity_score,
                'keyword_score': keyword_score
            },
            'factors': {
                'length_details': length_details,
                'tld_details': tld_details,
                'age_details': age_details,
                'activity_details': activity_details,
                'keyword_details': keyword_details
            },
            'valuation_method': 'internal_algorithm_v1',
            'algorithm_version': '1.0'
        }


# Example usage
if __name__ == '__main__':
    engine = DomainValuationEngine()

    # Test various domains
    test_domains = [
        ('example.com', None, None),
        ('shop.com', 15.0, {'has_ssl': True, 'spf_record': 'v=spf1...'}),
        ('my-long-domain-name.net', 2.0, None),
        ('ai.io', None, {'has_ssl': True, 'dnssec_enabled': True}),
        ('test123.xyz', 0.5, None),
    ]

    for domain, age, scan_data in test_domains:
        result = engine.estimate_value(domain, age, scan_data)
        print(f"\n{domain}:")
        print(f"  Value: ${result['estimated_value_low']:,} - ${result['estimated_value_high']:,} (mid: ${result['estimated_value_mid']:,})")
        print(f"  Overall Score: {result['overall_score']}/100")
        print(f"  Breakdown: Length={result['scores']['length_score']}, TLD={result['scores']['tld_score']}, " +
              f"Age={result['scores']['age_score']}, Activity={result['scores']['activity_score']}, " +
              f"Keywords={result['scores']['keyword_score']}")
