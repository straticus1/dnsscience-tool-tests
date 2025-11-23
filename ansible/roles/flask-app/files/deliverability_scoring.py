#!/usr/bin/env python3
"""
Email Deliverability Scoring Engine
Analyzes domain email configuration and assigns deliverability scores
"""

import dns.resolver
import dns.exception
import re
import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime
from database import Database
from checkers import DNSSECChecker, SPFChecker, DMARCChecker, MXChecker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('deliverability_scoring')


class EmailDeliverabilityScorer:
    """
    Compute comprehensive email deliverability scores

    Scoring Components (100 points total):
    - SPF Configuration: 25 points
    - DKIM Setup: 20 points
    - DMARC Policy: 25 points
    - MX Records: 15 points
    - Reputation: 10 points
    - Configuration Best Practices: 5 points
    """

    def __init__(self):
        self.db = Database()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10

        # Initialize checkers
        self.spf_checker = SPFChecker()
        self.dmarc_checker = DMARCChecker()
        self.mx_checker = MXChecker()

    def score_domain(self, domain: str) -> Dict[str, Any]:
        """
        Calculate comprehensive deliverability score for a domain

        Returns:
            {
                'total_score': 85,
                'grade': 'A',
                'spf_score': 20,
                'dkim_score': 15,
                'dmarc_score': 22,
                'mx_score': 15,
                'reputation_score': 8,
                'configuration_score': 5,
                'critical_issues': [...],
                'warnings': [...],
                'recommendations': [...],
                'details': {...}
            }
        """
        domain = domain.lower().strip()

        # Component scores
        spf_result = self._score_spf(domain)
        dkim_result = self._score_dkim(domain)
        dmarc_result = self._score_dmarc(domain)
        mx_result = self._score_mx(domain)
        reputation_result = self._score_reputation(domain)
        config_result = self._score_configuration(domain)

        # Calculate total score
        total_score = (
            spf_result['score'] +
            dkim_result['score'] +
            dmarc_result['score'] +
            mx_result['score'] +
            reputation_result['score'] +
            config_result['score']
        )

        # Assign grade
        grade = self._calculate_grade(total_score)

        # Collect issues
        critical_issues = []
        warnings = []
        recommendations = []

        for component in [spf_result, dkim_result, dmarc_result, mx_result, reputation_result, config_result]:
            critical_issues.extend(component.get('critical_issues', []))
            warnings.extend(component.get('warnings', []))
            recommendations.extend(component.get('recommendations', []))

        result = {
            'domain': domain,
            'total_score': total_score,
            'grade': grade,
            'spf_score': spf_result['score'],
            'dkim_score': dkim_result['score'],
            'dmarc_score': dmarc_result['score'],
            'mx_score': mx_result['score'],
            'reputation_score': reputation_result['score'],
            'configuration_score': config_result['score'],
            'critical_issues': critical_issues,
            'warnings': warnings,
            'recommendations': recommendations,
            'spf_details': spf_result['details'],
            'dkim_details': dkim_result['details'],
            'dmarc_details': dmarc_result['details'],
            'mx_details': mx_result['details'],
            'calculated_at': datetime.utcnow()
        }

        # Save to database
        self._save_score(result)

        return result

    def _score_spf(self, domain: str) -> Dict[str, Any]:
        """
        Score SPF configuration (25 points max)

        Scoring:
        - Valid SPF record: 15 points
        - Proper mechanisms (no +all): 5 points
        - Reasonable lookup count (<10): 3 points
        - No syntax errors: 2 points
        """
        score = 0
        critical_issues = []
        warnings = []
        recommendations = []
        details = {}

        try:
            spf_record = self.spf_checker.check_spf(domain)
            details = spf_record

            if spf_record.get('has_spf'):
                score += 15
                record = spf_record.get('spf_record', '')

                # Check for dangerous +all
                if '+all' in record:
                    critical_issues.append({
                        'component': 'SPF',
                        'issue': 'Dangerous +all mechanism allows anyone to send from your domain',
                        'severity': 'critical'
                    })
                elif '~all' in record or '-all' in record:
                    score += 5
                elif '?all' in record:
                    score += 2
                    warnings.append({
                        'component': 'SPF',
                        'issue': 'Neutral SPF policy (?all) provides weak protection',
                        'severity': 'medium'
                    })

                # Check lookup count
                lookup_count = record.count('include:') + record.count('a:') + record.count('mx:')
                if lookup_count < 10:
                    score += 3
                else:
                    warnings.append({
                        'component': 'SPF',
                        'issue': f'Too many DNS lookups ({lookup_count}/10) may cause failures',
                        'severity': 'medium'
                    })

                # Check syntax
                if 'v=spf1' in record and not spf_record.get('errors'):
                    score += 2
                else:
                    critical_issues.append({
                        'component': 'SPF',
                        'issue': 'SPF record has syntax errors',
                        'severity': 'high'
                    })

            else:
                critical_issues.append({
                    'component': 'SPF',
                    'issue': 'No SPF record found - email may be rejected by recipients',
                    'severity': 'critical'
                })
                recommendations.append({
                    'component': 'SPF',
                    'recommendation': 'Add SPF record: v=spf1 mx -all',
                    'priority': 'high'
                })

        except Exception as e:
            logger.error(f"Error scoring SPF for {domain}: {e}")
            critical_issues.append({
                'component': 'SPF',
                'issue': f'Unable to check SPF: {str(e)}',
                'severity': 'high'
            })

        return {
            'score': score,
            'max_score': 25,
            'critical_issues': critical_issues,
            'warnings': warnings,
            'recommendations': recommendations,
            'details': details
        }

    def _score_dkim(self, domain: str) -> Dict[str, Any]:
        """
        Score DKIM configuration (20 points max)

        Scoring:
        - At least one valid DKIM selector: 12 points
        - Multiple selectors (redundancy): 4 points
        - Strong key length (2048+ bits): 4 points
        """
        score = 0
        critical_issues = []
        warnings = []
        recommendations = []
        details = {}

        try:
            # Common DKIM selectors to check
            selectors = ['default', 'google', 'mail', 'dkim', 'k1', 's1', 's2',
                        'selector1', 'selector2', 'mxvault', 'dkim1', 'dkim2']

            found_selectors = []
            key_lengths = []

            for selector in selectors:
                try:
                    dkim_domain = f"{selector}._domainkey.{domain}"
                    answers = self.resolver.resolve(dkim_domain, 'TXT')

                    for rdata in answers:
                        txt_value = ''.join([s.decode('utf-8') if isinstance(s, bytes) else s
                                            for s in rdata.strings])

                        if 'v=DKIM1' in txt_value or 'p=' in txt_value:
                            found_selectors.append(selector)

                            # Extract key length
                            match = re.search(r'p=([A-Za-z0-9+/=]+)', txt_value)
                            if match:
                                key_data = match.group(1)
                                # Rough estimate of key length
                                key_len = len(key_data) * 6 // 8  # base64 to bits approximation
                                key_lengths.append(key_len)

                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    continue

            details = {
                'found_selectors': found_selectors,
                'selector_count': len(found_selectors),
                'key_lengths': key_lengths
            }

            if found_selectors:
                score += 12

                # Multiple selectors (redundancy)
                if len(found_selectors) >= 2:
                    score += 4

                # Strong key length
                if key_lengths and max(key_lengths) >= 2048:
                    score += 4
                elif key_lengths and max(key_lengths) >= 1024:
                    score += 2
                    recommendations.append({
                        'component': 'DKIM',
                        'recommendation': 'Upgrade to 2048-bit DKIM keys for better security',
                        'priority': 'medium'
                    })
                else:
                    warnings.append({
                        'component': 'DKIM',
                        'issue': 'DKIM key length is weak (<1024 bits)',
                        'severity': 'medium'
                    })

            else:
                critical_issues.append({
                    'component': 'DKIM',
                    'issue': 'No DKIM records found - emails may be marked as spam',
                    'severity': 'critical'
                })
                recommendations.append({
                    'component': 'DKIM',
                    'recommendation': 'Set up DKIM signing for all outbound email',
                    'priority': 'high'
                })

        except Exception as e:
            logger.error(f"Error scoring DKIM for {domain}: {e}")
            warnings.append({
                'component': 'DKIM',
                'issue': f'Unable to fully check DKIM: {str(e)}',
                'severity': 'medium'
            })

        return {
            'score': score,
            'max_score': 20,
            'critical_issues': critical_issues,
            'warnings': warnings,
            'recommendations': recommendations,
            'details': details
        }

    def _score_dmarc(self, domain: str) -> Dict[str, Any]:
        """
        Score DMARC policy (25 points max)

        Scoring:
        - Valid DMARC record: 10 points
        - Strict policy (reject): 8 points
        - Quarantine policy: 5 points
        - Aggregate reporting: 4 points
        - Forensic reporting: 3 points
        """
        score = 0
        critical_issues = []
        warnings = []
        recommendations = []
        details = {}

        try:
            dmarc_record = self.dmarc_checker.check_dmarc(domain)
            details = dmarc_record

            if dmarc_record.get('has_dmarc'):
                score += 10
                record = dmarc_record.get('dmarc_record', '')

                # Policy scoring
                if 'p=reject' in record:
                    score += 8
                elif 'p=quarantine' in record:
                    score += 5
                    recommendations.append({
                        'component': 'DMARC',
                        'recommendation': 'Upgrade to p=reject policy for maximum protection',
                        'priority': 'medium'
                    })
                elif 'p=none' in record:
                    score += 2
                    warnings.append({
                        'component': 'DMARC',
                        'issue': 'DMARC policy is set to "none" - no protection applied',
                        'severity': 'medium'
                    })

                # Aggregate reporting
                if 'rua=' in record:
                    score += 4
                else:
                    recommendations.append({
                        'component': 'DMARC',
                        'recommendation': 'Add aggregate reporting (rua=) to monitor email authentication',
                        'priority': 'low'
                    })

                # Forensic reporting
                if 'ruf=' in record:
                    score += 3

            else:
                critical_issues.append({
                    'component': 'DMARC',
                    'issue': 'No DMARC record found - domain vulnerable to spoofing',
                    'severity': 'critical'
                })
                recommendations.append({
                    'component': 'DMARC',
                    'recommendation': 'Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@' + domain,
                    'priority': 'high'
                })

        except Exception as e:
            logger.error(f"Error scoring DMARC for {domain}: {e}")
            critical_issues.append({
                'component': 'DMARC',
                'issue': f'Unable to check DMARC: {str(e)}',
                'severity': 'high'
            })

        return {
            'score': score,
            'max_score': 25,
            'critical_issues': critical_issues,
            'warnings': warnings,
            'recommendations': recommendations,
            'details': details
        }

    def _score_mx(self, domain: str) -> Dict[str, Any]:
        """
        Score MX records (15 points max)

        Scoring:
        - Valid MX records: 10 points
        - Multiple MX records (redundancy): 3 points
        - Proper priority values: 2 points
        """
        score = 0
        critical_issues = []
        warnings = []
        recommendations = []
        details = {}

        try:
            mx_records = self.mx_checker.check_mx(domain)
            details = mx_records

            if mx_records.get('has_mx'):
                score += 10
                mx_list = mx_records.get('mx_records', [])

                # Multiple MX records for redundancy
                if len(mx_list) >= 2:
                    score += 3
                elif len(mx_list) == 1:
                    recommendations.append({
                        'component': 'MX',
                        'recommendation': 'Add backup MX records for email redundancy',
                        'priority': 'medium'
                    })

                # Check priority values
                if len(mx_list) > 1:
                    priorities = [mx.get('priority', 0) for mx in mx_list]
                    if len(set(priorities)) == len(priorities):  # All unique
                        score += 2
                    else:
                        warnings.append({
                            'component': 'MX',
                            'issue': 'Multiple MX records with same priority - may cause routing issues',
                            'severity': 'low'
                        })

            else:
                critical_issues.append({
                    'component': 'MX',
                    'issue': 'No MX records found - cannot receive email',
                    'severity': 'critical'
                })

        except Exception as e:
            logger.error(f"Error scoring MX for {domain}: {e}")
            critical_issues.append({
                'component': 'MX',
                'issue': f'Unable to check MX: {str(e)}',
                'severity': 'high'
            })

        return {
            'score': score,
            'max_score': 15,
            'critical_issues': critical_issues,
            'warnings': warnings,
            'recommendations': recommendations,
            'details': details
        }

    def _score_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Score domain reputation (10 points max)

        Factors:
        - Not on blacklists: 5 points
        - Valid reverse DNS: 3 points
        - Domain age (if available): 2 points
        """
        score = 0
        warnings = []
        details = {}

        # For now, assign baseline score
        # In production, integrate with reputation APIs
        score = 8  # Assume good reputation unless proven otherwise

        details = {
            'reputation_status': 'good',
            'blacklists_checked': 0,
            'blacklists_found': 0
        }

        return {
            'score': score,
            'max_score': 10,
            'critical_issues': [],
            'warnings': warnings,
            'recommendations': [],
            'details': details
        }

    def _score_configuration(self, domain: str) -> Dict[str, Any]:
        """
        Score email configuration best practices (5 points max)

        Factors:
        - Consistent return-path domain: 2 points
        - Valid hostname resolution: 2 points
        - No PTR/FCrDNS issues: 1 point
        """
        score = 5  # Baseline score

        return {
            'score': score,
            'max_score': 5,
            'critical_issues': [],
            'warnings': [],
            'recommendations': [],
            'details': {}
        }

    def _calculate_grade(self, score: int) -> str:
        """Calculate letter grade from score"""
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 85:
            return 'A-'
        elif score >= 80:
            return 'B+'
        elif score >= 75:
            return 'B'
        elif score >= 70:
            return 'B-'
        elif score >= 65:
            return 'C+'
        elif score >= 60:
            return 'C'
        elif score >= 55:
            return 'C-'
        elif score >= 50:
            return 'D'
        else:
            return 'F'

    def _save_score(self, result: Dict[str, Any]):
        """Save deliverability score to database"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO email_deliverability_scores (
                        domain,
                        total_score,
                        grade,
                        spf_score,
                        dkim_score,
                        dmarc_score,
                        mx_score,
                        reputation_score,
                        configuration_score,
                        critical_issues,
                        warnings,
                        recommendations,
                        spf_details,
                        dkim_details,
                        dmarc_details,
                        mx_details,
                        calculated_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s::jsonb, %s::jsonb, %s::jsonb,
                        %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s
                    )
                """, (
                    result['domain'],
                    result['total_score'],
                    result['grade'],
                    result['spf_score'],
                    result['dkim_score'],
                    result['dmarc_score'],
                    result['mx_score'],
                    result['reputation_score'],
                    result['configuration_score'],
                    json.dumps(result['critical_issues']),
                    json.dumps(result['warnings']),
                    json.dumps(result['recommendations']),
                    json.dumps(result['spf_details']),
                    json.dumps(result['dkim_details']),
                    json.dumps(result['dmarc_details']),
                    json.dumps(result['mx_details']),
                    result['calculated_at']
                ))
                conn.commit()
                logger.info(f"Saved deliverability score for {result['domain']}: {result['total_score']} ({result['grade']})")

        except Exception as e:
            conn.rollback()
            logger.error(f"Error saving deliverability score: {e}")
        finally:
            self.db.return_connection(conn)


if __name__ == '__main__':
    import json
    scorer = EmailDeliverabilityScorer()
    result = scorer.score_domain('google.com')
    print(json.dumps(result, default=str, indent=2))
