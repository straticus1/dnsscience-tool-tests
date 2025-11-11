#!/usr/bin/env python3
"""
Webhook Notifications for DNS Cache Validator
Supports Slack, Discord, Microsoft Teams, PagerDuty, and generic webhooks
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Optional


class WebhookNotifier:
    """Base class for webhook notifications"""

    def __init__(self, webhook_url: str):
        """
        Initialize webhook notifier.

        Args:
            webhook_url: URL of the webhook endpoint
        """
        self.webhook_url = webhook_url

    def send(self, payload: Dict) -> bool:
        """
        Send webhook notification.

        Args:
            payload: Payload to send

        Returns:
            True if successful, False otherwise
        """
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            return response.status_code in [200, 201, 202, 204]
        except Exception as e:
            print(f"Webhook error: {e}")
            return False


class SlackNotifier(WebhookNotifier):
    """Slack webhook notifier"""

    def notify_scan_complete(
        self,
        domain: str,
        analysis: Dict,
        results: List[Dict],
        status: str = 'success'
    ) -> bool:
        """
        Send scan completion notification to Slack.

        Args:
            domain: Domain that was scanned
            analysis: Analysis results
            results: Query results
            status: Scan status (success, warning, error)

        Returns:
            True if notification sent successfully
        """
        # Determine color based on status
        color_map = {
            'success': 'good',
            'warning': 'warning',
            'error': 'danger'
        }
        color = color_map.get(status, 'warning')

        # Build message
        success_rate = (analysis['successful'] / analysis['total_queries'] * 100) \
                       if analysis['total_queries'] > 0 else 0

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"DNS Scan Complete: {domain}",
                    "fields": [
                        {
                            "title": "Success Rate",
                            "value": f"{success_rate:.1f}% ({analysis['successful']}/{analysis['total_queries']})",
                            "short": True
                        },
                        {
                            "title": "Consistency Score",
                            "value": f"{analysis['consistency_score']:.1%}",
                            "short": True
                        },
                        {
                            "title": "Unique Answers",
                            "value": str(len(analysis['unique_answers'])),
                            "short": True
                        },
                        {
                            "title": "Avg Response Time",
                            "value": f"{analysis['avg_response_time']}ms",
                            "short": True
                        }
                    ],
                    "footer": "DNS Cache Validator",
                    "ts": int(datetime.utcnow().timestamp())
                }
            ]
        }

        return self.send(payload)

    def notify_consistency_alert(
        self,
        domain: str,
        consistency_score: float,
        unique_answers: Dict
    ) -> bool:
        """
        Send low consistency alert to Slack.

        Args:
            domain: Domain with consistency issues
            consistency_score: Consistency score (0-1)
            unique_answers: Unique answers found

        Returns:
            True if notification sent successfully
        """
        answers_list = "\n".join([
            f"• {answer} ({data['count']} resolvers)"
            for answer, data in sorted(
                unique_answers.items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )[:5]
        ])

        payload = {
            "attachments": [
                {
                    "color": "danger",
                    "title": f"⚠️ Low DNS Consistency Detected: {domain}",
                    "text": f"Consistency Score: *{consistency_score:.1%}*\n\n*Top Answers:*\n{answers_list}",
                    "footer": "DNS Cache Validator",
                    "ts": int(datetime.utcnow().timestamp())
                }
            ]
        }

        return self.send(payload)


class DiscordNotifier(WebhookNotifier):
    """Discord webhook notifier"""

    def notify_scan_complete(
        self,
        domain: str,
        analysis: Dict,
        results: List[Dict],
        status: str = 'success'
    ) -> bool:
        """
        Send scan completion notification to Discord.

        Args:
            domain: Domain that was scanned
            analysis: Analysis results
            results: Query results
            status: Scan status

        Returns:
            True if notification sent successfully
        """
        # Determine embed color
        color_map = {
            'success': 0x00FF00,  # Green
            'warning': 0xFFA500,  # Orange
            'error': 0xFF0000     # Red
        }
        color = color_map.get(status, 0xFFA500)

        success_rate = (analysis['successful'] / analysis['total_queries'] * 100) \
                       if analysis['total_queries'] > 0 else 0

        payload = {
            "embeds": [
                {
                    "title": f"DNS Scan Complete: {domain}",
                    "color": color,
                    "fields": [
                        {
                            "name": "Success Rate",
                            "value": f"{success_rate:.1f}% ({analysis['successful']}/{analysis['total_queries']})",
                            "inline": True
                        },
                        {
                            "name": "Consistency Score",
                            "value": f"{analysis['consistency_score']:.1%}",
                            "inline": True
                        },
                        {
                            "name": "Unique Answers",
                            "value": str(len(analysis['unique_answers'])),
                            "inline": True
                        },
                        {
                            "name": "Avg Response Time",
                            "value": f"{analysis['avg_response_time']}ms",
                            "inline": True
                        }
                    ],
                    "footer": {
                        "text": "DNS Cache Validator"
                    },
                    "timestamp": datetime.utcnow().isoformat()
                }
            ]
        }

        return self.send(payload)


class TeamsNotifier(WebhookNotifier):
    """Microsoft Teams webhook notifier"""

    def notify_scan_complete(
        self,
        domain: str,
        analysis: Dict,
        results: List[Dict],
        status: str = 'success'
    ) -> bool:
        """
        Send scan completion notification to Microsoft Teams.

        Args:
            domain: Domain that was scanned
            analysis: Analysis results
            results: Query results
            status: Scan status

        Returns:
            True if notification sent successfully
        """
        # Determine theme color
        color_map = {
            'success': '00FF00',
            'warning': 'FFA500',
            'error': 'FF0000'
        }
        theme_color = color_map.get(status, 'FFA500')

        success_rate = (analysis['successful'] / analysis['total_queries'] * 100) \
                       if analysis['total_queries'] > 0 else 0

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": theme_color,
            "title": f"DNS Scan Complete: {domain}",
            "sections": [
                {
                    "facts": [
                        {
                            "name": "Success Rate",
                            "value": f"{success_rate:.1f}% ({analysis['successful']}/{analysis['total_queries']})"
                        },
                        {
                            "name": "Consistency Score",
                            "value": f"{analysis['consistency_score']:.1%}"
                        },
                        {
                            "name": "Unique Answers",
                            "value": str(len(analysis['unique_answers']))
                        },
                        {
                            "name": "Avg Response Time",
                            "value": f"{analysis['avg_response_time']}ms"
                        }
                    ]
                }
            ]
        }

        return self.send(payload)


class PagerDutyNotifier:
    """PagerDuty Events API notifier"""

    def __init__(self, routing_key: str):
        """
        Initialize PagerDuty notifier.

        Args:
            routing_key: PagerDuty integration/routing key
        """
        self.routing_key = routing_key
        self.api_url = 'https://events.pagerduty.com/v2/enqueue'

    def trigger_alert(
        self,
        domain: str,
        severity: str,
        summary: str,
        details: Dict
    ) -> bool:
        """
        Trigger PagerDuty alert.

        Args:
            domain: Domain with issue
            severity: Alert severity (critical, error, warning, info)
            summary: Alert summary
            details: Additional details

        Returns:
            True if alert sent successfully
        """
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": summary,
                "severity": severity,
                "source": "dns-cache-validator",
                "custom_details": details
            }
        }

        try:
            response = requests.post(
                self.api_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            return response.status_code in [200, 201, 202]
        except Exception as e:
            print(f"PagerDuty error: {e}")
            return False

    def resolve_alert(self, dedup_key: str) -> bool:
        """
        Resolve a PagerDuty alert.

        Args:
            dedup_key: Deduplication key of the alert

        Returns:
            True if successful
        """
        payload = {
            "routing_key": self.routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key
        }

        try:
            response = requests.post(
                self.api_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            return response.status_code in [200, 201, 202]
        except Exception as e:
            print(f"PagerDuty error: {e}")
            return False


class GenericWebhook(WebhookNotifier):
    """Generic webhook notifier for custom integrations"""

    def notify(self, event_type: str, data: Dict) -> bool:
        """
        Send generic webhook notification.

        Args:
            event_type: Type of event
            data: Event data

        Returns:
            True if successful
        """
        payload = {
            "event": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }

        return self.send(payload)


# Example usage
if __name__ == '__main__':
    # Test webhook
    from dns_cache_validator import DNSCacheValidator

    # Example analysis data
    analysis = {
        'total_queries': 100,
        'successful': 95,
        'failed': 5,
        'consistency_score': 0.98,
        'unique_answers': {
            '93.184.216.34': {'count': 95},
            '93.184.216.35': {'count': 2}
        },
        'avg_response_time': 45.2
    }

    # Test Slack (replace with actual webhook URL)
    # slack = SlackNotifier('https://hooks.slack.com/services/YOUR/WEBHOOK/URL')
    # slack.notify_scan_complete('example.com', analysis, [], 'success')

    print("Webhook module loaded successfully")
    print("Configure webhook URLs to enable notifications")
