"""
DNS Science - Complete Email System with AWS SES
Handles all transactional and marketing emails
"""

import logging
import boto3
from botocore.exceptions import ClientError
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.utils import formataddr
import os

from config import Config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BrandedEmailTemplates:
    """All branded HTML email templates for DNS Science"""

    BRAND_COLORS = {
        'primary': '#667eea',
        'secondary': '#764ba2',
        'success': '#10b981',
        'danger': '#ef4444',
        'warning': '#f59e0b',
        'dark': '#1e293b',
        'light': '#f8fafc'
    }

    @staticmethod
    def _base_template(title: str, content: str) -> str:
        """Base template with DNS Science branding"""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f3f4f6;
        }}
        .email-container {{
            max-width: 600px;
            margin: 20px auto;
            background: #ffffff;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #ffffff;
            padding: 40px 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 28px;
            font-weight: 700;
        }}
        .header .logo {{
            font-size: 48px;
            margin-bottom: 10px;
        }}
        .content {{
            padding: 40px 30px;
        }}
        .content h2 {{
            color: #1e293b;
            margin-top: 0;
            font-size: 24px;
        }}
        .button {{
            display: inline-block;
            padding: 14px 32px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #ffffff !important;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            margin: 20px 0;
            transition: transform 0.2s;
        }}
        .button:hover {{
            transform: translateY(-2px);
        }}
        .info-box {{
            background: #f0fdf4;
            border-left: 4px solid #10b981;
            padding: 15px 20px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        .warning-box {{
            background: #fef2f2;
            border-left: 4px solid #ef4444;
            padding: 15px 20px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #f8fafc;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{
            font-size: 14px;
            color: #64748b;
            margin-top: 5px;
        }}
        .footer {{
            background: #f8fafc;
            padding: 30px;
            text-align: center;
            color: #64748b;
            font-size: 14px;
        }}
        .footer a {{
            color: #667eea;
            text-decoration: none;
        }}
        .divider {{
            height: 1px;
            background: #e2e8f0;
            margin: 30px 0;
        }}
        ul {{
            padding-left: 20px;
        }}
        ul li {{
            margin: 10px 0;
        }}
        code {{
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }}
        @media only screen and (max-width: 600px) {{
            .email-container {{
                margin: 0;
                border-radius: 0;
            }}
            .content, .header, .footer {{
                padding: 20px;
            }}
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
            <div class="logo">🔬</div>
            <h1>DNS Science</h1>
        </div>
        <div class="content">
            {content}
        </div>
        <div class="footer">
            <p><strong>DNS Science</strong> - Advanced DNS Intelligence Platform</p>
            <p>
                <a href="https://www.dnsscience.io">Website</a> |
                <a href="https://www.dnsscience.io/docs">Documentation</a> |
                <a href="https://www.dnsscience.io/support">Support</a>
            </p>
            <p style="margin-top: 20px;">
                © {datetime.now().year} DNS Science. All rights reserved.<br>
                <a href="https://www.dnsscience.io/unsubscribe">Unsubscribe</a> |
                <a href="https://www.dnsscience.io/privacy">Privacy Policy</a>
            </p>
        </div>
    </div>
</body>
</html>
        """

    @classmethod
    def welcome_email(cls, user_name: str, verification_url: str) -> Dict[str, str]:
        """Welcome email upon signup"""
        content = f"""
            <h2>Welcome to DNS Science, {user_name}! 🎉</h2>
            <p>Thank you for signing up. We're excited to have you on board!</p>

            <div class="info-box">
                <p><strong>✨ Verify Your Email Address</strong></p>
                <p>Click the button below to verify your email and activate your account:</p>
            </div>

            <div style="text-align: center;">
                <a href="{verification_url}" class="button">Verify Email Address</a>
            </div>

            <p style="color: #64748b; font-size: 14px;">
                Or copy and paste this link: <code>{verification_url}</code>
            </p>

            <p><strong>⚠️ This link expires in 24 hours.</strong></p>

            <div class="divider"></div>

            <h3>🚀 What's Next?</h3>
            <ul>
                <li><strong>Scan Your First Domain</strong> - Try our comprehensive DNS, SSL, and email security scanner</li>
                <li><strong>Explore the Data Explorer</strong> - Browse over 1M+ domains in our database</li>
                <li><strong>Check Out the CLI Tools</strong> - Install <code>dnsscience-cli</code> for command-line access</li>
                <li><strong>Set Up API Keys</strong> - Generate API keys for automated scanning</li>
            </ul>

            <div class="info-box">
                <p><strong>💡 Pro Tip:</strong> Start with our Free tier (1,500 requests/month) and upgrade anytime as your needs grow!</p>
            </div>

            <p>If you didn't create this account, you can safely ignore this email.</p>
        """

        return {
            'subject': 'Welcome to DNS Science - Verify Your Email',
            'html': cls._base_template('Welcome to DNS Science', content),
            'text': f"""Welcome to DNS Science, {user_name}!

Thank you for signing up. Please verify your email by visiting: {verification_url}

This link expires in 24 hours.

What's Next?
- Scan your first domain
- Explore our database of 1M+ domains
- Install our CLI tools
- Set up API keys for automation

If you didn't create this account, please ignore this email.

© {datetime.now().year} DNS Science
"""
        }

    @classmethod
    def password_reset_email(cls, user_name: str, reset_url: str) -> Dict[str, str]:
        """Password reset email"""
        content = f"""
            <h2>Password Reset Request</h2>
            <p>Hello {user_name},</p>
            <p>We received a request to reset your DNS Science password.</p>

            <div style="text-align: center;">
                <a href="{reset_url}" class="button">Reset Password</a>
            </div>

            <p style="color: #64748b; font-size: 14px;">
                Or copy and paste this link: <code>{reset_url}</code>
            </p>

            <div class="warning-box">
                <p><strong>⚠️ Security Notice:</strong></p>
                <ul style="margin: 10px 0;">
                    <li>This link expires in <strong>1 hour</strong></li>
                    <li>You'll be logged out of all active sessions</li>
                    <li>The link can only be used once</li>
                    <li>If you didn't request this, please ignore this email and consider changing your password</li>
                </ul>
            </div>
        """

        return {
            'subject': 'DNS Science - Password Reset Request',
            'html': cls._base_template('Password Reset', content),
            'text': f"""DNS Science - Password Reset Request

Hello {user_name},

We received a request to reset your password. Visit this URL: {reset_url}

SECURITY NOTICE:
- This link expires in 1 hour
- You'll be logged out of all sessions
- The link can only be used once
- If you didn't request this, ignore this email

© {datetime.now().year} DNS Science
"""
        }

    @classmethod
    def checkin_email(cls, user_name: str, days_since_signup: int, user_stats: Dict[str, int]) -> Dict[str, str]:
        """3-day check-in email"""
        content = f"""
            <h2>How's It Going, {user_name}?</h2>
            <p>It's been {days_since_signup} days since you joined DNS Science! We wanted to check in and see how things are going.</p>

            <h3>📊 Your Activity So Far</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{user_stats.get('domains_scanned', 0)}</div>
                    <div class="stat-label">Domains Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{user_stats.get('api_calls', 0)}</div>
                    <div class="stat-label">API Calls</div>
                </div>
            </div>

            <div class="info-box">
                <p><strong>💬 Need Help Getting Started?</strong></p>
                <p>Our team is here to help! Here are some resources:</p>
                <ul style="margin: 10px 0;">
                    <li><a href="https://www.dnsscience.io/docs/quickstart">Quick Start Guide</a> - Get up and running in 5 minutes</li>
                    <li><a href="https://www.dnsscience.io/docs/api">API Documentation</a> - Complete API reference</li>
                    <li><a href="https://www.dnsscience.io/support">Support Center</a> - FAQs and troubleshooting</li>
                </ul>
            </div>

            <h3>🎯 Popular Features to Try:</h3>
            <ul>
                <li><strong>Advanced IP Scanning</strong> - Get threat intelligence and geolocation data</li>
                <li><strong>CIDR Range Scanning</strong> - Scan entire network blocks</li>
                <li><strong>Data Explorer</strong> - Browse and filter our domain database</li>
                <li><strong>CLI Tools</strong> - Automate scans from the command line</li>
            </ul>

            <div style="text-align: center; margin: 30px 0;">
                <a href="https://www.dnsscience.io/support" class="button">Get Support</a>
            </div>

            <p style="color: #64748b;">
                Reply to this email with any questions or feedback. We read every message!
            </p>
        """

        return {
            'subject': f'Checking In - How\'s DNS Science Working for You?',
            'html': cls._base_template('Checking In', content),
            'text': f"""How's It Going, {user_name}?

It's been {days_since_signup} days since you joined DNS Science!

Your Activity:
- Domains Scanned: {user_stats.get('domains_scanned', 0)}
- API Calls: {user_stats.get('api_calls', 0)}

Need Help?
- Quick Start Guide: https://www.dnsscience.io/docs/quickstart
- API Docs: https://www.dnsscience.io/docs/api
- Support: https://www.dnsscience.io/support

Reply to this email with any questions!

© {datetime.now().year} DNS Science
"""
        }

    @classmethod
    def report_email(cls, user_name: str, report_title: str, report_summary: Dict[str, Any]) -> Dict[str, str]:
        """Report email with attachment"""
        content = f"""
            <h2>Your Report is Ready, {user_name}</h2>
            <p>We've generated your <strong>{report_title}</strong> report.</p>

            <h3>📋 Report Summary</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{report_summary.get('total_domains', 0)}</div>
                    <div class="stat-label">Total Domains</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{report_summary.get('issues_found', 0)}</div>
                    <div class="stat-label">Issues Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{report_summary.get('security_score', 0)}/100</div>
                    <div class="stat-label">Avg Security Score</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{report_summary.get('critical_alerts', 0)}</div>
                    <div class="stat-label">Critical Alerts</div>
                </div>
            </div>

            <div class="info-box">
                <p><strong>📎 Report Attached</strong></p>
                <p>Your complete report is attached to this email in PDF format.</p>
            </div>

            <div style="text-align: center;">
                <a href="https://www.dnsscience.io/reports" class="button">View All Reports</a>
            </div>

            <p style="color: #64748b; font-size: 14px;">
                Reports are also available in your account dashboard for 90 days.
            </p>
        """

        return {
            'subject': f'DNS Science Report: {report_title}',
            'html': cls._base_template('Report Ready', content),
            'text': f"""Your Report is Ready, {user_name}

Report: {report_title}

Summary:
- Total Domains: {report_summary.get('total_domains', 0)}
- Issues Found: {report_summary.get('issues_found', 0)}
- Avg Security Score: {report_summary.get('security_score', 0)}/100
- Critical Alerts: {report_summary.get('critical_alerts', 0)}

Your complete report is attached.

View all reports: https://www.dnsscience.io/reports

© {datetime.now().year} DNS Science
"""
        }


class SESSender:
    """AWS SES email sender for DNS Science"""

    def __init__(self, region='us-east-1'):
        """Initialize SES client"""
        self.region = region
        self.ses_client = boto3.client('ses', region_name=region)
        self.from_email = os.getenv('SES_FROM_EMAIL', 'noreply@apps.afterdarksys.com')
        self.from_name = 'DNS Science'
        self.reply_to = os.getenv('SES_REPLY_TO', 'support@apps.afterdarksys.com')

    def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Send email via AWS SES

        Args:
            to_email: Recipient email
            subject: Email subject
            html_body: HTML content
            text_body: Plain text content
            attachments: List of dicts with 'filename' and 'content' (bytes)

        Returns:
            Dict with status and message_id or error
        """
        try:
            if attachments:
                # Use raw email for attachments
                return self._send_raw_email(to_email, subject, html_body, text_body, attachments)
            else:
                # Use simple send for text/html only
                response = self.ses_client.send_email(
                    Source=formataddr((self.from_name, self.from_email)),
                    Destination={'ToAddresses': [to_email]},
                    Message={
                        'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                        'Body': {
                            'Text': {'Data': text_body, 'Charset': 'UTF-8'},
                            'Html': {'Data': html_body, 'Charset': 'UTF-8'}
                        }
                    },
                    ReplyToAddresses=[self.reply_to]
                )

                logger.info(f"✅ Email sent to {to_email}: {response['MessageId']}")
                return {
                    'success': True,
                    'message_id': response['MessageId'],
                    'to': to_email
                }

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            logger.error(f"❌ SES Error ({error_code}): {error_msg}")
            return {
                'success': False,
                'error': f"{error_code}: {error_msg}",
                'to': to_email
            }
        except Exception as e:
            logger.error(f"❌ Email send error: {e}")
            return {
                'success': False,
                'error': str(e),
                'to': to_email
            }

    def _send_raw_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
        attachments: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Send email with attachments using raw API"""
        try:
            msg = MIMEMultipart('mixed')
            msg['Subject'] = subject
            msg['From'] = formataddr((self.from_name, self.from_email))
            msg['To'] = to_email
            msg['Reply-To'] = self.reply_to

            # Create multipart/alternative for text and HTML
            msg_body = MIMEMultipart('alternative')
            msg_body.attach(MIMEText(text_body, 'plain', 'utf-8'))
            msg_body.attach(MIMEText(html_body, 'html', 'utf-8'))
            msg.attach(msg_body)

            # Attach files
            for attachment in attachments:
                att = MIMEApplication(attachment['content'])
                att.add_header('Content-Disposition', 'attachment', filename=attachment['filename'])
                msg.attach(att)

            # Send raw email
            response = self.ses_client.send_raw_email(
                Source=self.from_email,
                Destinations=[to_email],
                RawMessage={'Data': msg.as_string()}
            )

            logger.info(f"✅ Email with attachments sent to {to_email}: {response['MessageId']}")
            return {
                'success': True,
                'message_id': response['MessageId'],
                'to': to_email
            }

        except Exception as e:
            logger.error(f"❌ Raw email send error: {e}")
            return {
                'success': False,
                'error': str(e),
                'to': to_email
            }

    def send_bulk_emails(
        self,
        emails: List[Dict[str, Any]],
        batch_size: int = 50
    ) -> Dict[str, Any]:
        """
        Send multiple emails in batches

        Args:
            emails: List of email dicts with to_email, subject, html_body, text_body
            batch_size: Number of emails per batch (SES limit is 50/sec)

        Returns:
            Dict with success/failure counts
        """
        sent = 0
        failed = 0
        errors = []

        for i in range(0, len(emails), batch_size):
            batch = emails[i:i+batch_size]

            for email in batch:
                result = self.send_email(
                    to_email=email['to_email'],
                    subject=email['subject'],
                    html_body=email['html_body'],
                    text_body=email['text_body'],
                    attachments=email.get('attachments')
                )

                if result['success']:
                    sent += 1
                else:
                    failed += 1
                    errors.append({
                        'to': email['to_email'],
                        'error': result.get('error')
                    })

        return {
            'sent': sent,
            'failed': failed,
            'total': len(emails),
            'errors': errors
        }


class EmailCampaignManager:
    """Manage email campaigns and scheduled sends"""

    def __init__(self):
        self.ses = SESSender()
        from database import Database
        self.db = Database()

    def send_welcome_emails(self, user_ids: Optional[List[int]] = None):
        """Send welcome emails to new users"""
        if user_ids:
            users = self.db.execute_query(
                "SELECT id, username, email FROM users WHERE id = ANY(%s) AND is_verified = false",
                (user_ids,)
            )
        else:
            # New signups in last hour
            users = self.db.execute_query("""
                SELECT id, username, email FROM users
                WHERE created_at > NOW() - INTERVAL '1 hour'
                AND is_verified = false
            """)

        for user in users:
            # Generate verification token
            token = f"verify_{user['id']}_{datetime.now().timestamp()}"
            template = BrandedEmailTemplates.welcome_email(user['username'], f"https://www.dnsscience.io/verify?token={token}")

            self.ses.send_email(
                to_email=user['email'],
                subject=template['subject'],
                html_body=template['html'],
                text_body=template['text']
            )

    def send_checkin_emails(self):
        """Send 3-day check-in emails"""
        users = self.db.execute_query("""
            SELECT u.id, u.username, u.email, u.created_at,
                   COUNT(DISTINCT ds.domain_name) as domains_scanned,
                   COALESCE(ut.total_requests, 0) as api_calls
            FROM users u
            LEFT JOIN domain_scans ds ON u.id = ds.user_id
            LEFT JOIN usage_tracking ut ON u.id = ut.user_id
            WHERE u.created_at BETWEEN NOW() - INTERVAL '4 days' AND NOW() - INTERVAL '3 days'
            AND u.is_verified = true
            GROUP BY u.id, u.username, u.email, u.created_at, ut.total_requests
        """)

        for user in users:
            days_since = (datetime.now() - user['created_at']).days
            stats = {
                'domains_scanned': user['domains_scanned'],
                'api_calls': user['api_calls']
            }

            template = BrandedEmailTemplates.checkin_email(user['username'], days_since, stats)

            self.ses.send_email(
                to_email=user['email'],
                subject=template['subject'],
                html_body=template['html'],
                text_body=template['text']
            )

    def get_users_by_timeframe(self, timeframe: str) -> List[Dict[str, Any]]:
        """Get users by signup timeframe"""
        queries = {
            'this_week': "WHERE u.created_at >= DATE_TRUNC('week', NOW())",
            'last_week': "WHERE u.created_at >= DATE_TRUNC('week', NOW() - INTERVAL '1 week') AND u.created_at < DATE_TRUNC('week', NOW())",
            'this_month': "WHERE u.created_at >= DATE_TRUNC('month', NOW())",
            'today': "WHERE u.created_at >= DATE_TRUNC('day', NOW())"
        }

        where_clause = queries.get(timeframe, '')

        return self.db.execute_query(f"""
            SELECT id, username, email, created_at
            FROM users u
            {where_clause}
            AND is_verified = true
            ORDER BY created_at DESC
        """)
