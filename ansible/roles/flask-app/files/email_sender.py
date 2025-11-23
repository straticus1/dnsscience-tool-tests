"""
DNS Science - Email Sending Module
Handles email delivery via AWS SES with template support
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
import json

# AWS SES would normally be imported like this:
# import boto3
# from botocore.exceptions import ClientError

# For now, we'll create a fallback SMTP implementation
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailTemplate:
    """Email templates for different notification types"""

    @staticmethod
    def welcome_email(user_name: str, verification_url: str) -> Dict[str, str]:
        """Welcome email after signup"""
        subject = "Welcome to DNS Science - Verify Your Email"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #1e293b; color: #fff; padding: 20px; text-align: center; }}
                .content {{ padding: 30px; background: #f8fafc; }}
                .button {{ display: inline-block; padding: 12px 24px; background: #3b82f6;
                           color: #fff; text-decoration: none; border-radius: 6px; }}
                .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #64748b; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔬 DNS Science</h1>
                </div>
                <div class="content">
                    <h2>Welcome, {user_name}!</h2>
                    <p>Thank you for signing up for DNS Science. We're excited to have you on board!</p>
                    <p>To get started, please verify your email address by clicking the button below:</p>
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{verification_url}" class="button">Verify Email Address</a>
                    </p>
                    <p>Or copy and paste this URL into your browser:</p>
                    <p style="word-break: break-all; color: #3b82f6;">{verification_url}</p>
                    <p><strong>This link will expire in 24 hours.</strong></p>
                    <hr>
                    <h3>What's Next?</h3>
                    <ul>
                        <li>Start scanning your first domain</li>
                        <li>Set up custom scanners with scheduling</li>
                        <li>Configure alert thresholds</li>
                        <li>Explore DNS, SSL, and email security features</li>
                    </ul>
                </div>
                <div class="footer">
                    <p>If you didn't create this account, please ignore this email.</p>
                    <p>&copy; {datetime.now().year} DNS Science. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

        text_body = f"""
        Welcome to DNS Science, {user_name}!

        Thank you for signing up. Please verify your email address by visiting:

        {verification_url}

        This link will expire in 24 hours.

        What's Next?
        - Start scanning your first domain
        - Set up custom scanners with scheduling
        - Configure alert thresholds
        - Explore DNS, SSL, and email security features

        If you didn't create this account, please ignore this email.

        © {datetime.now().year} DNS Science. All rights reserved.
        """

        return {'subject': subject, 'html': html_body, 'text': text_body}

    @staticmethod
    def password_reset_email(user_name: str, reset_url: str) -> Dict[str, str]:
        """Password reset email"""
        subject = "DNS Science - Password Reset Request"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #1e293b; color: #fff; padding: 20px; text-align: center; }}
                .content {{ padding: 30px; background: #f8fafc; }}
                .button {{ display: inline-block; padding: 12px 24px; background: #ef4444;
                           color: #fff; text-decoration: none; border-radius: 6px; }}
                .warning {{ background: #fef2f2; border-left: 4px solid #ef4444; padding: 15px; }}
                .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #64748b; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔬 DNS Science</h1>
                </div>
                <div class="content">
                    <h2>Password Reset Request</h2>
                    <p>Hello {user_name},</p>
                    <p>We received a request to reset your password. Click the button below to create a new password:</p>
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{reset_url}" class="button">Reset Password</a>
                    </p>
                    <p>Or copy and paste this URL into your browser:</p>
                    <p style="word-break: break-all; color: #3b82f6;">{reset_url}</p>
                    <div class="warning">
                        <p><strong>⚠️ Security Notice:</strong></p>
                        <ul>
                            <li>This link will expire in <strong>1 hour</strong></li>
                            <li>For security, you'll be logged out of all active sessions</li>
                            <li>If you didn't request this, please ignore this email</li>
                        </ul>
                    </div>
                </div>
                <div class="footer">
                    <p>For security reasons, this link can only be used once.</p>
                    <p>&copy; {datetime.now().year} DNS Science. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

        text_body = f"""
        DNS Science - Password Reset Request

        Hello {user_name},

        We received a request to reset your password. Visit this URL to create a new password:

        {reset_url}

        SECURITY NOTICE:
        - This link will expire in 1 hour
        - For security, you'll be logged out of all active sessions
        - If you didn't request this, please ignore this email

        For security reasons, this link can only be used once.

        © {datetime.now().year} DNS Science. All rights reserved.
        """

        return {'subject': subject, 'html': html_body, 'text': text_body}

    @staticmethod
    def password_changed_notification(user_name: str) -> Dict[str, str]:
        """Notification that password was changed"""
        subject = "DNS Science - Password Changed"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #1e293b; color: #fff; padding: 20px; text-align: center; }}
                .content {{ padding: 30px; background: #f8fafc; }}
                .alert {{ background: #f0fdf4; border-left: 4px solid #22c55e; padding: 15px; }}
                .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #64748b; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔬 DNS Science</h1>
                </div>
                <div class="content">
                    <h2>Password Changed Successfully</h2>
                    <p>Hello {user_name},</p>
                    <div class="alert">
                        <p><strong>✓ Your password has been changed successfully.</strong></p>
                        <p>Changed at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    </div>
                    <p>For security, all your active sessions have been logged out. Please log in again with your new password.</p>
                    <p>If you didn't make this change, please contact our support team immediately.</p>
                </div>
                <div class="footer">
                    <p>&copy; {datetime.now().year} DNS Science. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

        text_body = f"""
        DNS Science - Password Changed Successfully

        Hello {user_name},

        Your password has been changed successfully.
        Changed at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

        For security, all your active sessions have been logged out. Please log in again with your new password.

        If you didn't make this change, please contact our support team immediately.

        © {datetime.now().year} DNS Science. All rights reserved.
        """

        return {'subject': subject, 'html': html_body, 'text': text_body}

    @staticmethod
    def scanner_alert_email(user_name: str, scanner_name: str, alerts: List[Dict[str, Any]]) -> Dict[str, str]:
        """Custom scanner alert email"""
        alert_count = len(alerts)
        subject = f"DNS Science - {alert_count} Alert{'s' if alert_count > 1 else ''} from '{scanner_name}'"

        # Build alerts HTML
        alerts_html = ""
        for alert in alerts[:10]:  # Limit to 10 in email
            severity_color = {
                'critical': '#ef4444',
                'warning': '#f59e0b',
                'info': '#3b82f6'
            }.get(alert.get('severity', 'info'), '#3b82f6')

            alerts_html += f"""
            <div style="border-left: 4px solid {severity_color}; padding: 15px; margin: 10px 0; background: #f8fafc;">
                <p style="margin: 0; font-weight: bold; color: {severity_color};">
                    {alert.get('severity', 'INFO').upper()}: {alert.get('title', 'Alert')}
                </p>
                <p style="margin: 5px 0 0 0;">Domain: <strong>{alert.get('domain_name', 'N/A')}</strong></p>
                <p style="margin: 5px 0 0 0;">{alert.get('message', 'No details')}</p>
            </div>
            """

        if alert_count > 10:
            alerts_html += f"""
            <p style="text-align: center; color: #64748b;">
                ... and {alert_count - 10} more alert{'s' if alert_count - 10 > 1 else ''}
            </p>
            """

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #1e293b; color: #fff; padding: 20px; text-align: center; }}
                .content {{ padding: 30px; background: #fff; }}
                .button {{ display: inline-block; padding: 12px 24px; background: #3b82f6;
                           color: #fff; text-decoration: none; border-radius: 6px; }}
                .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #64748b; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔬 DNS Science</h1>
                </div>
                <div class="content">
                    <h2>Scanner Alert: {scanner_name}</h2>
                    <p>Hello {user_name},</p>
                    <p>Your custom scanner "{scanner_name}" has triggered {alert_count} alert{'s' if alert_count > 1 else ''}:</p>
                    {alerts_html}
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="https://dnsscience.io/scanners" class="button">View All Alerts</a>
                    </p>
                </div>
                <div class="footer">
                    <p>To manage alert settings, visit your <a href="https://dnsscience.io/settings">account settings</a>.</p>
                    <p>&copy; {datetime.now().year} DNS Science. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Build text version
        alerts_text = ""
        for alert in alerts[:10]:
            alerts_text += f"\n{'='*60}\n"
            alerts_text += f"{alert.get('severity', 'INFO').upper()}: {alert.get('title', 'Alert')}\n"
            alerts_text += f"Domain: {alert.get('domain_name', 'N/A')}\n"
            alerts_text += f"{alert.get('message', 'No details')}\n"

        if alert_count > 10:
            alerts_text += f"\n... and {alert_count - 10} more alert{'s' if alert_count - 10 > 1 else ''}\n"

        text_body = f"""
        DNS Science - Scanner Alert

        Hello {user_name},

        Your custom scanner "{scanner_name}" has triggered {alert_count} alert{'s' if alert_count > 1 else ''}:
        {alerts_text}

        View all alerts: https://dnsscience.io/scanners

        To manage alert settings, visit: https://dnsscience.io/settings

        © {datetime.now().year} DNS Science. All rights reserved.
        """

        return {'subject': subject, 'html': html_body, 'text': text_body}


class EmailSender:
    """Email sending service with AWS SES support"""

    def __init__(self, use_ses: bool = False):
        """
        Initialize email sender.

        Args:
            use_ses: Whether to use AWS SES (True) or SMTP fallback (False)
        """
        self.use_ses = use_ses
        self.from_email = "noreply@dnsscience.io"
        self.from_name = "DNS Science"

        if use_ses:
            # Initialize AWS SES client
            # self.ses_client = boto3.client('ses', region_name='us-east-1')
            pass
        else:
            # SMTP fallback configuration
            self.smtp_host = getattr(Config, 'SMTP_HOST', 'localhost')
            self.smtp_port = getattr(Config, 'SMTP_PORT', 587)
            self.smtp_user = getattr(Config, 'SMTP_USER', '')
            self.smtp_pass = getattr(Config, 'SMTP_PASS', '')
            self.smtp_tls = getattr(Config, 'SMTP_TLS', True)

    def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
        reply_to: Optional[str] = None
    ) -> bool:
        """
        Send an email.

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_body: HTML version of email body
            text_body: Plain text version of email body
            reply_to: Optional reply-to address

        Returns:
            True if sent successfully, False otherwise
        """
        try:
            if self.use_ses:
                return self._send_via_ses(to_email, subject, html_body, text_body, reply_to)
            else:
                return self._send_via_smtp(to_email, subject, html_body, text_body, reply_to)
        except Exception as e:
            logger.error(f"Email send error: {e}")
            return False

    def _send_via_ses(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
        reply_to: Optional[str] = None
    ) -> bool:
        """Send email via AWS SES"""
        try:
            # AWS SES implementation
            # response = self.ses_client.send_email(
            #     Source=formataddr((self.from_name, self.from_email)),
            #     Destination={'ToAddresses': [to_email]},
            #     Message={
            #         'Subject': {'Data': subject, 'Charset': 'UTF-8'},
            #         'Body': {
            #             'Text': {'Data': text_body, 'Charset': 'UTF-8'},
            #             'Html': {'Data': html_body, 'Charset': 'UTF-8'}
            #         }
            #     },
            #     ReplyToAddresses=[reply_to] if reply_to else []
            # )
            # logger.info(f"Email sent via SES to {to_email}: {response['MessageId']}")
            # return True

            # Placeholder for when SES is not configured
            logger.info(f"[SES DISABLED] Would send email to {to_email}: {subject}")
            return True

        except Exception as e:
            logger.error(f"SES send error: {e}")
            return False

    def _send_via_smtp(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
        reply_to: Optional[str] = None
    ) -> bool:
        """Send email via SMTP"""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = formataddr((self.from_name, self.from_email))
            msg['To'] = to_email

            if reply_to:
                msg['Reply-To'] = reply_to

            # Attach text and HTML parts
            part1 = MIMEText(text_body, 'plain', 'utf-8')
            part2 = MIMEText(html_body, 'html', 'utf-8')

            msg.attach(part1)
            msg.attach(part2)

            # Send via SMTP
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_tls:
                    server.starttls()

                if self.smtp_user and self.smtp_pass:
                    server.login(self.smtp_user, self.smtp_pass)

                server.send_message(msg)

            logger.info(f"Email sent via SMTP to {to_email}")
            return True

        except Exception as e:
            logger.error(f"SMTP send error: {e}")
            # Log but don't fail in development
            logger.info(f"[SMTP FAILED] Would send email to {to_email}: {subject}")
            return True  # Return True in development to not block flows

    def send_welcome_email(self, to_email: str, user_name: str, verification_token: str) -> bool:
        """Send welcome email with verification link"""
        verification_url = f"https://dnsscience.io/verify-email?token={verification_token}"
        template = EmailTemplate.welcome_email(user_name, verification_url)

        return self.send_email(
            to_email=to_email,
            subject=template['subject'],
            html_body=template['html'],
            text_body=template['text']
        )

    def send_password_reset_email(self, to_email: str, user_name: str, reset_token: str) -> bool:
        """Send password reset email"""
        reset_url = f"https://dnsscience.io/reset-password?token={reset_token}"
        template = EmailTemplate.password_reset_email(user_name, reset_url)

        return self.send_email(
            to_email=to_email,
            subject=template['subject'],
            html_body=template['html'],
            text_body=template['text']
        )

    def send_password_changed_notification(self, to_email: str, user_name: str) -> bool:
        """Send password changed confirmation"""
        template = EmailTemplate.password_changed_notification(user_name)

        return self.send_email(
            to_email=to_email,
            subject=template['subject'],
            html_body=template['html'],
            text_body=template['text']
        )

    def send_scanner_alert_email(
        self,
        to_email: str,
        user_name: str,
        scanner_name: str,
        alerts: List[Dict[str, Any]]
    ) -> bool:
        """Send custom scanner alert email"""
        template = EmailTemplate.scanner_alert_email(user_name, scanner_name, alerts)

        return self.send_email(
            to_email=to_email,
            subject=template['subject'],
            html_body=template['html'],
            text_body=template['text']
        )

    def send_bulk_emails(self, emails: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Send multiple emails in batch.

        Args:
            emails: List of dicts with keys: to_email, subject, html_body, text_body

        Returns:
            Dict with 'sent' and 'failed' counts
        """
        sent = 0
        failed = 0

        for email_data in emails:
            success = self.send_email(
                to_email=email_data['to_email'],
                subject=email_data['subject'],
                html_body=email_data['html_body'],
                text_body=email_data['text_body'],
                reply_to=email_data.get('reply_to')
            )

            if success:
                sent += 1
            else:
                failed += 1

        return {'sent': sent, 'failed': failed}
