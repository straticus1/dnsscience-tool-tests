#!/usr/bin/env python3
"""
Certificate Expiration Alert System
Monitors SSL certificates and sends alerts before expiration
"""

import os
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from database import Database
from email_system import SESSender, BrandedEmailTemplates

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('certificate_alerts')


class CertificateAlertManager:
    """Manage certificate expiration alerts and watching"""

    def __init__(self):
        self.db = Database()
        self.ses = SESSender()

        # Alert thresholds (days before expiration)
        self.alert_thresholds = [30, 14, 7, 3, 1]

    def add_certificate_watch(self, user_id: int, domain: str,
                            certificate_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Add a certificate to user's watch list

        Free users: max 2 certificates
        Paid users: unlimited
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                # Check user's subscription tier
                cursor.execute("""
                    SELECT st.tier_name, st.certificate_watch_limit
                    FROM users u
                    LEFT JOIN user_subscriptions us ON u.id = us.user_id
                    LEFT JOIN subscription_tiers st ON us.tier_id = st.id
                    WHERE u.id = %s
                """, (user_id,))

                tier_info = cursor.fetchone()
                if not tier_info:
                    # Default to free tier
                    watch_limit = 2
                    tier_name = 'Free'
                else:
                    tier_name = tier_info[0] or 'Free'
                    watch_limit = tier_info[1] if tier_info[1] else 2

                # Check current watch count
                cursor.execute("""
                    SELECT COUNT(*) FROM certificate_watches
                    WHERE user_id = %s AND is_active = true
                """, (user_id,))
                current_count = cursor.fetchone()[0]

                if watch_limit != -1 and current_count >= watch_limit:
                    return {
                        'success': False,
                        'error': f'Watch limit reached. {tier_name} tier allows {watch_limit} certificates.',
                        'current_count': current_count,
                        'limit': watch_limit
                    }

                # Add certificate watch
                cursor.execute("""
                    INSERT INTO certificate_watches
                    (user_id, domain, certificate_id, created_at, is_active)
                    VALUES (%s, %s, %s, NOW(), true)
                    ON CONFLICT (user_id, domain)
                    DO UPDATE SET
                        is_active = true,
                        updated_at = NOW()
                    RETURNING id
                """, (user_id, domain.lower(), certificate_id))

                watch_id = cursor.fetchone()[0]
                conn.commit()

                return {
                    'success': True,
                    'watch_id': watch_id,
                    'domain': domain,
                    'message': f'Now watching certificate for {domain}'
                }

        except Exception as e:
            conn.rollback()
            logger.error(f"Error adding certificate watch: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            self.db.return_connection(conn)

    def remove_certificate_watch(self, user_id: int, domain: str) -> Dict[str, Any]:
        """Remove a certificate from watch list"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE certificate_watches
                    SET is_active = false, updated_at = NOW()
                    WHERE user_id = %s AND domain = %s
                    RETURNING id
                """, (user_id, domain.lower()))

                result = cursor.fetchone()
                conn.commit()

                if result:
                    return {
                        'success': True,
                        'message': f'Stopped watching {domain}'
                    }
                else:
                    return {
                        'success': False,
                        'error': 'Certificate watch not found'
                    }

        except Exception as e:
            conn.rollback()
            logger.error(f"Error removing certificate watch: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            self.db.return_connection(conn)

    def get_user_watches(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all active certificate watches for a user"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT
                        cw.id,
                        cw.domain,
                        cw.created_at,
                        c.expiration_date,
                        c.issuer,
                        c.subject_common_name,
                        EXTRACT(DAY FROM (c.expiration_date - NOW())) as days_until_expiration
                    FROM certificate_watches cw
                    LEFT JOIN certificates c ON cw.domain = c.domain AND c.is_current = true
                    WHERE cw.user_id = %s AND cw.is_active = true
                    ORDER BY c.expiration_date ASC NULLS LAST
                """, (user_id,))

                watches = []
                for row in cursor.fetchall():
                    watches.append({
                        'id': row[0],
                        'domain': row[1],
                        'created_at': row[2],
                        'expiration_date': row[3],
                        'issuer': row[4],
                        'subject': row[5],
                        'days_until_expiration': int(row[6]) if row[6] else None
                    })

                return watches

        finally:
            self.db.return_connection(conn)

    def check_expiring_certificates(self) -> Dict[str, Any]:
        """
        Check all watched certificates and send alerts
        Called by daemon every day
        """
        conn = self.db.get_connection()
        alerts_sent = 0
        errors = []

        try:
            with conn.cursor() as cursor:
                # Get certificates expiring soon that need alerts
                for threshold in self.alert_thresholds:
                    cursor.execute("""
                        SELECT
                            cw.user_id,
                            u.username,
                            u.email,
                            cw.domain,
                            c.expiration_date,
                            c.issuer,
                            c.subject_common_name,
                            EXTRACT(DAY FROM (c.expiration_date - NOW())) as days_until_expiration
                        FROM certificate_watches cw
                        JOIN users u ON cw.user_id = u.id
                        JOIN certificates c ON cw.domain = c.domain AND c.is_current = true
                        WHERE cw.is_active = true
                        AND c.expiration_date BETWEEN NOW() AND NOW() + INTERVAL '%s days'
                        AND NOT EXISTS (
                            SELECT 1 FROM certificate_alerts
                            WHERE certificate_watch_id = cw.id
                            AND alert_threshold = %s
                            AND sent_at > NOW() - INTERVAL '24 hours'
                        )
                    """, (threshold, threshold))

                    expiring_certs = cursor.fetchall()

                    for cert in expiring_certs:
                        try:
                            user_id, username, email, domain, exp_date, issuer, subject, days = cert

                            # Send alert email
                            result = self._send_expiration_alert(
                                user_email=email,
                                username=username,
                                domain=domain,
                                expiration_date=exp_date,
                                days_until_expiration=int(days),
                                issuer=issuer
                            )

                            if result['success']:
                                # Log the alert
                                cursor.execute("""
                                    INSERT INTO certificate_alerts
                                    (certificate_watch_id, alert_threshold, sent_at, message_id)
                                    SELECT id, %s, NOW(), %s
                                    FROM certificate_watches
                                    WHERE user_id = %s AND domain = %s
                                """, (threshold, result['message_id'], user_id, domain))
                                conn.commit()

                                alerts_sent += 1
                                logger.info(f"Alert sent: {domain} expires in {days} days (user: {email})")
                            else:
                                errors.append(f"Failed to send alert for {domain}: {result.get('error')}")

                        except Exception as e:
                            logger.error(f"Error processing certificate alert: {e}")
                            errors.append(str(e))
                            conn.rollback()

            return {
                'success': True,
                'alerts_sent': alerts_sent,
                'errors': errors
            }

        except Exception as e:
            logger.error(f"Error checking expiring certificates: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            self.db.return_connection(conn)

    def _send_expiration_alert(self, user_email: str, username: str,
                              domain: str, expiration_date: datetime,
                              days_until_expiration: int, issuer: str) -> Dict[str, Any]:
        """Send certificate expiration alert email"""

        urgency = 'critical' if days_until_expiration <= 3 else 'warning'
        urgency_color = '#ef4444' if urgency == 'critical' else '#f59e0b'

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        .email-container {{ max-width: 600px; margin: 20px auto; font-family: Arial, sans-serif; }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #ffffff;
            padding: 40px 30px;
            text-align: center;
        }}
        .header .logo {{ font-size: 48px; margin-bottom: 10px; }}
        .content {{ background: #ffffff; padding: 40px 30px; }}
        .alert-box {{
            background: {urgency_color}15;
            border-left: 4px solid {urgency_color};
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        .cert-details {{
            background: #f3f4f6;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .button {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #ffffff !important;
            padding: 14px 32px;
            text-decoration: none;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .footer {{
            background: #f9fafb;
            padding: 30px;
            text-align: center;
            color: #6b7280;
        }}
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
            <div class="logo">⚠️</div>
            <h1>Certificate Expiration Alert</h1>
        </div>
        <div class="content">
            <p>Hi {username},</p>

            <div class="alert-box">
                <h2 style="color: {urgency_color}; margin-top: 0;">
                    Certificate expires in {days_until_expiration} day{"s" if days_until_expiration != 1 else ""}!
                </h2>
                <p style="font-size: 18px; margin: 0;">
                    <strong>{domain}</strong>
                </p>
            </div>

            <div class="cert-details">
                <h3 style="margin-top: 0;">Certificate Details</h3>
                <p><strong>Domain:</strong> {domain}</p>
                <p><strong>Expiration Date:</strong> {expiration_date.strftime('%B %d, %Y at %I:%M %p UTC')}</p>
                <p><strong>Issuer:</strong> {issuer}</p>
                <p><strong>Days Remaining:</strong> {days_until_expiration}</p>
            </div>

            <h3>⚡ Action Required</h3>
            <p>Your SSL/TLS certificate will expire soon. To avoid service interruptions:</p>
            <ul>
                <li>Renew your certificate with your certificate authority</li>
                <li>Update your web server configuration</li>
                <li>Verify the new certificate is properly installed</li>
            </ul>

            <div style="text-align: center;">
                <a href="https://www.dnsscience.io/certificates?domain={domain}" class="button">
                    View Certificate Details
                </a>
            </div>

            <p style="margin-top: 30px; color: #6b7280; font-size: 14px;">
                💡 <strong>Tip:</strong> Set up auto-renewal with Let's Encrypt or your certificate provider
                to avoid future expiration issues.
            </p>
        </div>
        <div class="footer">
            <p>You're receiving this alert because you're monitoring this certificate on DNS Science.</p>
            <p>
                <a href="https://www.dnsscience.io/settings/certificate-watches">Manage your certificate watches</a>
            </p>
            <p>© {datetime.now().year} DNS Science. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """

        text_body = f"""
Certificate Expiration Alert - DNS Science

Hi {username},

⚠️ CERTIFICATE EXPIRES IN {days_until_expiration} DAY{"S" if days_until_expiration != 1 else ""}!

Domain: {domain}
Expiration Date: {expiration_date.strftime('%B %d, %Y at %I:%M %p UTC')}
Issuer: {issuer}
Days Remaining: {days_until_expiration}

ACTION REQUIRED:
- Renew your certificate with your certificate authority
- Update your web server configuration
- Verify the new certificate is properly installed

View details: https://www.dnsscience.io/certificates?domain={domain}

Manage watches: https://www.dnsscience.io/settings/certificate-watches

---
DNS Science - Certificate Monitoring
© {datetime.now().year} All rights reserved
        """

        subject = f"⚠️ SSL Certificate expires in {days_until_expiration} day{"s" if days_until_expiration != 1 else ""}: {domain}"

        return self.ses.send_email(
            to_email=user_email,
            subject=subject,
            html_body=html_body,
            text_body=text_body
        )


if __name__ == '__main__':
    # Test certificate alert system
    manager = CertificateAlertManager()
    result = manager.check_expiring_certificates()
    print(f"Alerts sent: {result.get('alerts_sent', 0)}")
    if result.get('errors'):
        print(f"Errors: {result['errors']}")
