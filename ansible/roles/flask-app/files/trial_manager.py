#!/usr/bin/env python3
"""
Free Trial Management System
Handles trial creation, monitoring, reminders, and conversions
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from database import Database
from email_system import SESSender, BrandedEmailTemplates

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('trial_manager')


class TrialManager:
    """Manage free trials and conversions"""

    # Trial durations (days)
    TRIAL_DURATIONS = {
        'starter': 7,
        'professional': 14,
        'business': 14,
        'enterprise': 30
    }

    def __init__(self):
        self.db = Database()
        self.ses = SESSender()

    def start_trial(self, user_id: int, plan_name: str) -> Dict[str, Any]:
        """
        Start a free trial for a user

        Args:
            user_id: User ID
            plan_name: Plan name (starter, professional, business, enterprise)

        Returns:
            {'success': True, 'trial_id': 123, 'ends_at': datetime}
        """
        try:
            if plan_name not in self.TRIAL_DURATIONS:
                return {'success': False, 'error': f'Invalid plan: {plan_name}'}

            trial_days = self.TRIAL_DURATIONS[plan_name]
            ends_at = datetime.now() + timedelta(days=trial_days)

            conn = self.db.get_connection()
            try:
                with conn.cursor() as cursor:
                    # Check if user already had a trial for this plan
                    cursor.execute("""
                        SELECT id FROM free_trials
                        WHERE user_id = %s AND plan_name = %s
                    """, (user_id, plan_name))

                    if cursor.fetchone():
                        return {
                            'success': False,
                            'error': f'User already had a trial for {plan_name}'
                        }

                    # Create trial
                    cursor.execute("""
                        INSERT INTO free_trials (
                            user_id,
                            plan_name,
                            trial_days,
                            started_at,
                            ends_at,
                            status
                        ) VALUES (%s, %s, %s, NOW(), %s, 'active')
                        RETURNING id
                    """, (user_id, plan_name, trial_days, ends_at))

                    trial_id = cursor.fetchone()[0]
                    conn.commit()

                # Send trial started email
                self._send_trial_started_email(user_id, plan_name, trial_days)

                logger.info(f"Started {trial_days}-day trial for user {user_id}: {plan_name}")

                return {
                    'success': True,
                    'trial_id': trial_id,
                    'ends_at': ends_at,
                    'trial_days': trial_days
                }

            finally:
                self.db.return_connection(conn)

        except Exception as e:
            logger.error(f"Error starting trial: {e}")
            return {'success': False, 'error': str(e)}

    def check_expiring_trials(self) -> Dict[str, Any]:
        """
        Check for expiring trials and send reminders
        Run this daily via cron/daemon
        """
        conn = self.db.get_connection()
        reminders_sent = 0

        try:
            with conn.cursor() as cursor:
                # Get trials needing reminders
                cursor.execute("""
                    SELECT
                        trial_id,
                        user_id,
                        username,
                        email,
                        plan_name,
                        ends_at,
                        days_remaining,
                        reminder_type
                    FROM expiring_trials_needing_reminders
                    WHERE reminder_type IS NOT NULL
                """)

                trials = cursor.fetchall()

                for trial in trials:
                    trial_id, user_id, username, email, plan_name, ends_at, days_remaining, reminder_type = trial

                    try:
                        # Send reminder email
                        result = self._send_trial_reminder_email(
                            user_id=user_id,
                            username=username,
                            email=email,
                            plan_name=plan_name,
                            days_remaining=int(days_remaining) if days_remaining else 0,
                            ends_at=ends_at
                        )

                        if result['success']:
                            # Mark reminder as sent
                            if reminder_type == 7:
                                column = 'reminder_7_days_sent'
                            elif reminder_type == 3:
                                column = 'reminder_3_days_sent'
                            elif reminder_type == 1:
                                column = 'reminder_1_day_sent'
                            elif reminder_type == 0:
                                column = 'reminder_expired_sent'
                                # Also mark trial as expired
                                cursor.execute("""
                                    UPDATE free_trials
                                    SET status = 'expired', expired_at = NOW()
                                    WHERE id = %s
                                """, (trial_id,))
                            else:
                                continue

                            cursor.execute(f"""
                                UPDATE free_trials
                                SET {column} = true
                                WHERE id = %s
                            """, (trial_id,))
                            conn.commit()

                            reminders_sent += 1
                            logger.info(f"Sent {reminder_type}-day reminder to user {user_id}")

                    except Exception as e:
                        logger.error(f"Error sending reminder for trial {trial_id}: {e}")
                        continue

                return {
                    'success': True,
                    'reminders_sent': reminders_sent
                }

        except Exception as e:
            logger.error(f"Error checking expiring trials: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            self.db.return_connection(conn)

    def convert_trial_to_paid(self, user_id: int, stripe_subscription_id: str) -> Dict[str, Any]:
        """
        Mark trial as converted when user subscribes

        Args:
            user_id: User ID
            stripe_subscription_id: Stripe subscription ID

        Returns:
            {'success': True}
        """
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE free_trials
                    SET status = 'converted',
                        converted_at = NOW()
                    WHERE user_id = %s
                    AND status = 'active'
                """, (user_id,))
                conn.commit()

            logger.info(f"Converted trial to paid for user {user_id}")
            return {'success': True}

        except Exception as e:
            logger.error(f"Error converting trial: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            self.db.return_connection(conn)

    def get_trial_status(self, user_id: int) -> Dict[str, Any]:
        """Get current trial status for user"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT
                        id,
                        plan_name,
                        trial_days,
                        started_at,
                        ends_at,
                        status,
                        EXTRACT(DAY FROM (ends_at - NOW())) as days_remaining
                    FROM free_trials
                    WHERE user_id = %s
                    AND status = 'active'
                    AND ends_at > NOW()
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (user_id,))

                result = cursor.fetchone()
                if not result:
                    return {'has_trial': False}

                return {
                    'has_trial': True,
                    'trial_id': result[0],
                    'plan_name': result[1],
                    'trial_days': result[2],
                    'started_at': result[3],
                    'ends_at': result[4],
                    'status': result[5],
                    'days_remaining': int(result[6]) if result[6] else 0
                }

        finally:
            self.db.return_connection(conn)

    def _send_trial_started_email(self, user_id: int, plan_name: str, trial_days: int):
        """Send welcome email when trial starts"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT username, email
                    FROM users
                    WHERE id = %s
                """, (user_id,))
                user = cursor.fetchone()
                if not user:
                    return

                username, email = user

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
        .content {{ background: #ffffff; padding: 40px 30px; }}
        .button {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #ffffff !important;
            padding: 14px 32px;
            text-decoration: none;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .feature-box {{
            background: #f3f4f6;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
        }}
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
            <h1>🚀 Your {trial_days}-Day {plan_name.capitalize()} Trial Has Started!</h1>
        </div>
        <div class="content">
            <p>Hi {username},</p>

            <p>Welcome to DNS Science {plan_name.capitalize()} plan! Your {trial_days}-day free trial is now active.</p>

            <h3>What's Included:</h3>
            <div class="feature-box">
                <p><strong>✓ Full {plan_name.capitalize()} Features</strong></p>
                <p>• Unlimited domain scanning</p>
                <p>• Certificate expiration alerts</p>
                <p>• Email deliverability scoring</p>
                <p>• Webhook integrations</p>
                <p>• Advanced threat detection</p>
            </div>

            <p><strong>Trial ends in {trial_days} days</strong> - We'll remind you before it expires.</p>

            <div style="text-align: center;">
                <a href="https://www.dnsscience.io/dashboard" class="button">Get Started</a>
            </div>

            <h3>💡 Quick Tips:</h3>
            <ul>
                <li>Scan your first domain to see instant results</li>
                <li>Set up certificate monitoring for critical domains</li>
                <li>Check your email deliverability score</li>
                <li>Configure webhooks for real-time alerts</li>
            </ul>

            <p>Questions? Reply to this email - we're here to help!</p>
        </div>
    </div>
</body>
</html>
            """

            self.ses.send_email(
                to_email=email,
                subject=f"🚀 Your {trial_days}-Day {plan_name.capitalize()} Trial Started!",
                html_body=html_body,
                text_body=f"Hi {username}, your {trial_days}-day {plan_name.capitalize()} trial has started!"
            )

        finally:
            self.db.return_connection(conn)

    def _send_trial_reminder_email(self, user_id: int, username: str, email: str,
                                   plan_name: str, days_remaining: int, ends_at: datetime):
        """Send trial reminder email"""
        if days_remaining > 0:
            subject = f"⏰ Your {plan_name.capitalize()} Trial Expires in {days_remaining} Day{'s' if days_remaining != 1 else ''}!"
            urgency_color = '#f59e0b' if days_remaining > 3 else '#ef4444'
            urgency_text = 'Soon' if days_remaining > 3 else 'Very Soon'
        else:
            subject = f"😔 Your {plan_name.capitalize()} Trial Has Expired"
            urgency_color = '#ef4444'
            urgency_text = 'Expired'

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
        .content {{ background: #ffffff; padding: 40px 30px; }}
        .alert-box {{
            background: {urgency_color}15;
            border-left: 4px solid {urgency_color};
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
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
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
            <h1>⏰ Trial Reminder</h1>
        </div>
        <div class="content">
            <p>Hi {username},</p>

            <div class="alert-box">
                <h2 style="color: {urgency_color}; margin-top: 0;">
                    Your {plan_name.capitalize()} trial {'expires' if days_remaining > 0 else 'has expired'}!
                </h2>
                <p style="font-size: 18px;">
                    {'Days remaining: ' + str(days_remaining) if days_remaining > 0 else 'Trial ended on: ' + ends_at.strftime('%B %d, %Y')}
                </p>
            </div>

            {'<p><strong>Don' + "'" + 't lose access to your premium features!</strong></p>' if days_remaining > 0 else '<p><strong>Subscribe now to restore your premium features!</strong></p>'}

            <p>What you'll keep with a paid subscription:</p>
            <ul>
                <li>✓ Unlimited domain scanning</li>
                <li>✓ Certificate expiration monitoring</li>
                <li>✓ Email deliverability scoring</li>
                <li>✓ Webhook integrations</li>
                <li>✓ Advanced security features</li>
                <li>✓ Priority support</li>
            </ul>

            <div style="text-align: center;">
                <a href="https://www.dnsscience.io/pricing" class="button">
                    Subscribe Now
                </a>
            </div>

            <p style="margin-top: 30px; font-size: 14px; color: #6b7280;">
                Questions about pricing or features? <a href="mailto:support@apps.afterdarksys.com">Contact us</a> - we're happy to help!
            </p>
        </div>
    </div>
</body>
</html>
        """

        return self.ses.send_email(
            to_email=email,
            subject=subject,
            html_body=html_body,
            text_body=f"Hi {username}, your {plan_name.capitalize()} trial expires in {days_remaining} days."
        )


if __name__ == '__main__':
    # Test trial manager
    manager = TrialManager()
    result = manager.check_expiring_trials()
    print(f"Reminders sent: {result.get('reminders_sent', 0)}")
