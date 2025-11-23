#!/usr/bin/env python3
"""
DNS Science Email Scheduler Daemon
Automatically sends scheduled emails (welcome, check-ins, reports)
"""

import sys
import os
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from email_system import SESSender, BrandedEmailTemplates, EmailCampaignManager
from database import Database

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('email_scheduler')


class EmailSchedulerDaemon:
    """Daemon for scheduled email sends"""

    def __init__(self):
        self.ses = SESSender()
        self.campaign_mgr = EmailCampaignManager()
        self.db = Database()
        self.running = True

    def run(self):
        """Main daemon loop"""
        logger.info("🚀 Email Scheduler Daemon started")

        while self.running:
            try:
                current_time = datetime.now()

                # Run every hour
                if current_time.minute == 0:
                    logger.info(f"⏰ Running scheduled tasks at {current_time}")

                    # Send welcome emails to new signups
                    self.send_welcome_emails()

                    # Send 3-day check-ins (run at 10 AM)
                    if current_time.hour == 10:
                        self.send_checkin_emails()

                    # Send weekly reports (Mondays at 9 AM)
                    if current_time.weekday() == 0 and current_time.hour == 9:
                        self.send_weekly_reports()

                # Sleep until next minute
                time.sleep(60)

            except KeyboardInterrupt:
                logger.info("⛔ Shutdown signal received")
                self.running = False
                break

            except Exception as e:
                logger.error(f"❌ Error in main loop: {e}")
                time.sleep(60)

        logger.info("👋 Email Scheduler Daemon stopped")

    def send_welcome_emails(self):
        """Send welcome emails to users who signed up in the last hour"""
        try:
            # Get new unverified users from last hour
            users = self.db.execute_query("""
                SELECT id, username, email, created_at
                FROM users
                WHERE created_at > NOW() - INTERVAL '1 hour'
                AND is_verified = false
                AND NOT EXISTS (
                    SELECT 1 FROM email_sent_log
                    WHERE user_id = users.id
                    AND email_type = 'welcome'
                )
                ORDER BY created_at DESC
            """)

            if not users:
                logger.info("   No new signups to send welcome emails")
                return

            logger.info(f"📧 Sending welcome emails to {len(users)} new users")

            for user in users:
                try:
                    # Generate verification token
                    token = f"verify_{user['id']}_{int(user['created_at'].timestamp())}"

                    # Store token in database
                    self.db.execute_update("""
                        INSERT INTO email_verification_tokens (user_id, token, expires_at)
                        VALUES (%s, %s, NOW() + INTERVAL '24 hours')
                        ON CONFLICT (user_id) DO UPDATE SET
                            token = EXCLUDED.token,
                            expires_at = EXCLUDED.expires_at,
                            created_at = NOW()
                    """, (user['id'], token))

                    # Get template
                    template = BrandedEmailTemplates.welcome_email(
                        user['username'],
                        f"https://www.dnsscience.io/verify?token={token}"
                    )

                    # Send email
                    result = self.ses.send_email(
                        to_email=user['email'],
                        subject=template['subject'],
                        html_body=template['html'],
                        text_body=template['text']
                    )

                    if result['success']:
                        # Log successful send
                        self.db.execute_update("""
                            INSERT INTO email_sent_log (user_id, email_type, message_id, sent_at)
                            VALUES (%s, 'welcome', %s, NOW())
                        """, (user['id'], result['message_id']))

                        logger.info(f"   ✅ Welcome email sent to {user['email']}")
                    else:
                        logger.error(f"   ❌ Failed to send to {user['email']}: {result.get('error')}")

                except Exception as e:
                    logger.error(f"   ❌ Error sending to {user['email']}: {e}")

        except Exception as e:
            logger.error(f"❌ Error in send_welcome_emails: {e}")

    def send_checkin_emails(self):
        """Send 3-day check-in emails"""
        try:
            # Get users who signed up 3 days ago and haven't received check-in
            users = self.db.execute_query("""
                SELECT u.id, u.username, u.email, u.created_at,
                       COUNT(DISTINCT ds.domain_name) as domains_scanned,
                       COALESCE(SUM(ut.total_requests), 0) as api_calls
                FROM users u
                LEFT JOIN domain_scans ds ON u.id = ds.user_id
                LEFT JOIN usage_tracking ut ON u.id = ut.user_id
                WHERE u.created_at BETWEEN NOW() - INTERVAL '4 days' AND NOW() - INTERVAL '3 days'
                AND u.is_verified = true
                AND NOT EXISTS (
                    SELECT 1 FROM email_sent_log
                    WHERE user_id = u.id
                    AND email_type = 'checkin'
                )
                GROUP BY u.id, u.username, u.email, u.created_at
            """)

            if not users:
                logger.info("   No users eligible for 3-day check-in")
                return

            logger.info(f"📧 Sending check-in emails to {len(users)} users")

            for user in users:
                try:
                    days_since = (datetime.now() - user['created_at']).days
                    stats = {
                        'domains_scanned': user['domains_scanned'] or 0,
                        'api_calls': user['api_calls'] or 0
                    }

                    # Get template
                    template = BrandedEmailTemplates.checkin_email(
                        user['username'],
                        days_since,
                        stats
                    )

                    # Send email
                    result = self.ses.send_email(
                        to_email=user['email'],
                        subject=template['subject'],
                        html_body=template['html'],
                        text_body=template['text']
                    )

                    if result['success']:
                        # Log successful send
                        self.db.execute_update("""
                            INSERT INTO email_sent_log (user_id, email_type, message_id, sent_at)
                            VALUES (%s, 'checkin', %s, NOW())
                        """, (user['id'], result['message_id']))

                        logger.info(f"   ✅ Check-in email sent to {user['email']}")
                    else:
                        logger.error(f"   ❌ Failed to send to {user['email']}: {result.get('error')}")

                except Exception as e:
                    logger.error(f"   ❌ Error sending to {user['email']}: {e}")

        except Exception as e:
            logger.error(f"❌ Error in send_checkin_emails: {e}")

    def send_weekly_reports(self):
        """Send weekly activity reports"""
        try:
            # Get active users from last week
            users = self.db.execute_query("""
                SELECT u.id, u.username, u.email,
                       COUNT(DISTINCT ds.domain_name) as domains_scanned,
                       COALESCE(SUM(ut.total_requests), 0) as api_calls
                FROM users u
                LEFT JOIN domain_scans ds ON u.id = ds.user_id
                    AND ds.scan_timestamp > NOW() - INTERVAL '7 days'
                LEFT JOIN usage_tracking ut ON u.id = ut.user_id
                    AND ut.period_start > NOW() - INTERVAL '7 days'
                WHERE u.is_verified = true
                AND (ds.id IS NOT NULL OR ut.id IS NOT NULL)
                GROUP BY u.id, u.username, u.email
                HAVING COUNT(DISTINCT ds.domain_name) > 0 OR COALESCE(SUM(ut.total_requests), 0) > 0
            """)

            if not users:
                logger.info("   No active users for weekly reports")
                return

            logger.info(f"📧 Sending weekly reports to {len(users)} users")

            for user in users:
                try:
                    summary = {
                        'total_domains': user['domains_scanned'] or 0,
                        'issues_found': 0,  # Would calculate from actual data
                        'security_score': 85,  # Would calculate from actual data
                        'critical_alerts': 0  # Would calculate from actual data
                    }

                    # Get template
                    template = BrandedEmailTemplates.report_email(
                        user['username'],
                        "Weekly Activity Report",
                        summary
                    )

                    # Send email
                    result = self.ses.send_email(
                        to_email=user['email'],
                        subject=template['subject'],
                        html_body=template['html'],
                        text_body=template['text']
                    )

                    if result['success']:
                        logger.info(f"   ✅ Weekly report sent to {user['email']}")
                    else:
                        logger.error(f"   ❌ Failed to send to {user['email']}: {result.get('error')}")

                except Exception as e:
                    logger.error(f"   ❌ Error sending to {user['email']}: {e}")

        except Exception as e:
            logger.error(f"❌ Error in send_weekly_reports: {e}")


def main():
    """Main entry point"""
    daemon = EmailSchedulerDaemon()

    try:
        daemon.run()
    except KeyboardInterrupt:
        logger.info("⛔ Interrupted by user")
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        raise


if __name__ == '__main__':
    main()
