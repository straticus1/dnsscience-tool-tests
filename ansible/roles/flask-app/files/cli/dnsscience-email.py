#!/usr/bin/env python3
"""
DNS Science Email Campaign CLI Tool
Send branded emails to users with template support
"""

import sys
import os
import argparse
import json
from pathlib import Path
from typing import List, Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from email_system import SESSender, BrandedEmailTemplates, EmailCampaignManager
from database import Database


class EmailCLI:
    """CLI for email campaigns"""

    def __init__(self):
        self.ses = SESSender()
        self.campaign_mgr = EmailCampaignManager()
        self.db = Database()

    def send_template(self, template_file: str, to_email: str, variables: Dict[str, str]):
        """Send email from template file"""
        try:
            # Load template
            with open(template_file, 'r') as f:
                template_data = json.load(f)

            # Replace variables
            subject = template_data['subject']
            html_body = template_data['html']
            text_body = template_data.get('text', '')

            for key, value in variables.items():
                subject = subject.replace(f'{{{{{key}}}}}', value)
                html_body = html_body.replace(f'{{{{{key}}}}}', value)
                text_body = text_body.replace(f'{{{{{key}}}}}', value)

            # Send
            result = self.ses.send_email(
                to_email=to_email,
                subject=subject,
                html_body=html_body,
                text_body=text_body
            )

            if result['success']:
                print(f"✅ Email sent to {to_email}")
                print(f"   Message ID: {result['message_id']}")
            else:
                print(f"❌ Failed to send to {to_email}: {result.get('error')}")

        except FileNotFoundError:
            print(f"❌ Template file not found: {template_file}")
        except json.JSONDecodeError:
            print(f"❌ Invalid JSON in template file")
        except Exception as e:
            print(f"❌ Error: {e}")

    def send_to_user(self, user_identifier: str, template_type: str):
        """Send email to specific user by ID, username, or email"""
        try:
            # Find user
            user = self.db.execute_query("""
                SELECT id, username, email, created_at
                FROM users
                WHERE id::text = %s OR username = %s OR email = %s
                LIMIT 1
            """, (user_identifier, user_identifier, user_identifier), fetch_one=True)

            if not user:
                print(f"❌ User not found: {user_identifier}")
                return

            # Get template
            template = self._get_template(template_type, user)
            if not template:
                return

            # Send
            result = self.ses.send_email(
                to_email=user['email'],
                subject=template['subject'],
                html_body=template['html'],
                text_body=template['text']
            )

            if result['success']:
                print(f"✅ {template_type} email sent to {user['email']}")
                print(f"   Message ID: {result['message_id']}")
            else:
                print(f"❌ Failed: {result.get('error')}")

        except Exception as e:
            print(f"❌ Error: {e}")

    def send_to_timeframe(self, timeframe: str, template_type: str, dry_run: bool = False):
        """Send campaign to users who signed up in timeframe"""
        try:
            users = self.campaign_mgr.get_users_by_timeframe(timeframe)

            if not users:
                print(f"⚠️  No users found for timeframe: {timeframe}")
                return

            print(f"📊 Found {len(users)} users for timeframe: {timeframe}")

            if dry_run:
                print("\n🔍 DRY RUN - Would send to:")
                for user in users[:10]:
                    print(f"   - {user['email']} ({user['username']})")
                if len(users) > 10:
                    print(f"   ... and {len(users) - 10} more")
                print("\n💡 Remove --dry-run to actually send")
                return

            # Confirm
            confirm = input(f"\n⚠️  Send {template_type} email to {len(users)} users? (yes/no): ")
            if confirm.lower() != 'yes':
                print("❌ Cancelled")
                return

            # Send emails
            sent = 0
            failed = 0

            for user in users:
                template = self._get_template(template_type, user)
                if not template:
                    continue

                result = self.ses.send_email(
                    to_email=user['email'],
                    subject=template['subject'],
                    html_body=template['html'],
                    text_body=template['text']
                )

                if result['success']:
                    sent += 1
                    print(f"✅ Sent to {user['email']}")
                else:
                    failed += 1
                    print(f"❌ Failed for {user['email']}: {result.get('error')}")

            print(f"\n📈 Campaign Complete:")
            print(f"   Sent: {sent}")
            print(f"   Failed: {failed}")
            print(f"   Total: {len(users)}")

        except Exception as e:
            print(f"❌ Error: {e}")

    def list_templates(self):
        """List available email templates"""
        print("\n📧 Available Email Templates:")
        print("   1. welcome     - Welcome email with verification")
        print("   2. checkin     - 3-day check-in email")
        print("   3. password    - Password reset email")
        print("   4. report      - Report delivery email")
        print("\n💡 Use: dnsscience-email send-user <user> --template <template>")

    def test_ses_connection(self):
        """Test SES configuration"""
        print("\n🔧 Testing AWS SES Configuration...")
        try:
            # Try to get sending quota
            response = self.ses.ses_client.get_send_quota()
            print(f"✅ SES Connected!")
            print(f"   24-hour quota: {response['Max24HourSend']}")
            print(f"   Sent today: {response['SentLast24Hours']}")
            print(f"   Rate limit: {response['MaxSendRate']}/sec")
            print(f"   From email: {self.ses.from_email}")
            print(f"   Reply-to: {self.ses.reply_to}")

            # Check verified identities
            identities = self.ses.ses_client.list_verified_email_addresses()
            print(f"\n📬 Verified Email Addresses:")
            for email in identities.get('VerifiedEmailAddresses', []):
                print(f"   ✓ {email}")

        except Exception as e:
            print(f"❌ SES Connection Failed: {e}")
            print("\n💡 Make sure:")
            print("   1. AWS credentials are configured")
            print("   2. SES is set up in us-east-1")
            print("   3. apps.afterdarksys.com is verified")

    def _get_template(self, template_type: str, user: Dict[str, Any]) -> Dict[str, str]:
        """Get email template by type"""
        try:
            if template_type == 'welcome':
                token = f"verify_{user['id']}_{int(user['created_at'].timestamp())}"
                return BrandedEmailTemplates.welcome_email(
                    user['username'],
                    f"https://www.dnsscience.io/verify?token={token}"
                )

            elif template_type == 'checkin':
                days_since = (datetime.now() - user['created_at']).days
                stats = {
                    'domains_scanned': user.get('domains_scanned', 0),
                    'api_calls': user.get('api_calls', 0)
                }
                return BrandedEmailTemplates.checkin_email(
                    user['username'],
                    days_since,
                    stats
                )

            elif template_type == 'password':
                token = f"reset_{user['id']}_{int(datetime.now().timestamp())}"
                return BrandedEmailTemplates.password_reset_email(
                    user['username'],
                    f"https://www.dnsscience.io/reset?token={token}"
                )

            elif template_type == 'report':
                summary = {
                    'total_domains': 0,
                    'issues_found': 0,
                    'security_score': 0,
                    'critical_alerts': 0
                }
                return BrandedEmailTemplates.report_email(
                    user['username'],
                    "Sample Report",
                    summary
                )

            else:
                print(f"❌ Unknown template type: {template_type}")
                print("   Use: welcome, checkin, password, or report")
                return None

        except Exception as e:
            print(f"❌ Template error: {e}")
            return None


def main():
    parser = argparse.ArgumentParser(
        description='DNS Science Email Campaign Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send email from template file
  dnsscience-email send-template campaign.json user@example.com --vars '{"name":"John"}'

  # Send to specific user
  dnsscience-email send-user john@example.com --template welcome

  # Send to users who signed up this week
  dnsscience-email send-timeframe this_week --template checkin

  # Dry run (preview without sending)
  dnsscience-email send-timeframe this_month --template report --dry-run

  # Test SES connection
  dnsscience-email test-ses

  # List available templates
  dnsscience-email list-templates
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # send-template command
    template_parser = subparsers.add_parser('send-template', help='Send email from template file')
    template_parser.add_argument('template_file', help='Path to JSON template file')
    template_parser.add_argument('to_email', help='Recipient email address')
    template_parser.add_argument('--vars', help='JSON string of variables', default='{}')

    # send-user command
    user_parser = subparsers.add_parser('send-user', help='Send email to specific user')
    user_parser.add_argument('user_identifier', help='User ID, username, or email')
    user_parser.add_argument('--template', required=True, choices=['welcome', 'checkin', 'password', 'report'],
                            help='Email template to use')

    # send-timeframe command
    timeframe_parser = subparsers.add_parser('send-timeframe', help='Send campaign to users by signup time')
    timeframe_parser.add_argument('timeframe', choices=['today', 'this_week', 'last_week', 'this_month'],
                                 help='User signup timeframe')
    timeframe_parser.add_argument('--template', required=True, choices=['welcome', 'checkin', 'password', 'report'],
                                 help='Email template to use')
    timeframe_parser.add_argument('--dry-run', action='store_true', help='Preview without sending')

    # list-templates command
    subparsers.add_parser('list-templates', help='List available email templates')

    # test-ses command
    subparsers.add_parser('test-ses', help='Test AWS SES connection')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    cli = EmailCLI()

    if args.command == 'send-template':
        variables = json.loads(args.vars)
        cli.send_template(args.template_file, args.to_email, variables)

    elif args.command == 'send-user':
        cli.send_to_user(args.user_identifier, args.template)

    elif args.command == 'send-timeframe':
        cli.send_to_timeframe(args.timeframe, args.template, args.dry_run)

    elif args.command == 'list-templates':
        cli.list_templates()

    elif args.command == 'test-ses':
        cli.test_ses_connection()


if __name__ == '__main__':
    from datetime import datetime
    main()
