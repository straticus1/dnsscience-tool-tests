#!/usr/bin/env python3
"""
DNS Science Ticket Management CLI Tool

A comprehensive command-line tool for managing DNS Science tickets.
Supports authentication, ticket CRUD operations, comments, watching,
and multiple output formats.

Author: DNS Science
Version: 1.0.0
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# Version
VERSION = "1.0.0"

# Default configuration
DEFAULT_API_BASE = "https://www.dnsscience.io"
CONFIG_DIR = Path.home() / ".dnsscience"
CONFIG_FILE = CONFIG_DIR / "tickets.json"

# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    ORANGE = "\033[38;5;208m"
    GRAY = "\033[90m"


class TicketsCLI:
    """DNS Science Tickets CLI client."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.config = self.load_config()
        self.use_colors = not getattr(args, 'no_color', False) and sys.stdout.isatty()
        self.verbose = getattr(args, 'verbose', False)
        self.api_base = getattr(args, 'api_base', None) or self.config.get('api_base', DEFAULT_API_BASE)
        self.session = requests.Session()
        self._setup_auth()

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                if self.verbose:
                    self.error(f"Failed to load config: {e}")
        return {}

    def save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to file."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        os.chmod(CONFIG_FILE, 0o600)

    def _setup_auth(self) -> None:
        """Setup authentication headers/cookies."""
        # API key takes precedence
        api_key = getattr(self.args, 'api_key', None) or self.config.get('api_key')
        if api_key:
            self.session.headers['X-API-Key'] = api_key

        # Load session cookie if available
        session_cookie = self.config.get('session_cookie')
        if session_cookie:
            self.session.cookies.set('session', session_cookie, domain=self._get_domain())

    def _get_domain(self) -> str:
        """Extract domain from API base URL."""
        from urllib.parse import urlparse
        return urlparse(self.api_base).netloc

    def color(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if not self.use_colors:
            return text
        return f"{color}{text}{Colors.RESET}"

    def status_color(self, status: str) -> str:
        """Get colored status text."""
        status_colors = {
            'open': Colors.YELLOW,
            'in_progress': Colors.CYAN,
            'resolved': Colors.GREEN,
            'closed': Colors.GRAY,
            'critical': Colors.RED,
        }
        color = status_colors.get(status.lower(), Colors.RESET)
        return self.color(status, color)

    def priority_color(self, priority: str) -> str:
        """Get colored priority text."""
        priority_colors = {
            'critical': Colors.RED,
            'high': Colors.ORANGE,
            'medium': Colors.YELLOW,
            'low': Colors.GREEN,
            'info': Colors.BLUE,
        }
        color = priority_colors.get(priority.lower(), Colors.RESET)
        return self.color(priority, color)

    def error(self, message: str) -> None:
        """Print error message."""
        prefix = self.color("Error:", Colors.RED)
        print(f"{prefix} {message}", file=sys.stderr)

    def success(self, message: str) -> None:
        """Print success message."""
        prefix = self.color("Success:", Colors.GREEN)
        print(f"{prefix} {message}")

    def info(self, message: str) -> None:
        """Print info message."""
        prefix = self.color("Info:", Colors.BLUE)
        print(f"{prefix} {message}")

    def debug(self, message: str) -> None:
        """Print debug message if verbose mode is enabled."""
        if self.verbose:
            prefix = self.color("Debug:", Colors.GRAY)
            print(f"{prefix} {message}", file=sys.stderr)

    def api_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make API request."""
        url = f"{self.api_base}/api{endpoint}"
        self.debug(f"{method.upper()} {url}")

        try:
            response = self.session.request(method, url, **kwargs)
            self.debug(f"Response: {response.status_code}")
            return response
        except requests.RequestException as e:
            self.error(f"Request failed: {e}")
            sys.exit(1)

    def handle_response(self, response: requests.Response, success_message: Optional[str] = None) -> Any:
        """Handle API response."""
        if response.status_code == 401:
            self.error("Authentication required. Please login or provide an API key.")
            sys.exit(1)
        elif response.status_code == 403:
            self.error("Access denied. Insufficient permissions.")
            sys.exit(1)
        elif response.status_code == 404:
            self.error("Resource not found.")
            sys.exit(1)
        elif response.status_code >= 400:
            try:
                error_data = response.json()
                self.error(error_data.get('error', f"Request failed with status {response.status_code}"))
            except json.JSONDecodeError:
                self.error(f"Request failed with status {response.status_code}")
            sys.exit(1)

        if success_message:
            self.success(success_message)

        try:
            return response.json()
        except json.JSONDecodeError:
            return None

    def format_output(self, data: Any, columns: Optional[List[str]] = None) -> str:
        """Format output based on format argument."""
        output_format = getattr(self.args, 'format', 'table')

        if output_format == 'json':
            return json.dumps(data, indent=2, default=str)
        elif output_format == 'csv':
            return self.format_csv(data, columns)
        else:  # table
            return self.format_table(data, columns)

    def format_csv(self, data: Any, columns: Optional[List[str]] = None) -> str:
        """Format data as CSV."""
        if not data:
            return ""

        output = StringIO()
        if isinstance(data, list):
            if not data:
                return ""
            if columns:
                writer = csv.DictWriter(output, fieldnames=columns, extrasaction='ignore')
            else:
                writer = csv.DictWriter(output, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        elif isinstance(data, dict):
            writer = csv.writer(output)
            for key, value in data.items():
                writer.writerow([key, value])

        return output.getvalue().strip()

    def format_table(self, data: Any, columns: Optional[List[str]] = None) -> str:
        """Format data as pretty table."""
        if not data:
            return "No data to display."

        if isinstance(data, dict) and not isinstance(data, list):
            # Single item or key-value pairs
            if 'id' in data:
                # Single ticket
                return self.format_ticket_detail(data)
            else:
                # Key-value pairs (stats)
                return self.format_key_value_table(data)

        if not isinstance(data, list) or not data:
            return "No data to display."

        # List of items
        if not columns:
            columns = list(data[0].keys())

        # Calculate column widths
        widths = {col: len(col) for col in columns}
        for row in data:
            for col in columns:
                value = str(row.get(col, ''))
                # Strip ANSI codes for width calculation
                clean_value = self._strip_ansi(value)
                widths[col] = max(widths[col], len(clean_value))

        # Build table
        lines = []

        # Top border
        top = "+" + "+".join("-" * (widths[col] + 2) for col in columns) + "+"
        lines.append(top)

        # Header
        header = "|" + "|".join(f" {self.color(col.upper(), Colors.BOLD):^{widths[col]}} " for col in columns) + "|"
        lines.append(header)

        # Header separator
        sep = "+" + "+".join("=" * (widths[col] + 2) for col in columns) + "+"
        lines.append(sep)

        # Data rows
        for row in data:
            values = []
            for col in columns:
                value = row.get(col, '')
                if col == 'status':
                    value = self.status_color(str(value))
                elif col == 'priority':
                    value = self.priority_color(str(value))
                else:
                    value = str(value) if value is not None else ''

                # Calculate padding with ANSI codes
                clean_len = len(self._strip_ansi(value))
                padding = widths[col] - clean_len
                values.append(f" {value}{' ' * padding} ")

            lines.append("|" + "|".join(values) + "|")

        # Bottom border
        lines.append(top)

        return "\n".join(lines)

    def format_ticket_detail(self, ticket: Dict[str, Any]) -> str:
        """Format single ticket detail view."""
        lines = []

        # Header
        lines.append(self.color(f"Ticket #{ticket.get('id', 'N/A')}", Colors.BOLD + Colors.CYAN))
        lines.append("=" * 60)

        # Main fields
        fields = [
            ('Title', ticket.get('title', 'N/A')),
            ('Status', self.status_color(ticket.get('status', 'N/A'))),
            ('Priority', self.priority_color(ticket.get('priority', 'N/A'))),
            ('Category', ticket.get('category', 'N/A')),
            ('Domain', ticket.get('domain', 'N/A')),
            ('Assignee', ticket.get('assignee', 'Unassigned')),
            ('Created', ticket.get('created_at', 'N/A')),
            ('Updated', ticket.get('updated_at', 'N/A')),
        ]

        for label, value in fields:
            lines.append(f"{self.color(label + ':', Colors.BOLD):20} {value}")

        # Description
        if ticket.get('description'):
            lines.append("")
            lines.append(self.color("Description:", Colors.BOLD))
            lines.append(ticket['description'])

        # Compliance frameworks
        if ticket.get('compliance_frameworks'):
            lines.append("")
            lines.append(self.color("Compliance Frameworks:", Colors.BOLD))
            lines.append(", ".join(ticket['compliance_frameworks']))

        # Comments
        if ticket.get('comments'):
            lines.append("")
            lines.append(self.color("Comments:", Colors.BOLD))
            lines.append("-" * 40)
            for comment in ticket['comments']:
                author = comment.get('author', 'Unknown')
                created = comment.get('created_at', '')
                text = comment.get('text', '')
                lines.append(f"{self.color(author, Colors.CYAN)} ({created}):")
                lines.append(f"  {text}")
                lines.append("")

        return "\n".join(lines)

    def format_key_value_table(self, data: Dict[str, Any]) -> str:
        """Format key-value pairs as table."""
        lines = []

        max_key_len = max(len(str(k)) for k in data.keys())

        lines.append("+" + "-" * (max_key_len + 2) + "+" + "-" * 20 + "+")

        for key, value in data.items():
            key_str = str(key).replace('_', ' ').title()
            value_str = str(value)
            lines.append(f"| {key_str:<{max_key_len}} | {value_str:<18} |")

        lines.append("+" + "-" * (max_key_len + 2) + "+" + "-" * 20 + "+")

        return "\n".join(lines)

    def _strip_ansi(self, text: str) -> str:
        """Strip ANSI codes from text."""
        import re
        return re.sub(r'\033\[[0-9;]*m', '', text)

    # Command implementations
    def cmd_list(self) -> None:
        """List tickets with optional filters."""
        params = {}

        if hasattr(self.args, 'status') and self.args.status:
            params['status'] = self.args.status
        if hasattr(self.args, 'priority') and self.args.priority:
            params['priority'] = self.args.priority
        if hasattr(self.args, 'category') and self.args.category:
            params['category'] = self.args.category
        if hasattr(self.args, 'assignee') and self.args.assignee:
            params['assignee'] = self.args.assignee
        if hasattr(self.args, 'domain') and self.args.domain:
            params['domain'] = self.args.domain
        if hasattr(self.args, 'limit') and self.args.limit:
            params['limit'] = self.args.limit
        if hasattr(self.args, 'offset') and self.args.offset:
            params['offset'] = self.args.offset

        response = self.api_request('GET', '/tickets', params=params)
        data = self.handle_response(response)

        tickets = data.get('tickets', data) if isinstance(data, dict) else data

        columns = ['id', 'title', 'status', 'priority', 'category', 'created_at']
        output = self.format_output(tickets, columns)
        print(output)

    def cmd_view(self) -> None:
        """View ticket details."""
        ticket_id = self.args.id

        response = self.api_request('GET', f'/tickets/{ticket_id}')
        ticket = self.handle_response(response)

        # Fetch comments if requested
        if getattr(self.args, 'comments', False):
            comments_response = self.api_request('GET', f'/tickets/{ticket_id}/comments')
            comments = self.handle_response(comments_response)
            ticket['comments'] = comments.get('comments', comments) if isinstance(comments, dict) else comments

        output = self.format_output(ticket)
        print(output)

    def cmd_create(self) -> None:
        """Create a new ticket."""
        payload = {
            'title': self.args.title,
            'description': self.args.description,
            'priority': self.args.priority,
            'category': self.args.category,
        }

        if hasattr(self.args, 'domain') and self.args.domain:
            payload['domain'] = self.args.domain
        if hasattr(self.args, 'assignee') and self.args.assignee:
            payload['assignee'] = self.args.assignee
        if hasattr(self.args, 'compliance') and self.args.compliance:
            payload['compliance_frameworks'] = self.args.compliance

        response = self.api_request('POST', '/tickets', json=payload)
        ticket = self.handle_response(response, "Ticket created successfully")

        if ticket:
            ticket_id = ticket.get('id', ticket.get('ticket_id', 'N/A'))
            print(f"Ticket ID: {self.color(str(ticket_id), Colors.CYAN)}")

    def cmd_update(self) -> None:
        """Update a ticket."""
        ticket_id = self.args.id
        payload = {}

        if hasattr(self.args, 'status') and self.args.status:
            payload['status'] = self.args.status
        if hasattr(self.args, 'priority') and self.args.priority:
            payload['priority'] = self.args.priority
        if hasattr(self.args, 'assignee') and self.args.assignee:
            payload['assignee'] = self.args.assignee
        if hasattr(self.args, 'title') and self.args.title:
            payload['title'] = self.args.title
        if hasattr(self.args, 'description') and self.args.description:
            payload['description'] = self.args.description
        if hasattr(self.args, 'compliance') and self.args.compliance:
            payload['compliance_frameworks'] = self.args.compliance

        if not payload:
            self.error("No updates specified. Use --status, --priority, --assignee, etc.")
            sys.exit(1)

        response = self.api_request('PUT', f'/tickets/{ticket_id}', json=payload)
        self.handle_response(response, f"Ticket {ticket_id} updated successfully")

    def cmd_comment(self) -> None:
        """Add a comment to a ticket."""
        ticket_id = self.args.id
        comment_text = self.args.text

        payload = {'text': comment_text}

        if hasattr(self.args, 'internal') and self.args.internal:
            payload['internal'] = True

        response = self.api_request('POST', f'/tickets/{ticket_id}/comments', json=payload)
        self.handle_response(response, f"Comment added to ticket {ticket_id}")

    def cmd_close(self) -> None:
        """Close a ticket."""
        ticket_id = self.args.id

        payload = {'status': 'closed'}
        if hasattr(self.args, 'reason') and self.args.reason:
            payload['resolution'] = self.args.reason

        response = self.api_request('PUT', f'/tickets/{ticket_id}', json=payload)
        self.handle_response(response, f"Ticket {ticket_id} closed")

    def cmd_watch(self) -> None:
        """Watch a ticket."""
        ticket_id = self.args.id

        response = self.api_request('POST', f'/tickets/{ticket_id}/watch')
        self.handle_response(response, f"Now watching ticket {ticket_id}")

    def cmd_unwatch(self) -> None:
        """Unwatch a ticket."""
        ticket_id = self.args.id

        response = self.api_request('DELETE', f'/tickets/{ticket_id}/watch')
        self.handle_response(response, f"Stopped watching ticket {ticket_id}")

    def cmd_stats(self) -> None:
        """Show ticket statistics."""
        response = self.api_request('GET', '/tickets/stats')
        stats = self.handle_response(response)

        output = self.format_output(stats)
        print(output)

    def cmd_templates(self) -> None:
        """List available ticket templates."""
        response = self.api_request('GET', '/tickets/templates')
        templates = self.handle_response(response)

        template_list = templates.get('templates', templates) if isinstance(templates, dict) else templates

        columns = ['name', 'category', 'description']
        output = self.format_output(template_list, columns)
        print(output)

    def cmd_login(self) -> None:
        """Login and store session."""
        email = self.args.email
        password = self.args.password

        payload = {
            'email': email,
            'password': password
        }

        response = self.api_request('POST', '/auth/login', json=payload)

        if response.status_code == 200:
            # Extract session cookie
            session_cookie = response.cookies.get('session')
            if session_cookie:
                self.config['session_cookie'] = session_cookie
                self.save_config(self.config)
                self.success("Login successful. Session saved.")
            else:
                # Try to get token from response
                data = response.json()
                if 'token' in data:
                    self.config['api_key'] = data['token']
                    self.save_config(self.config)
                    self.success("Login successful. Token saved.")
                else:
                    self.success("Login successful.")
        else:
            self.handle_response(response)

    def cmd_logout(self) -> None:
        """Clear stored session."""
        if 'session_cookie' in self.config:
            del self.config['session_cookie']
        if 'api_key' in self.config:
            del self.config['api_key']

        self.save_config(self.config)
        self.success("Logged out successfully. Session cleared.")

    def cmd_config(self) -> None:
        """Show or set configuration."""
        if hasattr(self.args, 'set_key') and self.args.set_key:
            key, value = self.args.set_key
            self.config[key] = value
            self.save_config(self.config)
            self.success(f"Configuration updated: {key} = {value}")
        elif hasattr(self.args, 'get_key') and self.args.get_key:
            key = self.args.get_key
            value = self.config.get(key, 'Not set')
            print(f"{key}: {value}")
        elif hasattr(self.args, 'api_key_value') and self.args.api_key_value:
            self.config['api_key'] = self.args.api_key_value
            self.save_config(self.config)
            self.success("API key saved.")
        else:
            # Show all config
            print(self.color("Configuration:", Colors.BOLD))
            print(f"Config file: {CONFIG_FILE}")
            print(f"API Base: {self.config.get('api_base', DEFAULT_API_BASE)}")
            print(f"API Key: {'*' * 8 if self.config.get('api_key') else 'Not set'}")
            print(f"Session: {'Active' if self.config.get('session_cookie') else 'Not set'}")


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog='dnsscience_tickets.py',
        description='DNS Science Ticket Management CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all open tickets
  %(prog)s list --status open

  # Create a ticket
  %(prog)s create --title "SSL Expiry Alert" --description "Certificate expiring" \\
      --priority high --category ssl_expiry --domain example.com

  # View ticket with comments
  %(prog)s view 123 --comments

  # Add a comment
  %(prog)s comment 123 "Investigating the issue"

  # Update ticket status
  %(prog)s update 123 --status in_progress --assignee admin

  # Close ticket with reason
  %(prog)s close 123 --reason "Issue resolved"

  # Get statistics in JSON format
  %(prog)s stats --format json

  # Login with credentials
  %(prog)s login --email admin@dnsscience.io --password mypassword

  # Set API key
  %(prog)s config --api-key YOUR_API_KEY

  # Watch a ticket
  %(prog)s watch 123

Configuration:
  Config file: ~/.dnsscience/tickets.json

  You can authenticate using:
  - API key: %(prog)s config --api-key YOUR_KEY
  - Session: %(prog)s login --email EMAIL --password PASSWORD
  - Command line: %(prog)s --api-key YOUR_KEY list
"""
    )

    # Global arguments
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('--api-key', dest='api_key', help='API key for authentication')
    parser.add_argument('--api-base', dest='api_base', help=f'API base URL (default: {DEFAULT_API_BASE})')
    parser.add_argument('--format', choices=['table', 'json', 'csv'], default='table',
                        help='Output format (default: table)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # list command
    list_parser = subparsers.add_parser('list', help='List tickets')
    list_parser.add_argument('--status', choices=['open', 'in_progress', 'resolved', 'closed'],
                             help='Filter by status')
    list_parser.add_argument('--priority', choices=['critical', 'high', 'medium', 'low', 'info'],
                             help='Filter by priority')
    list_parser.add_argument('--category', help='Filter by category')
    list_parser.add_argument('--assignee', help='Filter by assignee')
    list_parser.add_argument('--domain', help='Filter by domain')
    list_parser.add_argument('--limit', type=int, default=50, help='Limit results (default: 50)')
    list_parser.add_argument('--offset', type=int, default=0, help='Offset for pagination')

    # view command
    view_parser = subparsers.add_parser('view', help='View ticket details')
    view_parser.add_argument('id', type=int, help='Ticket ID')
    view_parser.add_argument('--comments', action='store_true', help='Include comments')

    # create command
    create_parser = subparsers.add_parser('create', help='Create a new ticket')
    create_parser.add_argument('--title', required=True, help='Ticket title')
    create_parser.add_argument('--description', required=True, help='Ticket description')
    create_parser.add_argument('--priority', required=True,
                               choices=['critical', 'high', 'medium', 'low', 'info'],
                               help='Ticket priority')
    create_parser.add_argument('--category', required=True, help='Ticket category')
    create_parser.add_argument('--domain', help='Associated domain')
    create_parser.add_argument('--assignee', help='Assign to user')
    create_parser.add_argument('--compliance', nargs='+',
                               help='Compliance frameworks (e.g., SOC2 HIPAA PCI-DSS)')

    # update command
    update_parser = subparsers.add_parser('update', help='Update a ticket')
    update_parser.add_argument('id', type=int, help='Ticket ID')
    update_parser.add_argument('--status', choices=['open', 'in_progress', 'resolved', 'closed'],
                               help='New status')
    update_parser.add_argument('--priority', choices=['critical', 'high', 'medium', 'low', 'info'],
                               help='New priority')
    update_parser.add_argument('--assignee', help='New assignee')
    update_parser.add_argument('--title', help='New title')
    update_parser.add_argument('--description', help='New description')
    update_parser.add_argument('--compliance', nargs='+', help='Compliance frameworks')

    # comment command
    comment_parser = subparsers.add_parser('comment', help='Add a comment to a ticket')
    comment_parser.add_argument('id', type=int, help='Ticket ID')
    comment_parser.add_argument('text', help='Comment text')
    comment_parser.add_argument('--internal', action='store_true', help='Mark as internal comment')

    # close command
    close_parser = subparsers.add_parser('close', help='Close a ticket')
    close_parser.add_argument('id', type=int, help='Ticket ID')
    close_parser.add_argument('--reason', help='Resolution reason')

    # watch command
    watch_parser = subparsers.add_parser('watch', help='Watch a ticket')
    watch_parser.add_argument('id', type=int, help='Ticket ID')

    # unwatch command
    unwatch_parser = subparsers.add_parser('unwatch', help='Unwatch a ticket')
    unwatch_parser.add_argument('id', type=int, help='Ticket ID')

    # stats command
    subparsers.add_parser('stats', help='Show ticket statistics')

    # templates command
    subparsers.add_parser('templates', help='List available ticket templates')

    # login command
    login_parser = subparsers.add_parser('login', help='Login and store session')
    login_parser.add_argument('--email', required=True, help='Email address')
    login_parser.add_argument('--password', required=True, help='Password')

    # logout command
    subparsers.add_parser('logout', help='Clear stored session')

    # config command
    config_parser = subparsers.add_parser('config', help='Show or set configuration')
    config_parser.add_argument('--api-key', dest='api_key_value', help='Set API key')
    config_parser.add_argument('--set', dest='set_key', nargs=2, metavar=('KEY', 'VALUE'),
                               help='Set configuration value')
    config_parser.add_argument('--get', dest='get_key', metavar='KEY',
                               help='Get configuration value')

    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    cli = TicketsCLI(args)

    # Command dispatch
    commands = {
        'list': cli.cmd_list,
        'view': cli.cmd_view,
        'create': cli.cmd_create,
        'update': cli.cmd_update,
        'comment': cli.cmd_comment,
        'close': cli.cmd_close,
        'watch': cli.cmd_watch,
        'unwatch': cli.cmd_unwatch,
        'stats': cli.cmd_stats,
        'templates': cli.cmd_templates,
        'login': cli.cmd_login,
        'logout': cli.cmd_logout,
        'config': cli.cmd_config,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
