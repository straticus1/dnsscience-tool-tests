#!/usr/bin/env python3
"""
DNS Science - p0f Passive OS Fingerprinting Daemon
Analyzes network traffic to identify client operating systems and applications
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from base_daemon import BaseDaemon
import subprocess
import json
import re
from datetime import datetime

class P0fDaemon(BaseDaemon):
    """Daemon for p0f passive OS fingerprinting"""

    def __init__(self):
        super().__init__('dnsscience_p0f')
        self.p0f_process = None
        self.p0f_log = '/var/log/p0f/p0f.log'
        self.last_processed_line = 0

    def start_p0f(self):
        """Start p0f in background if not already running"""
        try:
            # Check if p0f is already running
            result = subprocess.run(['pgrep', '-x', 'p0f'], capture_output=True)
            if result.returncode == 0:
                self.logger.info("p0f already running")
                return True

            # Start p0f on the network interface
            # -i any = listen on all interfaces
            # -p = promiscuous mode
            # -o = output log file
            # -d = daemon mode
            cmd = ['p0f', '-i', 'any', '-p', '-o', self.p0f_log, '-d']
            subprocess.run(cmd, check=True)
            self.logger.info("Started p0f passive fingerprinting")
            return True

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to start p0f: {e}")
            return False
        except FileNotFoundError:
            self.logger.error("p0f not installed")
            return False

    def process_iteration(self):
        """Process p0f log and store fingerprints"""
        work_done = False

        try:
            # Ensure p0f is running
            if not self.start_p0f():
                return False

            # Read new lines from p0f log
            if not os.path.exists(self.p0f_log):
                return False

            conn = self.get_db_connection()
            cursor = conn.cursor()

            with open(self.p0f_log, 'r') as f:
                lines = f.readlines()
                new_lines = lines[self.last_processed_line:]

                for line in new_lines:
                    if self.process_p0f_line(line, cursor):
                        work_done = True

                self.last_processed_line = len(lines)

            if work_done:
                conn.commit()

        except Exception as e:
            self.logger.error(f"Error in p0f daemon: {e}")
            if conn:
                conn.rollback()

        return work_done

    def process_p0f_line(self, line, cursor):
        """Parse and store a single p0f log line"""
        try:
            # p0f output format: mod=mtu|cli=1.2.3.4/12345|srv=5.6.7.8/80|subj=cli|os=Linux 3.x|dist=10|params=...
            if not line.startswith('mod='):
                return False

            # Parse p0f output
            data = {}
            for part in line.strip().split('|'):
                if '=' in part:
                    key, value = part.split('=', 1)
                    data[key] = value

            if 'cli' not in data or 'os' not in data:
                return False

            # Extract client IP
            client_ip = data.get('cli', '').split('/')[0]
            if not client_ip:
                return False

            # Store fingerprint
            cursor.execute("""
                INSERT INTO p0f_fingerprints
                (client_ip, os_name, os_version, distance, link_type,
                 language, uptime, raw_sig, first_seen, last_seen)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                ON CONFLICT (client_ip) DO UPDATE
                SET os_name = EXCLUDED.os_name,
                    os_version = EXCLUDED.os_version,
                    distance = EXCLUDED.distance,
                    link_type = EXCLUDED.link_type,
                    language = EXCLUDED.language,
                    uptime = EXCLUDED.uptime,
                    raw_sig = EXCLUDED.raw_sig,
                    last_seen = NOW(),
                    seen_count = p0f_fingerprints.seen_count + 1
            """, (
                client_ip,
                data.get('os', 'Unknown'),
                data.get('ver', ''),
                data.get('dist', 0),
                data.get('link', ''),
                data.get('lang', ''),
                data.get('uptime', ''),
                line.strip()
            ))

            self.logger.info(f"Fingerprinted {client_ip}: {data.get('os', 'Unknown')}")
            return True

        except Exception as e:
            self.logger.error(f"Error processing p0f line: {e}")
            return False

    def cleanup(self):
        """Stop p0f on shutdown"""
        try:
            subprocess.run(['pkill', '-x', 'p0f'], check=False)
            self.logger.info("Stopped p0f process")
        except:
            pass
        super().cleanup()

if __name__ == '__main__':
    daemon = P0fDaemon()
    daemon.run()
