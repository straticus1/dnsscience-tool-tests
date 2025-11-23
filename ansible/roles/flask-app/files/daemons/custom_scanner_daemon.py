#!/usr/bin/env python3
"""
DNS Science - Custom Scanner Daemon
Runs scheduled custom scanners automatically
"""

import sys
import os
import time
import signal
import logging
from datetime import datetime
from typing import List, Dict

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Database
from custom_scanners import CustomScannerManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/dnsscience/custom_scanner_daemon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CustomScannerDaemon:
    """Daemon for running scheduled custom scanners"""

    def __init__(self):
        """Initialize daemon"""
        self.db = Database()
        self.scanner_manager = CustomScannerManager(self.db)
        self.running = True
        self.check_interval = 60  # Check every 60 seconds

        # Handle shutdown signals
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        signal.signal(signal.SIGINT, self.handle_shutdown)

    def handle_shutdown(self, signum, frame):
        """Handle shutdown signal"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False

    def get_scanners_ready_to_run(self) -> List[Dict]:
        """Get scanners that are due to run"""
        conn = self.db.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM scanners_ready_to_run
                    ORDER BY next_run_at ASC NULLS FIRST
                """)

                columns = [desc[0] for desc in cursor.description]
                scanners = []
                for row in cursor.fetchall():
                    scanners.append(dict(zip(columns, row)))

                return scanners
        finally:
            self.db.return_connection(conn)

    def run_scanner(self, scanner: Dict):
        """Execute a scanner"""
        scanner_id = scanner['id']
        scanner_name = scanner['scanner_name']
        user_id = scanner['user_id']

        logger.info(f"Running scanner: {scanner_name} (ID: {scanner_id})")

        try:
            result = self.scanner_manager.run_scanner(
                scanner_id=scanner_id,
                user_id=user_id,
                trigger_type='scheduled'
            )

            logger.info(
                f"Scanner {scanner_name} completed: "
                f"{result['successful_scans']} successful, "
                f"{result['failed_scans']} failed, "
                f"{result['alerts_triggered']} alerts"
            )

            return True

        except Exception as e:
            logger.error(f"Error running scanner {scanner_name}: {e}", exc_info=True)

            # Update scanner status
            conn = self.db.get_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE custom_scanners
                        SET status = 'error', error_message = %s
                        WHERE id = %s
                    """, (str(e), scanner_id))
                    conn.commit()
            except Exception as db_error:
                logger.error(f"Failed to update scanner status: {db_error}")
                conn.rollback()
            finally:
                self.db.return_connection(conn)

            return False

    def run(self):
        """Main daemon loop"""
        logger.info("Custom Scanner Daemon started")

        while self.running:
            try:
                # Get scanners ready to run
                scanners = self.get_scanners_ready_to_run()

                if scanners:
                    logger.info(f"Found {len(scanners)} scanner(s) ready to run")

                    for scanner in scanners:
                        if not self.running:
                            break

                        self.run_scanner(scanner)

                        # Small delay between scanners
                        time.sleep(5)

                # Sleep before next check
                logger.debug(f"Sleeping for {self.check_interval} seconds...")
                time.sleep(self.check_interval)

            except KeyboardInterrupt:
                logger.info("Received keyboard interrupt")
                break

            except Exception as e:
                logger.error(f"Daemon error: {e}", exc_info=True)
                time.sleep(60)  # Sleep longer on error

        logger.info("Custom Scanner Daemon stopped")

    def cleanup(self):
        """Cleanup resources"""
        try:
            if self.db:
                self.db.close_all_connections()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


def main():
    """Main entry point"""
    daemon = CustomScannerDaemon()

    try:
        daemon.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        daemon.cleanup()

    sys.exit(0)


if __name__ == '__main__':
    main()
