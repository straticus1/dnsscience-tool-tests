#!/usr/bin/env python3
"""
Trial Reminder Daemon
Runs continuously, checking for expiring trials once per day
"""

import time
import logging
from trial_manager import TrialManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger('trial_daemon')

def main():
    """Main daemon loop"""
    logger.info("Trial Reminder Daemon started")

    trial_mgr = TrialManager()

    while True:
        try:
            logger.info("Checking for expiring trials...")
            result = trial_mgr.check_expiring_trials()

            if result.get('success'):
                reminders_sent = result.get('reminders_sent', 0)
                logger.info(f"Trial check complete: {reminders_sent} reminders sent")
            else:
                logger.error(f"Trial check failed: {result.get('error')}")

        except Exception as e:
            logger.error(f"Error in trial check: {e}", exc_info=True)

        # Sleep for 24 hours (86400 seconds)
        logger.info("Sleeping for 24 hours until next check")
        time.sleep(86400)


if __name__ == '__main__':
    main()
