#!/usr/bin/env python3
"""
DNS Science - Base Daemon Class
Provides common functionality for all DNS Science daemons
"""

import os
import sys
import time
import signal
import logging
import psycopg2
import psycopg2.extensions
import redis
from datetime import datetime
from abc import ABC, abstractmethod

class BaseDaemon(ABC):
    """Base class for all DNS Science daemons"""

    def __init__(self, daemon_name, log_level=logging.INFO):
        self.daemon_name = daemon_name
        self.running = False
        self.log_dir = '/var/log/dnsscience'
        self.pid_dir = '/var/run/dnsscience'

        # Ensure directories exist
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.pid_dir, exist_ok=True)

        # Setup logging
        self.setup_logging(log_level)

        # Database and Redis connections (lazy loaded)
        self.db_conn = None
        self.redis_conn = None

        # Register signal handlers
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

        self.logger.info(f"{self.daemon_name} daemon initializing...")

    def setup_logging(self, log_level):
        """Configure logging to file and console"""
        log_file = os.path.join(self.log_dir, f'{self.daemon_name}.log')

        # Create logger
        self.logger = logging.getLogger(self.daemon_name)
        self.logger.setLevel(log_level)

        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def get_db_connection(self):
        """Get PostgreSQL connection via PgBouncer with auto-reconnect and transaction recovery"""
        if self.db_conn is None or self.db_conn.closed:
            try:
                # Try PgBouncer first (localhost:6432), fallback to direct RDS
                try:
                    self.db_conn = psycopg2.connect(
                        host='127.0.0.1',
                        port=6432,
                        dbname='dnsscience',
                        user='dnsscience',
                        password='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK',
                        connect_timeout=5,
                        options='-c statement_timeout=30000'
                    )
                    self.logger.debug("Connected via PgBouncer")
                except:
                    # Fallback to direct RDS connection
                    self.db_conn = psycopg2.connect(
                        host='dnsscience-db.c3iuy64is41m.us-east-1.rds.amazonaws.com',
                        port=5432,
                        dbname='dnsscience',
                        user='dnsscience',
                        password='lQZKcaumXsL0zxJAl4IBjMqGvq3dAAzK',
                        connect_timeout=10,
                        options='-c statement_timeout=30000'
                    )
                    self.logger.warning("Connected directly to RDS (PgBouncer unavailable)")

                self.db_conn.autocommit = False
                self.logger.info("Database connection established")
            except Exception as e:
                self.logger.error(f"Database connection failed: {e}")
                raise
        else:
            # Check if connection is in a failed transaction state
            try:
                status = self.db_conn.get_transaction_status()
                if status == psycopg2.extensions.TRANSACTION_STATUS_INERROR:
                    self.logger.warning("Transaction in error state, rolling back")
                    self.db_conn.rollback()
            except:
                # If we can't check status, close and reconnect
                try:
                    self.db_conn.close()
                except:
                    pass
                self.db_conn = None
                return self.get_db_connection()

        return self.db_conn

    def get_redis_connection(self):
        """Get Redis connection with auto-reconnect"""
        if self.redis_conn is None:
            try:
                self.redis_conn = redis.Redis(
                    host='dnsscience-redis.092cyw.0001.use1.cache.amazonaws.com',
                    port=6379,
                    db=0,
                    decode_responses=True,
                    socket_timeout=5,
                    socket_connect_timeout=5
                )
                self.redis_conn.ping()
                self.logger.info("Redis connection established")
            except Exception as e:
                self.logger.error(f"Redis connection failed: {e}")
                raise

        return self.redis_conn

    def write_pid_file(self):
        """Write PID file"""
        pid_file = os.path.join(self.pid_dir, f'{self.daemon_name}.pid')
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))

    def remove_pid_file(self):
        """Remove PID file"""
        pid_file = os.path.join(self.pid_dir, f'{self.daemon_name}.pid')
        try:
            os.remove(pid_file)
        except:
            pass

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False

    @abstractmethod
    def process_iteration(self):
        """
        Main processing logic for one iteration
        Must be implemented by subclasses
        Returns: True if work was done, False if idle
        """
        pass

    def get_sleep_duration(self, work_done):
        """
        Get sleep duration based on whether work was done
        Override in subclasses for custom behavior
        """
        return 1 if work_done else 30  # 1 second if busy, 30 seconds if idle

    def run(self):
        """Main daemon loop"""
        self.write_pid_file()
        self.running = True

        self.logger.info(f"{self.daemon_name} daemon started (PID: {os.getpid()})")

        try:
            while self.running:
                try:
                    # Execute one iteration
                    work_done = self.process_iteration()

                    # Update last run timestamp in Redis
                    try:
                        redis_conn = self.get_redis_connection()
                        redis_conn.set(
                            f'daemon:{self.daemon_name}:last_run',
                            datetime.utcnow().isoformat()
                        )
                    except:
                        pass  # Don't fail if Redis is down

                    # Sleep based on whether work was done
                    if self.running:
                        sleep_duration = self.get_sleep_duration(work_done)
                        time.sleep(sleep_duration)

                except Exception as e:
                    self.logger.error(f"Error in processing iteration: {e}", exc_info=True)
                    # Close DB connection after error to avoid keeping failed connections
                    self.close_db_connection()
                    time.sleep(60)  # Wait longer after error

                # Close DB connection when idle to free up connection pool
                if not work_done and self.running:
                    self.close_db_connection()

        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
        finally:
            self.cleanup()

    def close_db_connection(self):
        """Close database connection to free up pool slots"""
        if self.db_conn and not self.db_conn.closed:
            try:
                self.db_conn.close()
                self.db_conn = None
                self.logger.debug("Database connection closed")
            except:
                pass

    def cleanup(self):
        """Cleanup resources before shutdown"""
        self.logger.info(f"{self.daemon_name} daemon shutting down...")

        # Close database connection
        self.close_db_connection()

        # Close Redis connection
        if self.redis_conn:
            try:
                self.redis_conn.close()
                self.logger.info("Redis connection closed")
            except:
                pass

        self.remove_pid_file()
        self.logger.info(f"{self.daemon_name} daemon stopped")

    def cache_get(self, key, default=None):
        """Get value from Redis cache"""
        try:
            redis_conn = self.get_redis_connection()
            value = redis_conn.get(key)
            return value if value is not None else default
        except:
            return default

    def cache_set(self, key, value, expiry=3600):
        """Set value in Redis cache"""
        try:
            redis_conn = self.get_redis_connection()
            redis_conn.setex(key, expiry, value)
            return True
        except:
            return False

    def get_config(self, key, default=None):
        """Get configuration value from database or cache"""
        cache_key = f'config:{key}'

        # Try cache first
        cached = self.cache_get(cache_key)
        if cached is not None:
            return cached

        # Query database
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM system_config WHERE key = %s",
                (key,)
            )
            row = cursor.fetchone()
            cursor.close()

            if row:
                value = row[0]
                self.cache_set(cache_key, value, 300)  # Cache for 5 minutes
                return value
        except:
            pass

        return default
