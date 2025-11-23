#!/usr/bin/env python3
"""
Distributed Queue Manager using Redis

For internet-scale scanning, use Redis queues to distribute work across multiple workers.

Setup:
1. Install Redis: brew install redis (macOS) or apt-get install redis (Linux)
2. Start Redis: redis-server
3. Install Python package: pip install redis rq
"""
import os
import redis
from rq import Queue, Worker
from rq.job import Job
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QueueManager:
    """Manage Redis queues for distributed scanning"""

    def __init__(self, redis_url=None):
        self.redis_url = redis_url or os.environ.get(
            'REDIS_URL',
            'redis://localhost:6379/0'
        )
        self.redis_conn = redis.from_url(self.redis_url)

        # Create queues with different priorities
        self.high_priority = Queue('high', connection=self.redis_conn)
        self.default_queue = Queue('default', connection=self.redis_conn)
        self.low_priority = Queue('low', connection=self.redis_conn)

    def enqueue_domain(self, domain, priority='default'):
        """Add a domain to the scanning queue"""
        from checkers import DomainScanner

        queue_map = {
            'high': self.high_priority,
            'default': self.default_queue,
            'low': self.low_priority
        }

        queue = queue_map.get(priority, self.default_queue)

        job = queue.enqueue(
            'queue_manager.scan_domain_worker',
            domain,
            job_timeout='5m',
            result_ttl=3600
        )

        logger.info(f"Queued {domain} (priority: {priority}, job: {job.id})")
        return job.id

    def enqueue_batch(self, domains, priority='default', batch_size=1000):
        """Add multiple domains to queue in batches"""
        total = len(domains)
        logger.info(f"Enqueueing {total:,} domains...")

        job_ids = []
        for i, domain in enumerate(domains, 1):
            job_id = self.enqueue_domain(domain, priority=priority)
            job_ids.append(job_id)

            if i % batch_size == 0:
                logger.info(f"Queued {i:,}/{total:,} domains")

        logger.info(f"✓ All {total:,} domains queued")
        return job_ids

    def enqueue_from_file(self, filename, priority='default'):
        """Enqueue domains from a file"""
        logger.info(f"Loading domains from {filename}...")

        domains = []
        with open(filename, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    domains.append(domain)

        logger.info(f"Loaded {len(domains):,} domains")
        return self.enqueue_batch(domains, priority=priority)

    def get_queue_stats(self):
        """Get statistics about queues"""
        stats = {
            'high_priority': {
                'queued': len(self.high_priority),
                'started': self.high_priority.started_job_registry.count,
                'finished': self.high_priority.finished_job_registry.count,
                'failed': self.high_priority.failed_job_registry.count
            },
            'default': {
                'queued': len(self.default_queue),
                'started': self.default_queue.started_job_registry.count,
                'finished': self.default_queue.finished_job_registry.count,
                'failed': self.default_queue.failed_job_registry.count
            },
            'low_priority': {
                'queued': len(self.low_priority),
                'started': self.low_priority.started_job_registry.count,
                'finished': self.low_priority.finished_job_registry.count,
                'failed': self.low_priority.failed_job_registry.count
            }
        }
        return stats

    def clear_queue(self, priority='default'):
        """Clear a queue"""
        queue_map = {
            'high': self.high_priority,
            'default': self.default_queue,
            'low': self.low_priority
        }

        queue = queue_map.get(priority, self.default_queue)
        count = len(queue)
        queue.empty()
        logger.info(f"Cleared {count} jobs from {priority} queue")


def scan_domain_worker(domain):
    """
    Worker function that scans a domain.
    This runs in the worker process.
    """
    from checkers import DomainScanner
    from database import Database
    import os

    # Use PostgreSQL if available, otherwise SQLite
    if os.environ.get('DATABASE_URL'):
        from database_postgres import PostgresDatabase
        db = PostgresDatabase()
    else:
        db = Database()

    scanner = DomainScanner()

    logger.info(f"Worker scanning {domain}")

    try:
        result = scanner.scan_domain(domain)
        db.save_scan_result(domain, result)
        logger.info(f"✓ Completed {domain}")
        return result

    except Exception as e:
        logger.error(f"✗ Failed {domain}: {e}")
        raise


def start_worker(queues=None, burst=False):
    """
    Start a worker process.

    Args:
        queues: List of queue names to listen to (default: ['high', 'default', 'low'])
        burst: If True, worker exits after all jobs complete (for testing)
    """
    redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    redis_conn = redis.from_url(redis_url)

    if queues is None:
        queues = ['high', 'default', 'low']

    logger.info(f"Starting worker for queues: {queues}")

    worker = Worker(queues, connection=redis_conn)
    worker.work(burst=burst)


def main():
    """CLI for queue management"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Distributed Queue Manager',
        epilog="""
SETUP:
1. Install Redis: brew install redis
2. Start Redis: redis-server
3. Install: pip install redis rq

USAGE:
  # Queue domains
  %(prog)s enqueue example.com
  %(prog)s enqueue-file domains.txt

  # Start workers (in separate terminals)
  %(prog)s worker
  %(prog)s worker --queues high default

  # Monitor queues
  %(prog)s stats
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Command')

    # Enqueue single domain
    enqueue_parser = subparsers.add_parser('enqueue', help='Queue a domain')
    enqueue_parser.add_argument('domain', help='Domain to scan')
    enqueue_parser.add_argument('-p', '--priority', choices=['high', 'default', 'low'],
                               default='default', help='Priority')

    # Enqueue from file
    enqueue_file_parser = subparsers.add_parser('enqueue-file', help='Queue domains from file')
    enqueue_file_parser.add_argument('file', help='File with domains')
    enqueue_file_parser.add_argument('-p', '--priority', choices=['high', 'default', 'low'],
                                    default='default', help='Priority')

    # Start worker
    worker_parser = subparsers.add_parser('worker', help='Start a worker')
    worker_parser.add_argument('--queues', nargs='+', help='Queue names to process')
    worker_parser.add_argument('--burst', action='store_true', help='Exit after completing all jobs')

    # Queue stats
    stats_parser = subparsers.add_parser('stats', help='Show queue statistics')

    # Clear queue
    clear_parser = subparsers.add_parser('clear', help='Clear a queue')
    clear_parser.add_argument('priority', choices=['high', 'default', 'low'], help='Queue to clear')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    qm = QueueManager()

    if args.command == 'enqueue':
        qm.enqueue_domain(args.domain, priority=args.priority)

    elif args.command == 'enqueue-file':
        qm.enqueue_from_file(args.file, priority=args.priority)

    elif args.command == 'worker':
        start_worker(queues=args.queues, burst=args.burst)

    elif args.command == 'stats':
        stats = qm.get_queue_stats()

        print("\n📊 Queue Statistics")
        print("=" * 70)

        for queue_name, queue_stats in stats.items():
            print(f"\n{queue_name.upper()} Priority:")
            print(f"  Queued:   {queue_stats['queued']:,}")
            print(f"  Started:  {queue_stats['started']:,}")
            print(f"  Finished: {queue_stats['finished']:,}")
            print(f"  Failed:   {queue_stats['failed']:,}")

        total_queued = sum(s['queued'] for s in stats.values())
        total_finished = sum(s['finished'] for s in stats.values())
        total_failed = sum(s['failed'] for s in stats.values())

        print(f"\nTOTAL:")
        print(f"  Queued:   {total_queued:,}")
        print(f"  Finished: {total_finished:,}")
        print(f"  Failed:   {total_failed:,}")
        print()

    elif args.command == 'clear':
        qm.clear_queue(args.priority)


if __name__ == '__main__':
    main()
