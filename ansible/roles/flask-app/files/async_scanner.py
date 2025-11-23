"""Async scan worker for background domain scanning"""
import redis
import json
import time
import uuid
from config import Config
from checkers import DomainScanner
from database import Database

class AsyncScanWorker:
    """Background worker for processing scan jobs"""

    def __init__(self):
        self.redis_client = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            decode_responses=True
        )
        self.scanner = DomainScanner()
        self.db = Database()

    def queue_scan(self, domain, check_ssl=True):
        """
        Queue a domain scan job.

        Args:
            domain: Domain to scan
            check_ssl: Whether to check SSL certificates

        Returns:
            str: Job ID for tracking
        """
        job_id = str(uuid.uuid4())

        job_data = {
            'job_id': job_id,
            'domain': domain,
            'check_ssl': check_ssl,
            'status': 'queued',
            'queued_at': time.time()
        }

        # Store job metadata
        self.redis_client.setex(
            f'scan:job:{job_id}',
            3600,  # 1 hour TTL
            json.dumps(job_data)
        )

        # Add to scan queue
        self.redis_client.lpush('scan:queue', job_id)

        return job_id

    def get_job_status(self, job_id):
        """
        Get status of a scan job.

        Args:
            job_id: Job ID to check

        Returns:
            dict: Job status and results if complete
        """
        job_key = f'scan:job:{job_id}'
        job_data = self.redis_client.get(job_key)

        if not job_data:
            return {'error': 'Job not found or expired'}

        job = json.loads(job_data)

        # Check if results are available
        result_key = f'scan:result:{job_id}'
        result_data = self.redis_client.get(result_key)

        if result_data:
            job['result'] = json.loads(result_data)

        return job

    def process_scan(self, job_id):
        """
        Process a single scan job.

        Args:
            job_id: Job ID to process
        """
        job_key = f'scan:job:{job_id}'
        job_data = self.redis_client.get(job_key)

        if not job_data:
            print(f"Job {job_id} not found")
            return

        job = json.loads(job_data)
        domain = job['domain']
        check_ssl = job.get('check_ssl', True)

        # Update status to processing
        job['status'] = 'processing'
        job['started_at'] = time.time()
        self.redis_client.setex(job_key, 3600, json.dumps(job))

        try:
            # Perform the scan with timeout
            scan_result = self.scanner.scan_domain(domain, check_ssl=check_ssl)

            # Save to database
            self.db.save_scan_result(domain, scan_result)

            # Save SSL certificates if present
            if 'ssl_certificates' in scan_result and scan_result['ssl_certificates']:
                self.db.save_certificates_batch(domain, scan_result['ssl_certificates'])

            # Update job status
            job['status'] = 'completed'
            job['completed_at'] = time.time()
            self.redis_client.setex(job_key, 3600, json.dumps(job))

            # Store result
            result_key = f'scan:result:{job_id}'
            self.redis_client.setex(result_key, 3600, json.dumps(scan_result))

        except Exception as e:
            # Update job status to failed
            job['status'] = 'failed'
            job['error'] = str(e)
            job['failed_at'] = time.time()
            self.redis_client.setex(job_key, 3600, json.dumps(job))
            print(f"Scan failed for {domain}: {e}")

    def run_worker(self):
        """
        Run the worker to process scan jobs from the queue.
        This should be run in a separate process/thread.
        """
        print("Starting async scan worker...")

        while True:
            try:
                # Block and wait for a job (timeout after 5 seconds to check for shutdown)
                job_id = self.redis_client.brpop('scan:queue', timeout=5)

                if job_id:
                    _, job_id = job_id  # brpop returns (queue_name, value)
                    print(f"Processing scan job: {job_id}")
                    self.process_scan(job_id)

            except KeyboardInterrupt:
                print("Worker shutting down...")
                break
            except Exception as e:
                print(f"Worker error: {e}")
                time.sleep(1)  # Brief pause before retrying

# Singleton instance
_worker_instance = None

def get_async_scanner():
    """Get singleton AsyncScanWorker instance"""
    global _worker_instance
    if _worker_instance is None:
        _worker_instance = AsyncScanWorker()
    return _worker_instance
