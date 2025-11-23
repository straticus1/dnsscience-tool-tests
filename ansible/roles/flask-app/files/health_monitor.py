#!/usr/bin/env python3
"""
Health Monitoring Script for DNS Science
Runs on instance to report health metrics to CloudWatch
"""

import os
import sys
import time
import psutil
import subprocess
import requests
import boto3
from datetime import datetime

# Configuration
NAMESPACE = "DNSScience/Application"
CLOUDWATCH = boto3.client('cloudwatch', region_name='us-east-1')

EXPECTED_DAEMONS = [
    "domain_discovery_daemon.py",
    "rdap_daemon.py",
    "domain_expiry_daemon.py",
    "email_scheduler_daemon.py",
    "trial_reminder_daemon.py",
    "auto_renewal_daemon.py",
    "domain_acquisition_daemon.py",
    "arpad_daemon_updated.py",
]

def get_instance_id():
    """Get EC2 instance ID"""
    try:
        response = requests.get(
            'http://169.254.169.254/latest/meta-data/instance-id',
            timeout=2
        )
        return response.text
    except:
        return "unknown"

def check_apache():
    """Check if Apache is running"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'apache2'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False

def check_health_endpoint():
    """Check application health endpoint"""
    try:
        response = requests.get('http://localhost/health', timeout=5)
        return response.status_code == 200
    except:
        return False

def count_running_daemons():
    """Count running daemon processes"""
    count = 0
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info['cmdline'] or [])
            if 'python3' in cmdline and 'daemon' in cmdline:
                count += 1
        except:
            pass
    return count

def check_database_connection():
    """Check database connectivity"""
    try:
        import psycopg2
        from dotenv import load_dotenv

        load_dotenv('/var/www/dnsscience/.env')

        conn = psycopg2.connect(
            host=os.getenv('DB_HOST'),
            port=os.getenv('DB_PORT', 5432),
            database=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASS'),
            connect_timeout=5
        )
        conn.close()
        return True
    except:
        return False

def check_redis_connection():
    """Check Redis connectivity"""
    try:
        import redis
        from dotenv import load_dotenv

        load_dotenv('/var/www/dnsscience/.env')

        r = redis.Redis(
            host=os.getenv('REDIS_HOST'),
            port=int(os.getenv('REDIS_PORT', 6379)),
            socket_connect_timeout=5
        )
        r.ping()
        return True
    except:
        return False

def get_system_metrics():
    """Get system resource metrics"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    return {
        'cpu_percent': cpu_percent,
        'memory_percent': memory.percent,
        'memory_available_gb': memory.available / (1024**3),
        'disk_percent': disk.percent,
        'disk_free_gb': disk.free / (1024**3),
    }

def get_apache_workers():
    """Count Apache worker processes"""
    count = 0
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] == 'apache2':
                count += 1
        except:
            pass
    return count

def send_metrics_to_cloudwatch(instance_id):
    """Send all metrics to CloudWatch"""
    timestamp = datetime.utcnow()

    metrics = []

    # Health checks
    apache_running = check_apache()
    health_ok = check_health_endpoint()
    db_ok = check_database_connection()
    redis_ok = check_redis_connection()

    metrics.append({
        'MetricName': 'ApacheRunning',
        'Value': 1 if apache_running else 0,
        'Timestamp': timestamp,
        'Dimensions': [{'Name': 'Instance', 'Value': instance_id}]
    })

    metrics.append({
        'MetricName': 'HealthEndpointOK',
        'Value': 1 if health_ok else 0,
        'Timestamp': timestamp,
        'Dimensions': [{'Name': 'Instance', 'Value': instance_id}]
    })

    metrics.append({
        'MetricName': 'DatabaseOK',
        'Value': 1 if db_ok else 0,
        'Timestamp': timestamp,
        'Dimensions': [{'Name': 'Instance', 'Value': instance_id}]
    })

    metrics.append({
        'MetricName': 'RedisOK',
        'Value': 1 if redis_ok else 0,
        'Timestamp': timestamp,
        'Dimensions': [{'Name': 'Instance', 'Value': instance_id}]
    })

    # Daemon count
    daemon_count = count_running_daemons()
    metrics.append({
        'MetricName': 'DaemonCount',
        'Value': daemon_count,
        'Timestamp': timestamp,
        'Dimensions': [{'Name': 'Instance', 'Value': instance_id}]
    })

    # System metrics
    sys_metrics = get_system_metrics()

    metrics.append({
        'MetricName': 'CPUUtilization',
        'Value': sys_metrics['cpu_percent'],
        'Unit': 'Percent',
        'Timestamp': timestamp,
        'Dimensions': [{'Name': 'Instance', 'Value': instance_id}]
    })

    metrics.append({
        'MetricName': 'MemoryUtilization',
        'Value': sys_metrics['memory_percent'],
        'Unit': 'Percent',
        'Timestamp': timestamp,
        'Dimensions': [{'Name': 'Instance', 'Value': instance_id}]
    })

    metrics.append({
        'MetricName': 'MemoryAvailable',
        'Value': sys_metrics['memory_available_gb'],
        'Unit': 'Gigabytes',
        'Timestamp': timestamp,
        'Dimensions': [{'Name': 'Instance', 'Value': instance_id}]
    })

    metrics.append({
        'MetricName': 'DiskUtilization',
        'Value': sys_metrics['disk_percent'],
        'Unit': 'Percent',
        'Timestamp': timestamp,
        'Dimensions': [{'Name': 'Instance', 'Value': instance_id}]
    })

    # Apache workers
    apache_workers = get_apache_workers()
    metrics.append({
        'MetricName': 'ApacheWorkers',
        'Value': apache_workers,
        'Timestamp': timestamp,
        'Dimensions': [{'Name': 'Instance', 'Value': instance_id}]
    })

    # Overall health score (0-100)
    health_score = 0
    if apache_running: health_score += 25
    if health_ok: health_score += 25
    if db_ok: health_score += 20
    if redis_ok: health_score += 10
    if daemon_count >= 6: health_score += 20

    metrics.append({
        'MetricName': 'HealthScore',
        'Value': health_score,
        'Unit': 'Percent',
        'Timestamp': timestamp,
        'Dimensions': [{'Name': 'Instance', 'Value': instance_id}]
    })

    # Send to CloudWatch in batches
    try:
        CLOUDWATCH.put_metric_data(
            Namespace=NAMESPACE,
            MetricData=metrics
        )
        return True
    except Exception as e:
        print(f"Error sending metrics: {e}")
        return False

def print_status(instance_id):
    """Print current status"""
    print(f"\n{'='*60}")
    print(f"DNS Science Health Status - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Instance: {instance_id}")
    print(f"{'='*60}\n")

    # Service checks
    apache_ok = check_apache()
    health_ok = check_health_endpoint()
    db_ok = check_database_connection()
    redis_ok = check_redis_connection()
    daemon_count = count_running_daemons()

    print("Service Health:")
    print(f"  Apache:          {'✓' if apache_ok else '✗'}")
    print(f"  Health Endpoint: {'✓' if health_ok else '✗'}")
    print(f"  Database:        {'✓' if db_ok else '✗'}")
    print(f"  Redis:           {'✓' if redis_ok else '✗'}")
    print(f"  Daemons:         {daemon_count}/8")

    # System metrics
    sys_metrics = get_system_metrics()
    print(f"\nSystem Resources:")
    print(f"  CPU:             {sys_metrics['cpu_percent']:.1f}%")
    print(f"  Memory:          {sys_metrics['memory_percent']:.1f}% ({sys_metrics['memory_available_gb']:.1f} GB free)")
    print(f"  Disk:            {sys_metrics['disk_percent']:.1f}% ({sys_metrics['disk_free_gb']:.1f} GB free)")

    apache_workers = get_apache_workers()
    print(f"  Apache Workers:  {apache_workers}")

    # Overall status
    all_ok = apache_ok and health_ok and db_ok and redis_ok and daemon_count >= 6
    print(f"\nOverall Status:    {'HEALTHY ✓' if all_ok else 'DEGRADED ✗'}")
    print(f"{'='*60}\n")

def main():
    """Main monitoring loop"""
    instance_id = get_instance_id()

    if len(sys.argv) > 1 and sys.argv[1] == '--once':
        # Single run mode
        print_status(instance_id)
        send_metrics_to_cloudwatch(instance_id)
    else:
        # Continuous monitoring mode
        print(f"Starting health monitor for instance {instance_id}")
        print("Reporting metrics every 60 seconds (Ctrl+C to stop)")

        while True:
            try:
                print_status(instance_id)
                send_metrics_to_cloudwatch(instance_id)
                time.sleep(60)
            except KeyboardInterrupt:
                print("\nMonitoring stopped")
                break
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(60)

if __name__ == "__main__":
    main()
