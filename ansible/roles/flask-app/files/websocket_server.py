"""
DNS Science - WebSocket Server
Real-time domain monitoring with live feeds for CT logs, DNS changes, SSL updates
"""

from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room
import redis
import json
import threading
import time
from datetime import datetime

# Initialize SocketIO
socketio = None  # Will be initialized in app.py

# Redis for pub/sub
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
pubsub = redis_client.pubsub()


class WebSocketManager:
    """Manage WebSocket connections and real-time events"""

    def __init__(self, socketio_instance):
        self.socketio = socketio_instance
        self.active_monitors = {}  # domain -> set of session_ids

    def start_background_tasks(self):
        """Start background tasks for real-time monitoring"""
        # CT Log monitor
        threading.Thread(target=self._monitor_ct_logs, daemon=True).start()

        # DNS change monitor
        threading.Thread(target=self._monitor_dns_changes, daemon=True).start()

        # SSL expiry monitor
        threading.Thread(target=self._monitor_ssl_expiry, daemon=True).start()

        # Redis pubsub listener
        threading.Thread(target=self._redis_listener, daemon=True).start()

    def _monitor_ct_logs(self):
        """Monitor Certificate Transparency logs for new certificates"""
        while True:
            try:
                # Subscribe to CT log channel
                pubsub.subscribe('ct_logs')

                for message in pubsub.listen():
                    if message['type'] == 'message':
                        data = json.loads(message['data'])
                        domain = data.get('domain')

                        if domain in self.active_monitors:
                            self.socketio.emit('ct_log_entry', {
                                'domain': domain,
                                'certificate': {
                                    'issuer': data.get('issuer'),
                                    'serial': data.get('serial'),
                                    'not_before': data.get('not_before'),
                                    'not_after': data.get('not_after')
                                },
                                'timestamp': datetime.utcnow().isoformat()
                            }, room=f'domain:{domain}')

            except Exception as e:
                print(f"CT log monitor error: {e}")
                time.sleep(5)

    def _monitor_dns_changes(self):
        """Monitor DNS record changes"""
        while True:
            try:
                pubsub.subscribe('dns_changes')

                for message in pubsub.listen():
                    if message['type'] == 'message':
                        data = json.loads(message['data'])
                        domain = data.get('domain')

                        if domain in self.active_monitors:
                            self.socketio.emit('dns_change', {
                                'domain': domain,
                                'record_type': data.get('record_type'),
                                'old_value': data.get('old_value'),
                                'new_value': data.get('new_value'),
                                'timestamp': datetime.utcnow().isoformat()
                            }, room=f'domain:{domain}')

            except Exception as e:
                print(f"DNS change monitor error: {e}")
                time.sleep(5)

    def _monitor_ssl_expiry(self):
        """Monitor SSL certificate expiration"""
        while True:
            try:
                pubsub.subscribe('ssl_expiry_alerts')

                for message in pubsub.listen():
                    if message['type'] == 'message':
                        data = json.loads(message['data'])
                        domain = data.get('domain')

                        if domain in self.active_monitors:
                            self.socketio.emit('ssl_expiry_alert', {
                                'domain': domain,
                                'days_until_expiry': data.get('days_until_expiry'),
                                'expiry_date': data.get('expiry_date'),
                                'severity': data.get('severity'),
                                'timestamp': datetime.utcnow().isoformat()
                            }, room=f'domain:{domain}')

            except Exception as e:
                print(f"SSL expiry monitor error: {e}")
                time.sleep(5)

    def _redis_listener(self):
        """Listen to Redis pub/sub for real-time events"""
        channels = ['platform_events', 'scan_results', 'threat_alerts']

        try:
            pubsub.subscribe(*channels)

            for message in pubsub.listen():
                if message['type'] == 'message':
                    try:
                        data = json.loads(message['data'])
                        channel = message['channel']

                        # Broadcast to appropriate room
                        if channel == 'platform_events':
                            self.socketio.emit('platform_event', data, broadcast=True)
                        elif channel == 'scan_results':
                            domain = data.get('domain')
                            if domain:
                                self.socketio.emit('scan_complete', data, room=f'domain:{domain}')
                        elif channel == 'threat_alerts':
                            self.socketio.emit('threat_alert', data, broadcast=True)

                    except Exception as e:
                        print(f"Redis message processing error: {e}")

        except Exception as e:
            print(f"Redis listener error: {e}")


# WebSocket event handlers
def register_websocket_handlers(socketio_instance):
    """Register WebSocket event handlers"""
    global socketio
    socketio = socketio_instance

    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        print(f"Client connected: {request.sid}")
        emit('connected', {
            'session_id': request.sid,
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'Connected to DNS Science real-time monitoring'
        })

    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        print(f"Client disconnected: {request.sid}")

    @socketio.on('subscribe_domain')
    def handle_subscribe_domain(data):
        """Subscribe to domain monitoring"""
        domain = data.get('domain')
        if not domain:
            emit('error', {'message': 'Domain required'})
            return

        # Join room for this domain
        room = f'domain:{domain}'
        join_room(room)

        emit('subscribed', {
            'domain': domain,
            'room': room,
            'timestamp': datetime.utcnow().isoformat()
        })

        print(f"Client {request.sid} subscribed to domain: {domain}")

    @socketio.on('unsubscribe_domain')
    def handle_unsubscribe_domain(data):
        """Unsubscribe from domain monitoring"""
        domain = data.get('domain')
        if not domain:
            emit('error', {'message': 'Domain required'})
            return

        room = f'domain:{domain}'
        leave_room(room)

        emit('unsubscribed', {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat()
        })

        print(f"Client {request.sid} unsubscribed from domain: {domain}")

    @socketio.on('subscribe_ct_logs')
    def handle_subscribe_ct_logs():
        """Subscribe to Certificate Transparency log stream"""
        join_room('ct_logs_stream')
        emit('subscribed_ct_logs', {
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'Subscribed to CT log stream'
        })

    @socketio.on('subscribe_dns_changes')
    def handle_subscribe_dns_changes():
        """Subscribe to global DNS change stream"""
        join_room('dns_changes_stream')
        emit('subscribed_dns_changes', {
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'Subscribed to DNS changes stream'
        })

    @socketio.on('subscribe_threat_feed')
    def handle_subscribe_threat_feed():
        """Subscribe to real-time threat intelligence feed"""
        join_room('threat_feed_stream')
        emit('subscribed_threat_feed', {
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'Subscribed to threat intelligence feed'
        })

    @socketio.on('ping')
    def handle_ping():
        """Handle ping for keepalive"""
        emit('pong', {'timestamp': datetime.utcnow().isoformat()})

    @socketio.on('request_stats')
    def handle_request_stats():
        """Request real-time platform statistics"""
        import database as db
        stats = db.get_live_stats()

        emit('stats_update', {
            'total_domains': stats.get('total_domains', 0),
            'total_scans_today': stats.get('scans_today', 0),
            'active_monitors': stats.get('active_monitors', 0),
            'ct_logs_today': stats.get('ct_logs_today', 0),
            'timestamp': datetime.utcnow().isoformat()
        })


# Utility functions for publishing events
def publish_ct_log_entry(domain, cert_data):
    """Publish CT log entry to Redis"""
    redis_client.publish('ct_logs', json.dumps({
        'domain': domain,
        'issuer': cert_data.get('issuer'),
        'serial': cert_data.get('serial'),
        'not_before': cert_data.get('not_before'),
        'not_after': cert_data.get('not_after')
    }))


def publish_dns_change(domain, record_type, old_value, new_value):
    """Publish DNS change to Redis"""
    redis_client.publish('dns_changes', json.dumps({
        'domain': domain,
        'record_type': record_type,
        'old_value': old_value,
        'new_value': new_value
    }))


def publish_ssl_expiry_alert(domain, days_until_expiry, expiry_date, severity='warning'):
    """Publish SSL expiry alert to Redis"""
    redis_client.publish('ssl_expiry_alerts', json.dumps({
        'domain': domain,
        'days_until_expiry': days_until_expiry,
        'expiry_date': expiry_date,
        'severity': severity
    }))


def publish_scan_result(domain, result_data):
    """Publish scan completion to Redis"""
    redis_client.publish('scan_results', json.dumps({
        'domain': domain,
        'result': result_data,
        'timestamp': datetime.utcnow().isoformat()
    }))


def publish_threat_alert(alert_data):
    """Publish threat alert to Redis"""
    redis_client.publish('threat_alerts', json.dumps(alert_data))
