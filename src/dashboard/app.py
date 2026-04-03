"""Flask dashboard application with real-time Socket.IO updates"""

import os
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from flask import Flask, render_template, jsonify, request, Response, make_response
from flask_socketio import SocketIO, emit
import logging

from ..utils.logger import get_logger
from ..utils.config import get_config
from ..capture.packet_capture import PacketCapture, CapturedPacket
from ..capture.traffic_processor import TrafficProcessor, PacketStats
from ..ml.classifier import TrafficClassifier, ClassificationResult
from ..ml.features import FeatureExtractor
from ..ai.explanation_engine import ExplanationEngine, TrafficExplanation
from ..alerts.alert_manager import AlertManager, Alert

logger = get_logger(__name__)


class AppState:
    """Global application state"""

    def __init__(self, socketio):
        self.socketio = socketio
        self.capture: Optional[PacketCapture] = None
        self.processor: Optional[TrafficProcessor] = None
        self.classifier: Optional[TrafficClassifier] = None
        self.explainer: Optional[ExplanationEngine] = None
        self.alert_manager: Optional[AlertManager] = None

        self.is_capturing = False
        self.current_stats: Dict[str, Any] = {}
        self.current_classification: Dict[str, Any] = {}
        self.current_explanation: Dict[str, Any] = {}

        self._lock = threading.Lock()
        self._stats_thread: Optional[threading.Thread] = None
        self._running = False

        self._initialize_components()

    def _initialize_components(self):
        """Initialize all components"""
        try:
            self.capture = PacketCapture()
            self.processor = TrafficProcessor(window_size=60)
            self.classifier = TrafficClassifier()
            self.explainer = ExplanationEngine()
            self.alert_manager = AlertManager()

            self.alert_manager.register_callback(self._on_alert)

            logger.info("All components initialized")
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")

    def _on_alert(self, alert: Alert):
        """Handle new alert"""
        try:
            self.socketio.emit('alert', alert.to_dict(), namespace='/')
            logger.info(f"Alert emitted: {alert.attack_type}")
        except Exception as e:
            logger.error(f"Error emitting alert: {e}")

    def _emit_update(self):
        """Emit traffic update to all connected clients"""
        try:
            with self._lock:
                stats = self.current_stats.copy() if self.current_stats else {}
                classification = self.current_classification.copy() if self.current_classification else {}
                explanation = self.current_explanation.copy() if self.current_explanation else {}

            self.socketio.emit('traffic_update', {
                'stats': stats,
                'classification': classification,
                'explanation': explanation,
                'timestamp': datetime.now().isoformat()
            }, namespace='/')
        except Exception as e:
            logger.error(f"Error emitting update: {e}")

    def _stats_loop(self):
        """Background thread to emit stats periodically"""
        while self._running:
            if self.is_capturing and self.processor:
                self._emit_update()
            time.sleep(0.5)  # Emit every 500ms

    def _process_packet(self, packet: CapturedPacket):
        """Process captured packet through the pipeline"""
        try:
            self.processor.add_packet(packet)

            features = self.processor.get_current_features()

            with self._lock:
                self.current_stats = self.processor.get_stats().to_dict()

            is_threat, classification = self.classifier.is_threat(features)

            with self._lock:
                self.current_classification = classification.to_dict()

            # Assign classification to packet for display
            packet_dict = packet.to_dict()
            packet_dict['threat_label'] = classification.label
            packet_dict['confidence'] = classification.confidence
            packet_dict['threat_level'] = 'high' if classification.severity >= 3 else 'medium' if classification.severity >= 2 else 'low' if classification.severity >= 1 else 'none'

            # Generate explanation for ALL traffic (not just threats)
            if features.get('total_packets', 0) > 10:
                explanation = self.explainer.generate(features, classification.to_dict())

                with self._lock:
                    self.current_explanation = explanation.to_dict()

                # Only create alerts for high-confidence threats
                if is_threat and classification.confidence > 0.85:
                    # Create alerts for all detected attacks
                    detected_attacks = classification.all_detected_attacks or [classification.category]
                    if detected_attacks:
                        self.alert_manager.create_alerts_for_attacks(
                            detected_attacks=detected_attacks,
                            stats=features,
                            classification=classification.to_dict()
                        )

            # Emit update for each packet (will be throttled by stats_loop)
            self._emit_update()

        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            import traceback
            traceback.print_exc()

    def start_capture(self, interface: str = "auto", bpf_filter: str = ""):
        """Start packet capture"""
        with self._lock:
            if self.is_capturing:
                return False

            try:
                logger.info(f"Starting capture on {interface}")

                # Start background stats thread
                self._running = True
                self._stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
                self._stats_thread.start()

                self.capture.start_capture(
                    interface=interface,
                    bpf_filter=bpf_filter,
                    callback=self._process_packet,
                    simulate=True
                )
                self.is_capturing = True
                logger.info(f"Capture started successfully on interface: {interface}")
                return True
            except Exception as e:
                logger.error(f"Failed to start capture: {e}")
                import traceback
                traceback.print_exc()
                return False

    def stop_capture(self):
        """Stop packet capture"""
        with self._lock:
            if not self.is_capturing:
                return False

            self._running = False
            if self._stats_thread:
                self._stats_thread.join(timeout=1)

            self.capture.stop_capture()
            self.is_capturing = False
            logger.info("Capture stopped")
            return True

    def get_status(self) -> Dict[str, Any]:
        """Get current status"""
        with self._lock:
            return {
                'is_capturing': self.is_capturing,
                'stats': self.current_stats,
                'classification': self.current_classification,
                'explanation': self.current_explanation,
                'alert_stats': self.alert_manager.get_alert_stats() if self.alert_manager else {},
                'timestamp': datetime.now().isoformat()
            }


_app_state: Optional[AppState] = None


def create_app(config_path: str = "config.yaml") -> Flask:
    """Create and configure Flask application"""
    global _app_state

    template_dir = Path(__file__).parent / 'templates'
    app = Flask(__name__, template_folder=str(template_dir))
    app.config['SECRET_KEY'] = 'netwatcher-secret-key'
    app.config['JSON_SORT_KEYS'] = False

    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=False, engineio_logger=False)

    @app.route('/')
    def index():
        """Dashboard home page"""
        response = make_response(render_template('index.html'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    @app.route('/api/status')
    def get_status():
        """Get system status"""
        return jsonify(_app_state.get_status())

    @app.route('/api/capture/start', methods=['POST'])
    def start_capture():
        """Start packet capture"""
        data = request.get_json() or {}
        interface = data.get('interface', 'auto')
        bpf_filter = data.get('filter', '')

        success = _app_state.start_capture(interface, bpf_filter)

        return jsonify({
            'success': success,
            'message': 'Capture started' if success else 'Failed to start capture'
        })

    @app.route('/api/capture/stop', methods=['POST'])
    def stop_capture():
        """Stop packet capture"""
        success = _app_state.stop_capture()

        return jsonify({
            'success': success,
            'message': 'Capture stopped' if success else 'Capture was not running'
        })

    @app.route('/api/capture/status')
    def capture_status():
        """Get capture status"""
        return jsonify({
            'is_capturing': _app_state.is_capturing
        })

    @app.route('/api/traffic/stats')
    def traffic_stats():
        """Get traffic statistics"""
        with _app_state._lock:
            return jsonify(_app_state.current_stats)

    @app.route('/api/traffic/packets')
    def recent_packets():
        """Get recent packets with classification"""
        count = request.args.get('count', 100, type=int)
        packets = _app_state.processor.get_recent_packets(count)

        # Add current classification to each packet
        with _app_state._lock:
            current_class = _app_state.current_classification

        for pkt in packets:
            pkt['threat_label'] = current_class.get('label', 'Normal') if current_class else 'Normal'
            pkt['confidence'] = current_class.get('confidence', 0) if current_class else 0
            pkt['threat_level'] = current_class.get('threat_level', 'none') if current_class else 'none'

        return jsonify(packets)

    @app.route('/api/classification')
    def get_classification():
        """Get current classification"""
        with _app_state._lock:
            return jsonify(_app_state.current_classification)

    @app.route('/api/explanation')
    def get_explanation():
        """Get current explanation"""
        with _app_state._lock:
            return jsonify(_app_state.current_explanation)

    @app.route('/api/alerts')
    def get_alerts():
        """Get recent alerts"""
        limit = request.args.get('limit', 50, type=int)
        alerts = _app_state.alert_manager.get_alerts(limit)
        return jsonify([a.to_dict() for a in alerts])

    @app.route('/api/alerts/stats')
    def alert_stats():
        """Get alert statistics"""
        stats = _app_state.alert_manager.get_alert_stats()
        return jsonify(stats)

    @app.route('/api/alerts/clear', methods=['POST'])
    def clear_alerts():
        """Clear alert history"""
        _app_state.alert_manager.clear_alerts()
        return jsonify({'success': True})

    @app.route('/api/session/reset', methods=['POST'])
    def reset_session():
        """Reset all session data"""
        with _app_state._lock:
            _app_state.current_stats = None
            _app_state.current_classification = None
            _app_state.current_explanation = None
            if _app_state.processor:
                _app_state.processor.reset()
        _app_state.alert_manager.clear_alerts()
        return jsonify({'success': True, 'message': 'Session reset'})

    @app.route('/api/packets/import', methods=['POST'])
    def import_packets():
        """Import packets from JSON/CSV/PCAP file for analysis"""
        try:
            if 'file' not in request.files:
                return jsonify({'success': False, 'error': 'No file provided'}), 400

            file = request.files['file']
            if file.filename == '':
                return jsonify({'success': False, 'error': 'No file selected'}), 400

            filename = file.filename.lower()
            packets = []

            if filename.endswith('.json'):
                # Import JSON format
                data = json.load(file)
                if isinstance(data, list):
                    packets = data
                elif isinstance(data, dict) and 'packets' in data:
                    packets = data['packets']
            elif filename.endswith('.csv'):
                # Import CSV format
                content = file.read().decode('utf-8')
                lines = content.strip().split('\n')
                if len(lines) < 2:
                    return jsonify({'success': False, 'error': 'CSV file empty or invalid'}), 400

                # Parse CSV header
                header = lines[0].lower().split(',')
                for line in lines[1:]:
                    values = line.split(',')
                    if len(values) >= 5:
                        packet = {
                            'timestamp': values[0] if len(values) > 0 else datetime.now().isoformat(),
                            'src_ip': values[1] if len(values) > 1 else '0.0.0.0',
                            'dst_ip': values[2] if len(values) > 2 else '0.0.0.0',
                            'src_port': int(values[3]) if len(values) > 3 and values[3].isdigit() else 0,
                            'dst_port': int(values[4]) if len(values) > 4 and values[4].isdigit() else 0,
                            'protocol': values[5].upper() if len(values) > 5 else 'TCP',
                            'length': int(values[6]) if len(values) > 6 and values[6].isdigit() else 64
                        }
                        packets.append(packet)
            elif filename.endswith('.pcap') or filename.endswith('.pcapng'):
                # Import PCAP format using scapy
                try:
                    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
                    import io

                    # Read file data
                    file_data = file.read()

                    # Write to temp file for scapy to read
                    import tempfile
                    import os

                    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
                        tmp.write(file_data)
                        tmp_path = tmp.name

                    try:
                        # Parse PCAP with scapy
                        scapy_packets = rdpcap(tmp_path)
                        base_time = scapy_packets[0].time if scapy_packets else time.time()

                        for pkt in scapy_packets[:1000]:  # Limit to 1000 packets
                            if IP in pkt:
                                packet = {
                                    'timestamp': pkt.time - base_time,
                                    'src_ip': pkt[IP].src,
                                    'dst_ip': pkt[IP].dst,
                                    'length': len(pkt),
                                    'ttl': pkt[IP].ttl,
                                    'info': ''
                                }

                                # Extract payload from packet layers
                                payload_bytes = bytes(pkt.payload.payload) if hasattr(pkt, 'payload') and pkt.payload else b''
                                if payload_bytes:
                                    try:
                                        packet['payload'] = payload_bytes.decode('utf-8', errors='ignore')
                                        packet['payload_size'] = len(payload_bytes)
                                    except:
                                        packet['payload'] = ''
                                        packet['payload_size'] = 0
                                else:
                                    packet['payload'] = ''
                                    packet['payload_size'] = 0

                                if TCP in pkt:
                                    packet['protocol'] = 'TCP'
                                    packet['src_port'] = pkt[TCP].sport
                                    packet['dst_port'] = pkt[TCP].dport
                                    packet['tcp_flags'] = 'PSH,ACK'
                                elif UDP in pkt:
                                    packet['protocol'] = 'UDP'
                                    packet['src_port'] = pkt[UDP].sport
                                    packet['dst_port'] = pkt[UDP].dport
                                elif ICMP in pkt:
                                    packet['protocol'] = 'ICMP'
                                    packet['src_port'] = 0
                                    packet['dst_port'] = 0
                                else:
                                    packet['protocol'] = 'IP'
                                    packet['src_port'] = 0
                                    packet['dst_port'] = 0

                                packets.append(packet)
                    finally:
                        os.unlink(tmp_path)

                    if not packets:
                        return jsonify({'success': False, 'error': 'No valid packets found in PCAP file'}), 400

                except ImportError:
                    return jsonify({'success': False, 'error': 'PCAP import requires scapy. Install with: pip install scapy'}), 400
                except Exception as e:
                    logger.error(f"PCAP parse error: {e}")
                    return jsonify({'success': False, 'error': f'Failed to parse PCAP: {str(e)}'}), 400
            else:
                return jsonify({'success': False, 'error': 'Unsupported format. Use JSON, CSV, or PCAP'}), 400

            # Process imported packets through ML classification
            imported_count = 0
            for pkt_data in packets:
                try:
                    ts = pkt_data.get('timestamp', datetime.now().timestamp())
                    if isinstance(ts, str):
                        try:
                            ts = float(ts)
                        except (ValueError, TypeError):
                            ts = datetime.now().timestamp()
                    packet = CapturedPacket(
                        timestamp=float(ts),
                        src_ip=pkt_data.get('src_ip', '0.0.0.0'),
                        dst_ip=pkt_data.get('dst_ip', '0.0.0.0'),
                        src_port=int(pkt_data.get('src_port', 0)),
                        dst_port=int(pkt_data.get('dst_port', 0)),
                        protocol=pkt_data.get('protocol', 'TCP'),
                        length=int(pkt_data.get('length', 64)),
                        ttl=int(pkt_data.get('ttl', 64)),
                        tcp_flags=pkt_data.get('tcp_flags', pkt_data.get('flags', '')),
                        payload_size=int(pkt_data.get('payload_size', 0)),
                        info=pkt_data.get('info', ''),
                        payload=pkt_data.get('payload', '')
                    )
                    _app_state.processor.add_packet(packet)
                    imported_count += 1

                    # Run ML classification for every 10 packets imported
                    if imported_count % 10 == 0:
                        features = _app_state.processor.get_current_features()
                        is_threat, classification = _app_state.classifier.is_threat(features)
                        with _app_state._lock:
                            _app_state.current_classification = classification.to_dict()
                            _app_state.current_stats = _app_state.processor.get_stats().to_dict()
                        if features.get('total_packets', 0) > 10:
                            explanation = _app_state.explainer.generate(features, classification.to_dict())
                            with _app_state._lock:
                                _app_state.current_explanation = explanation.to_dict()
                except Exception as e:
                    logger.warning(f"Failed to import packet: {e}")

            # Final classification after all packets imported
            features = _app_state.processor.get_current_features()
            is_threat, classification = _app_state.classifier.is_threat(features)
            with _app_state._lock:
                _app_state.current_classification = classification.to_dict()
                _app_state.current_stats = _app_state.processor.get_stats().to_dict()
            explanation = _app_state.explainer.generate(features, classification.to_dict())
            with _app_state._lock:
                _app_state.current_explanation = explanation.to_dict()

            # Create alerts for detected threats
            alerts_created = []
            if classification.is_threat:
                all_attacks = classification.all_detected_attacks or [classification.label]
                stats_dict = _app_state.processor.get_stats().to_dict()
                for attack in all_attacks:
                    alert = _app_state.alert_manager.create_alert(
                        attack_type=attack,
                        confidence=classification.confidence,
                        explanation=explanation.to_dict(),
                        severity=_app_state.alert_manager._get_attack_severity(attack, stats_dict)
                    )
                    if alert:
                        alerts_created.append(alert.to_dict())

            return jsonify({
                'success': True,
                'message': f'Imported {imported_count} packets',
                'count': imported_count,
                'classification': classification.to_dict(),
                'alerts_created': len(alerts_created)
            })
        except Exception as e:
            logger.error(f"Import error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/packets/export', methods=['GET'])
    def export_packets():
        """Export packets to JSON or CSV format"""
        format_type = request.args.get('format', 'json').lower()
        count = request.args.get('count', 1000, type=int)

        packets = _app_state.processor.get_recent_packets(count)

        if format_type == 'csv':
            # Export as CSV
            csv_lines = ['timestamp,src_ip,dst_ip,src_port,dst_port,protocol,length,ttl,flags']
            for pkt in packets:
                csv_lines.append(f"{pkt.get('timestamp','')},{pkt.get('src_ip','')},{pkt.get('dst_ip','')},{pkt.get('src_port',0)},{pkt.get('dst_port',0)},{pkt.get('protocol','')},{pkt.get('length',0)},{pkt.get('ttl',64)},{pkt.get('flags','')}")
            return Response('\n'.join(csv_lines), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=packets.csv'})
        else:
            # Export as JSON
            return jsonify({
                'timestamp': datetime.now().isoformat(),
                'count': len(packets),
                'packets': packets
            })

    @app.route('/api/interfaces')
    def get_interfaces():
        """Get available network interfaces"""
        interfaces = _app_state.capture.get_available_interfaces()
        return jsonify(interfaces)

    @app.route('/api/config')
    def get_config_api():
        """Get current configuration"""
        config = get_config()
        return jsonify({
            'capture': {
                'interface': config.capture.interface,
                'filter': config.capture.filter
            },
            'dashboard': {
                'refresh_interval': config.dashboard.refresh_interval
            }
        })

    @app.route('/api/model/info')
    def get_model_info():
        """Get ML model information"""
        classifier = _app_state.classifier
        if classifier and classifier.model_data:
            return jsonify({
                'loaded': True,
                'accuracy': classifier.model_data.get('accuracy', 0),
                'training_date': classifier.model_data.get('training_date', 'Unknown'),
                'n_samples': classifier.model_data.get('n_samples', 0),
                'classes': list(classifier.model_data['label_encoder'].classes_) if classifier.model_data.get('label_encoder') else [],
                'attack_labels': classifier.model_data.get('attack_labels', []),
                'model_path': str(classifier.model_path)
            })
        return jsonify({
            'loaded': False,
            'message': 'No trained model loaded'
        })

    # Socket.IO events
    @socketio.on('connect')
    def handle_connect():
        """Handle WebSocket connection"""
        logger.info('Client connected')
        # Send current status immediately on connect
        emit('status', _app_state.get_status())

    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle WebSocket disconnection"""
        logger.info('Client disconnected')

    @socketio.on('request_update')
    def handle_update_request():
        """Handle update request"""
        emit('status', _app_state.get_status())

    # Initialize app state after socketio is configured
    _app_state = AppState(socketio)

    return app, socketio


def get_app_state() -> Optional[AppState]:
    """Get application state"""
    return _app_state
