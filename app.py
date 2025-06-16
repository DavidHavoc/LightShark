#!/usr/bin/env python3
"""
Network Traffic Analyzer - Main Flask Application
Captures network packets using TShark and provides web interface for analysis
"""

import os
import json
import threading
import time
from datetime import datetime
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from dotenv import load_dotenv

from packet_capture import PacketCapture
from data_processor import DataProcessor
from ip_enrichment import IPEnrichment

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global variables
packet_capture = None
data_processor = None
ip_enrichment = None
capture_thread = None
is_capturing = False

def initialize_components():
    """Initialize all application components"""
    global packet_capture, data_processor, ip_enrichment
    
    packet_capture = PacketCapture()
    data_processor = DataProcessor()
    ip_enrichment = IPEnrichment(data_processor)
    
    # Set cross-references
    ip_enrichment.set_data_processor(data_processor)

@app.route('/')
def index():
    """Main dashboard endpoint"""
    return jsonify({
        "status": "running",
        "service": "Network Traffic Analyzer",
        "version": "1.0.0",
        "capture_status": "active" if is_capturing else "stopped"
    })

@app.route('/api/status')
def get_status():
    """Get current system status"""
    return jsonify({
        "capturing": is_capturing,
        "packets_captured": data_processor.get_packet_count() if data_processor else 0,
        "uptime": time.time() - app.start_time if hasattr(app, 'start_time') else 0
    })

@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """Start packet capture"""
    global capture_thread, is_capturing
    
    if is_capturing:
        return jsonify({"error": "Capture already running"}), 400
    
    try:
        # Get capture parameters from request
        data = request.get_json() or {}
        interface = data.get('interface', os.getenv('CAPTURE_INTERFACE', 'eth0'))
        capture_filter = data.get('filter', os.getenv('CAPTURE_FILTER', ''))
        
        # Start capture in separate thread
        capture_thread = threading.Thread(
            target=run_capture,
            args=(interface, capture_filter),
            daemon=True
        )
        capture_thread.start()
        is_capturing = True
        
        return jsonify({
            "status": "started",
            "interface": interface,
            "filter": capture_filter
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    global is_capturing
    
    if not is_capturing:
        return jsonify({"error": "No capture running"}), 400
    
    try:
        packet_capture.stop_capture()
        is_capturing = False
        return jsonify({"status": "stopped"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/data/export/<format>')
def export_data(format):
    """Export captured data in specified format"""
    try:
        if format not in ['csv', 'json', 'pcap']:
            return jsonify({"error": "Invalid format"}), 400
        
        file_path = data_processor.export_data(format)
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/enrichment/trigger', methods=['POST'])
def trigger_enrichment():
    """Trigger IP enrichment for recent packets"""
    try:
        data = request.get_json() or {}
        ip_address = data.get('ip')
        
        if ip_address:
            result = ip_enrichment.enrich_ip(ip_address)
        else:
            limit = data.get('limit', 50)
            result = ip_enrichment.enrich_recent_ips(limit)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/enrichment/suspicious')
def get_suspicious_ips():
    """Get list of suspicious IPs"""
    try:
        threshold = request.args.get('threshold', 50, type=int)
        suspicious_ips = ip_enrichment.get_suspicious_ips(threshold)
        return jsonify({
            'suspicious_ips': suspicious_ips,
            'count': len(suspicious_ips),
            'threshold': threshold
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/enrichment/geo')
def get_geo_tagged_ips():
    """Get IPs with geolocation data for mapping"""
    try:
        geo_ips = ip_enrichment.get_geo_tagged_ips()
        return jsonify({
            'geo_tagged_ips': geo_ips,
            'count': len(geo_ips)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/enrichment/stats')
def get_enrichment_stats():
    """Get IP enrichment statistics"""
    try:
        stats = ip_enrichment.get_enrichment_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/enrichment/export')
def export_enrichment_data():
    """Export enrichment data"""
    try:
        data = ip_enrichment.export_enrichment_data()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/enrichment/clear', methods=['POST'])
def clear_enrichment_cache():
    """Clear enrichment cache"""
    try:
        result = ip_enrichment.clear_cache()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats/summary')
def get_stats_summary():
    """Get traffic statistics summary"""
    try:
        stats = data_processor.get_summary_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats/influxdb')
def get_influxdb_stats():
    """Get statistics from InfluxDB for Grafana"""
    try:
        time_range = request.args.get('time_range', '1h')
        stats = data_processor.get_influxdb_stats(time_range)
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/refresh/trigger', methods=['POST'])
def trigger_refresh():
    """Trigger data refresh for dashboards"""
    try:
        # Force flush InfluxDB buffer
        data_processor.influxdb.force_flush()
        
        return jsonify({
            "status": "refreshed",
            "timestamp": time.time()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_capture(interface, capture_filter):
    """Run packet capture in background thread"""
    try:
        packet_capture.start_capture(
            interface=interface,
            capture_filter=capture_filter,
            callback=data_processor.process_packet
        )
    except Exception as e:
        print(f"Capture error: {e}")
        global is_capturing
        is_capturing = False

if __name__ == '__main__':
    # Initialize components
    initialize_components()
    app.start_time = time.time()
    
    # Run Flask app
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    app.run(host='0.0.0.0', port=port, debug=debug)

