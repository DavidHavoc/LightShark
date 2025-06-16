#!/usr/bin/env python3
"""
Network Traffic Analyzer - Test Script
Tests the core components without Docker
"""

import sys
import os
import time
import threading
from unittest.mock import Mock

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_imports():
    """Test that all modules can be imported"""
    print("Testing module imports...")
    
    try:
        from data_processor import DataProcessor
        print("✓ DataProcessor imported successfully")
    except Exception as e:
        print(f"✗ DataProcessor import failed: {e}")
        return False
    
    try:
        from packet_capture import PacketCapture
        print("✓ PacketCapture imported successfully")
    except Exception as e:
        print(f"✗ PacketCapture import failed: {e}")
        return False
    
    try:
        from ip_enrichment import IPEnrichment
        print("✓ IPEnrichment imported successfully")
    except Exception as e:
        print(f"✗ IPEnrichment import failed: {e}")
        return False
    
    try:
        from influxdb_handler import InfluxDBHandler
        print("✓ InfluxDBHandler imported successfully")
    except Exception as e:
        print(f"✗ InfluxDBHandler import failed: {e}")
        return False
    
    return True

def test_data_processor():
    """Test DataProcessor functionality"""
    print("\nTesting DataProcessor...")
    
    try:
        # Mock InfluxDBHandler to avoid connection issues
        from data_processor import DataProcessor
        processor = DataProcessor()
        
        # Mock the InfluxDB handler
        processor.influxdb = Mock()
        processor.influxdb.write_packet = Mock(return_value=True)
        processor.influxdb.get_connection_status = Mock(return_value={'connected': False})
        
        # Test packet processing
        test_packet = {
            'timestamp': time.time(),
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'protocol': '6',
            'length': 1500,
            'src_port': '12345',
            'dst_port': '80'
        }
        
        processor.process_packet(test_packet)
        
        # Check statistics
        stats = processor.get_summary_stats()
        assert stats['total_packets'] == 1
        assert stats['total_bytes'] == 1500
        
        print("✓ DataProcessor basic functionality works")
        return True
        
    except Exception as e:
        print(f"✗ DataProcessor test failed: {e}")
        return False

def test_ip_enrichment():
    """Test IPEnrichment functionality"""
    print("\nTesting IPEnrichment...")
    
    try:
        from ip_enrichment import IPEnrichment
        enrichment = IPEnrichment()
        
        # Test public IP detection
        assert enrichment._is_public_ip('8.8.8.8') == True
        assert enrichment._is_public_ip('192.168.1.1') == False
        assert enrichment._is_public_ip('127.0.0.1') == False
        
        # Test rate limiting
        assert enrichment._check_rate_limit('test_service') == True
        
        print("✓ IPEnrichment basic functionality works")
        return True
        
    except Exception as e:
        print(f"✗ IPEnrichment test failed: {e}")
        return False

def test_flask_app():
    """Test Flask application"""
    print("\nTesting Flask application...")
    
    try:
        from app import app
        
        # Test that app can be created
        assert app is not None
        
        # Test basic route
        with app.test_client() as client:
            response = client.get('/')
            assert response.status_code == 200
            
        print("✓ Flask application basic functionality works")
        return True
        
    except Exception as e:
        print(f"✗ Flask application test failed: {e}")
        return False

def test_configuration():
    """Test configuration files"""
    print("\nTesting configuration files...")
    
    # Check if required files exist
    required_files = [
        'docker-compose.yml',
        'Dockerfile',
        'requirements.txt',
        '.env',
        'config/grafana/datasources/influxdb.yml',
        'dashboards/network-traffic-overview.json'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print(f"✗ Missing configuration files: {missing_files}")
        return False
    
    print("✓ All configuration files present")
    return True

def main():
    """Run all tests"""
    print("Network Traffic Analyzer - Component Tests")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_configuration,
        test_data_processor,
        test_ip_enrichment,
        test_flask_app
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\nTest Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed! The application is ready for deployment.")
        return 0
    else:
        print("✗ Some tests failed. Please check the errors above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())

