#!/usr/bin/env python3
"""
Network Traffic Analyzer - Simple Test Script
Tests core components without pandas dependency
"""

import sys
import os
import time
from unittest.mock import Mock

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_basic_functionality():
    """Test basic functionality without pandas"""
    print("Testing basic functionality...")
    
    try:
        # Test IP enrichment (no pandas dependency)
        from ip_enrichment import IPEnrichment
        enrichment = IPEnrichment()
        
        # Test public IP detection
        assert enrichment._is_public_ip('8.8.8.8') == True
        assert enrichment._is_public_ip('192.168.1.1') == False
        print("✓ IP enrichment basic functions work")
        
        # Test packet capture imports
        from packet_capture import PacketCapture
        print("✓ PacketCapture can be imported")
        
        # Test Flask app creation
        from app import app
        assert app is not None
        print("✓ Flask app can be created")
        
        return True
        
    except Exception as e:
        print(f"✗ Basic functionality test failed: {e}")
        return False

def test_configuration_files():
    """Test that all configuration files exist"""
    print("\nTesting configuration files...")
    
    required_files = [
        'docker-compose.yml',
        'Dockerfile',
        'requirements.txt',
        '.env',
        'config/grafana/datasources/influxdb.yml',
        'dashboards/network-traffic-overview.json',
        'dashboards/network-geolocation.json'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print(f"✗ Missing files: {missing_files}")
        return False
    
    print("✓ All required configuration files present")
    return True

def test_docker_compose_structure():
    """Test Docker Compose file structure"""
    print("\nTesting Docker Compose configuration...")
    
    try:
        with open('docker-compose.yml', 'r') as f:
            content = f.read()
        
        required_services = ['influxdb', 'grafana', 'traffic-analyzer']
        missing_services = []
        
        for service in required_services:
            if service not in content:
                missing_services.append(service)
        
        if missing_services:
            print(f"✗ Missing services in docker-compose.yml: {missing_services}")
            return False
        
        print("✓ Docker Compose configuration is complete")
        return True
        
    except Exception as e:
        print(f"✗ Docker Compose test failed: {e}")
        return False

def test_grafana_dashboards():
    """Test Grafana dashboard configuration"""
    print("\nTesting Grafana dashboards...")
    
    try:
        import json
        
        # Test main dashboard
        with open('dashboards/network-traffic-overview.json', 'r') as f:
            dashboard = json.load(f)
        
        assert 'panels' in dashboard
        assert len(dashboard['panels']) > 0
        print("✓ Main dashboard JSON is valid")
        
        # Test geolocation dashboard
        with open('dashboards/network-geolocation.json', 'r') as f:
            geo_dashboard = json.load(f)
        
        assert 'panels' in geo_dashboard
        print("✓ Geolocation dashboard JSON is valid")
        
        return True
        
    except Exception as e:
        print(f"✗ Grafana dashboard test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("Network Traffic Analyzer - Simple Component Tests")
    print("=" * 55)
    
    tests = [
        test_configuration_files,
        test_docker_compose_structure,
        test_grafana_dashboards,
        test_basic_functionality
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\nTest Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed! The application structure is correct.")
        print("\nNext steps:")
        print("1. Install Docker and Docker Compose")
        print("2. Run: docker-compose up -d")
        print("3. Access Grafana at http://localhost:3000 (admin/admin123)")
        print("4. Access Flask API at http://localhost:5000")
        return 0
    else:
        print("✗ Some tests failed. Please check the errors above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())

