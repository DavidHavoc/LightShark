#!/usr/bin/env python3
"""
InfluxDB Integration Module
Handles time-series data storage for packet metadata
"""

import os
import time
from datetime import datetime
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import threading

class InfluxDBHandler:
    def __init__(self):
        # InfluxDB configuration
        self.url = os.getenv('INFLUXDB_URL', 'http://localhost:8086')
        self.token = os.getenv('INFLUXDB_TOKEN', 'network-analyzer-token-123456789')
        self.org = os.getenv('INFLUXDB_ORG', 'network-analyzer')
        self.bucket = os.getenv('INFLUXDB_BUCKET', 'network-traffic')
        
        # Initialize client
        self.client = None
        self.write_api = None
        self.query_api = None
        
        # Buffer for batch writes
        self.write_buffer = []
        self.buffer_lock = threading.Lock()
        self.buffer_size = 100  # Write every 100 points
        self.last_write_time = time.time()
        self.write_interval = 10  # Write every 10 seconds
        
        # Initialize connection
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize InfluxDB connection"""
        try:
            self.client = InfluxDBClient(
                url=self.url,
                token=self.token,
                org=self.org
            )
            
            self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
            self.query_api = self.client.query_api()
            
            # Test connection
            self._test_connection()
            print("InfluxDB connection established successfully")
            
        except Exception as e:
            print(f"Failed to connect to InfluxDB: {e}")
            self.client = None
    
    def _test_connection(self):
        """Test InfluxDB connection"""
        if not self.client:
            raise Exception("InfluxDB client not initialized")
        
        # Try to query buckets to test connection
        buckets_api = self.client.buckets_api()
        buckets = buckets_api.find_buckets()
        print(f"Connected to InfluxDB. Available buckets: {len(buckets.buckets)}")
    
    def write_packet(self, packet_info):
        """Write packet data to InfluxDB"""
        if not self.client:
            return False
        
        try:
            # Create InfluxDB point
            point = self._create_packet_point(packet_info)
            
            # Add to buffer
            with self.buffer_lock:
                self.write_buffer.append(point)
                
                # Check if we should flush the buffer
                current_time = time.time()
                should_flush = (
                    len(self.write_buffer) >= self.buffer_size or
                    (current_time - self.last_write_time) >= self.write_interval
                )
                
                if should_flush:
                    self._flush_buffer()
            
            return True
            
        except Exception as e:
            print(f"Error writing packet to InfluxDB: {e}")
            return False
    
    def _create_packet_point(self, packet_info):
        """Create InfluxDB point from packet information"""
        # Convert protocol number to name if it's numeric
        protocol = packet_info.get('protocol', '')
        protocol_name = self._get_protocol_name(protocol)
        
        # Create the point
        point = Point("network_packet") \
            .tag("src_ip", packet_info.get('src_ip', '')) \
            .tag("dst_ip", packet_info.get('dst_ip', '')) \
            .tag("protocol", protocol_name) \
            .tag("src_port", str(packet_info.get('src_port', ''))) \
            .tag("dst_port", str(packet_info.get('dst_port', ''))) \
            .field("length", int(packet_info.get('length', 0))) \
            .field("protocols", packet_info.get('protocols', '')) \
            .field("dns_query", packet_info.get('dns_query', '')) \
            .field("http_host", packet_info.get('http_host', '')) \
            .field("http_method", packet_info.get('http_method', '')) \
            .field("http_response", packet_info.get('http_response', '')) \
            .time(int(packet_info.get('timestamp', time.time()) * 1000000000), WritePrecision.NS)
        
        return point
    
    def _get_protocol_name(self, protocol):
        """Convert protocol number to name"""
        protocol_map = {
            '1': 'ICMP',
            '6': 'TCP',
            '17': 'UDP',
            '41': 'IPv6',
            '47': 'GRE',
            '50': 'ESP',
            '51': 'AH',
            '58': 'ICMPv6'
        }
        
        return protocol_map.get(str(protocol), protocol)
    
    def _flush_buffer(self):
        """Flush write buffer to InfluxDB"""
        if not self.write_buffer:
            return
        
        try:
            # Write all points in buffer
            self.write_api.write(
                bucket=self.bucket,
                org=self.org,
                record=self.write_buffer
            )
            
            print(f"Wrote {len(self.write_buffer)} points to InfluxDB")
            
            # Clear buffer and update timestamp
            self.write_buffer.clear()
            self.last_write_time = time.time()
            
        except Exception as e:
            print(f"Error flushing buffer to InfluxDB: {e}")
    
    def query_packets(self, time_range="1h", limit=1000):
        """Query packets from InfluxDB"""
        if not self.client:
            return []
        
        try:
            query = f'''
            from(bucket: "{self.bucket}")
                |> range(start: -{time_range})
                |> filter(fn: (r) => r._measurement == "network_packet")
                |> limit(n: {limit})
            '''
            
            result = self.query_api.query(query, org=self.org)
            
            packets = []
            for table in result:
                for record in table.records:
                    packets.append({
                        'time': record.get_time(),
                        'src_ip': record.values.get('src_ip', ''),
                        'dst_ip': record.values.get('dst_ip', ''),
                        'protocol': record.values.get('protocol', ''),
                        'length': record.get_value(),
                        'field': record.get_field()
                    })
            
            return packets
            
        except Exception as e:
            print(f"Error querying packets from InfluxDB: {e}")
            return []
    
    def get_top_source_ips(self, time_range="1h", limit=10):
        """Get top source IPs from InfluxDB"""
        if not self.client:
            return {}
        
        try:
            query = f'''
            from(bucket: "{self.bucket}")
                |> range(start: -{time_range})
                |> filter(fn: (r) => r._measurement == "network_packet")
                |> filter(fn: (r) => r._field == "length")
                |> group(columns: ["src_ip"])
                |> count()
                |> sort(columns: ["_value"], desc: true)
                |> limit(n: {limit})
            '''
            
            result = self.query_api.query(query, org=self.org)
            
            top_ips = {}
            for table in result:
                for record in table.records:
                    src_ip = record.values.get('src_ip', '')
                    count = record.get_value()
                    if src_ip:
                        top_ips[src_ip] = count
            
            return top_ips
            
        except Exception as e:
            print(f"Error querying top source IPs: {e}")
            return {}
    
    def get_top_destination_ips(self, time_range="1h", limit=10):
        """Get top destination IPs from InfluxDB"""
        if not self.client:
            return {}
        
        try:
            query = f'''
            from(bucket: "{self.bucket}")
                |> range(start: -{time_range})
                |> filter(fn: (r) => r._measurement == "network_packet")
                |> filter(fn: (r) => r._field == "length")
                |> group(columns: ["dst_ip"])
                |> count()
                |> sort(columns: ["_value"], desc: true)
                |> limit(n: {limit})
            '''
            
            result = self.query_api.query(query, org=self.org)
            
            top_ips = {}
            for table in result:
                for record in table.records:
                    dst_ip = record.values.get('dst_ip', '')
                    count = record.get_value()
                    if dst_ip:
                        top_ips[dst_ip] = count
            
            return top_ips
            
        except Exception as e:
            print(f"Error querying top destination IPs: {e}")
            return {}
    
    def get_protocol_distribution(self, time_range="1h"):
        """Get protocol distribution from InfluxDB"""
        if not self.client:
            return {}
        
        try:
            query = f'''
            from(bucket: "{self.bucket}")
                |> range(start: -{time_range})
                |> filter(fn: (r) => r._measurement == "network_packet")
                |> filter(fn: (r) => r._field == "length")
                |> group(columns: ["protocol"])
                |> count()
                |> sort(columns: ["_value"], desc: true)
            '''
            
            result = self.query_api.query(query, org=self.org)
            
            protocols = {}
            for table in result:
                for record in table.records:
                    protocol = record.values.get('protocol', '')
                    count = record.get_value()
                    if protocol:
                        protocols[protocol] = count
            
            return protocols
            
        except Exception as e:
            print(f"Error querying protocol distribution: {e}")
            return {}
    
    def get_traffic_over_time(self, time_range="1h", window="1m"):
        """Get traffic over time from InfluxDB"""
        if not self.client:
            return []
        
        try:
            query = f'''
            from(bucket: "{self.bucket}")
                |> range(start: -{time_range})
                |> filter(fn: (r) => r._measurement == "network_packet")
                |> filter(fn: (r) => r._field == "length")
                |> aggregateWindow(every: {window}, fn: count, createEmpty: false)
                |> yield(name: "count")
            '''
            
            result = self.query_api.query(query, org=self.org)
            
            traffic_data = []
            for table in result:
                for record in table.records:
                    traffic_data.append({
                        'time': record.get_time(),
                        'count': record.get_value()
                    })
            
            return traffic_data
            
        except Exception as e:
            print(f"Error querying traffic over time: {e}")
            return []
    
    def force_flush(self):
        """Force flush the write buffer"""
        with self.buffer_lock:
            if self.write_buffer:
                self._flush_buffer()
    
    def close(self):
        """Close InfluxDB connection"""
        if self.client:
            # Flush any remaining data
            self.force_flush()
            self.client.close()
            print("InfluxDB connection closed")
    
    def get_connection_status(self):
        """Get InfluxDB connection status"""
        return {
            'connected': self.client is not None,
            'url': self.url,
            'org': self.org,
            'bucket': self.bucket,
            'buffer_size': len(self.write_buffer)
        }

