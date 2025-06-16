#!/usr/bin/env python3
"""
Data Processor Module
Handles packet metadata extraction, storage, and export functionality
"""

import os
import json
import csv
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import threading
from influxdb_handler import InfluxDBHandler

class DataProcessor:
    def __init__(self):
        self.packets = []
        self.packet_count = 0
        self.lock = threading.Lock()
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': Counter(),
            'src_ips': Counter(),
            'dst_ips': Counter(),
            'ports': Counter(),
            'start_time': None,
            'last_packet_time': None
        }
        
        # Initialize InfluxDB handler
        self.influxdb = InfluxDBHandler()
    
    def process_packet(self, packet_info):
        """Process a single packet and update statistics"""
        with self.lock:
            try:
                # Add packet to collection
                self.packets.append(packet_info)
                self.packet_count += 1
                
                # Write to InfluxDB
                self.influxdb.write_packet(packet_info)
                
                # Update statistics
                self._update_stats(packet_info)
                
                # Limit memory usage by keeping only recent packets
                max_packets = int(os.getenv('MAX_PACKETS_MEMORY', '10000'))
                if len(self.packets) > max_packets:
                    self.packets = self.packets[-max_packets:]
                
                # Log packet processing (every 100 packets)
                if self.packet_count % 100 == 0:
                    print(f"Processed {self.packet_count} packets")
                
            except Exception as e:
                print(f"Error processing packet: {e}")
    
    def _update_stats(self, packet_info):
        """Update internal statistics with new packet"""
        timestamp = packet_info.get('timestamp', 0)
        
        # Update counters
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += packet_info.get('length', 0)
        
        # Update protocol statistics
        protocol = packet_info.get('protocol', 'unknown')
        if protocol:
            self.stats['protocols'][protocol] += 1
        
        # Update IP statistics
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        if src_ip:
            self.stats['src_ips'][src_ip] += 1
        if dst_ip:
            self.stats['dst_ips'][dst_ip] += 1
        
        # Update port statistics
        src_port = packet_info.get('src_port', '')
        dst_port = packet_info.get('dst_port', '')
        if src_port:
            self.stats['ports'][src_port] += 1
        if dst_port:
            self.stats['ports'][dst_port] += 1
        
        # Update time tracking
        if not self.stats['start_time']:
            self.stats['start_time'] = timestamp
        self.stats['last_packet_time'] = timestamp
    
    def get_packet_count(self):
        """Get total number of processed packets"""
        return self.packet_count
    
    def get_recent_packets(self, limit=100):
        """Get most recent packets"""
        with self.lock:
            return self.packets[-limit:] if self.packets else []
    
    def get_summary_stats(self):
        """Get summary statistics"""
        with self.lock:
            duration = 0
            if self.stats['start_time'] and self.stats['last_packet_time']:
                duration = self.stats['last_packet_time'] - self.stats['start_time']
            
            return {
                'total_packets': self.stats['total_packets'],
                'total_bytes': self.stats['total_bytes'],
                'duration_seconds': duration,
                'packets_per_second': self.stats['total_packets'] / max(duration, 1),
                'top_protocols': dict(self.stats['protocols'].most_common(10)),
                'top_src_ips': dict(self.stats['src_ips'].most_common(10)),
                'top_dst_ips': dict(self.stats['dst_ips'].most_common(10)),
                'top_ports': dict(self.stats['ports'].most_common(10)),
                'influxdb_status': self.influxdb.get_connection_status()
            }
    
    def get_influxdb_stats(self, time_range="1h"):
        """Get statistics from InfluxDB"""
        return {
            'top_source_ips': self.influxdb.get_top_source_ips(time_range),
            'top_destination_ips': self.influxdb.get_top_destination_ips(time_range),
            'protocol_distribution': self.influxdb.get_protocol_distribution(time_range),
            'traffic_over_time': self.influxdb.get_traffic_over_time(time_range)
        }
    
    def export_data(self, format_type):
        """Export packet data in specified format"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type == 'csv':
            return self._export_csv(timestamp)
        elif format_type == 'json':
            return self._export_json(timestamp)
        elif format_type == 'pcap':
            return self._get_pcap_file()
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _export_csv(self, timestamp):
        """Export packet data to CSV format"""
        filename = f"/app/data/packets_{timestamp}.csv"
        
        with self.lock:
            if not self.packets:
                raise ValueError("No packet data to export")
            
            # Convert to DataFrame for easier CSV export
            df = pd.DataFrame(self.packets)
            
            # Convert timestamp to readable format
            df['timestamp_readable'] = pd.to_datetime(df['timestamp'], unit='s')
            
            # Reorder columns for better readability
            columns = [
                'timestamp_readable', 'timestamp', 'src_ip', 'dst_ip', 
                'protocol', 'src_port', 'dst_port', 'length', 'protocols',
                'dns_query', 'http_host', 'http_method', 'http_response'
            ]
            
            # Only include columns that exist
            available_columns = [col for col in columns if col in df.columns]
            df = df[available_columns]
            
            # Export to CSV
            df.to_csv(filename, index=False)
            
        print(f"Exported {len(self.packets)} packets to {filename}")
        return filename
    
    def _export_json(self, timestamp):
        """Export packet data to JSON format"""
        filename = f"/app/data/packets_{timestamp}.json"
        
        with self.lock:
            if not self.packets:
                raise ValueError("No packet data to export")
            
            export_data = {
                'export_timestamp': timestamp,
                'total_packets': len(self.packets),
                'summary_stats': self.get_summary_stats(),
                'packets': self.packets
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
        
        print(f"Exported {len(self.packets)} packets to {filename}")
        return filename
    
    def _get_pcap_file(self):
        """Get the most recent PCAP file"""
        data_dir = "/app/data"
        pcap_files = [f for f in os.listdir(data_dir) if f.endswith('.pcap')]
        
        if not pcap_files:
            raise ValueError("No PCAP files available")
        
        # Return the most recent PCAP file
        pcap_files.sort(reverse=True)
        return os.path.join(data_dir, pcap_files[0])
    
    def get_packets_by_timerange(self, start_time, end_time):
        """Get packets within a specific time range"""
        with self.lock:
            filtered_packets = [
                packet for packet in self.packets
                if start_time <= packet.get('timestamp', 0) <= end_time
            ]
            return filtered_packets
    
    def get_packets_by_ip(self, ip_address):
        """Get packets involving a specific IP address"""
        with self.lock:
            filtered_packets = [
                packet for packet in self.packets
                if packet.get('src_ip') == ip_address or packet.get('dst_ip') == ip_address
            ]
            return filtered_packets
    
    def get_protocol_breakdown(self):
        """Get detailed protocol breakdown"""
        with self.lock:
            protocol_stats = {}
            
            for protocol, count in self.stats['protocols'].items():
                protocol_stats[protocol] = {
                    'count': count,
                    'percentage': (count / max(self.stats['total_packets'], 1)) * 100
                }
            
            return protocol_stats
    
    def clear_data(self):
        """Clear all stored packet data and statistics"""
        with self.lock:
            self.packets.clear()
            self.packet_count = 0
            self.stats = {
                'total_packets': 0,
                'total_bytes': 0,
                'protocols': Counter(),
                'src_ips': Counter(),
                'dst_ips': Counter(),
                'ports': Counter(),
                'start_time': None,
                'last_packet_time': None
            }
            print("Cleared all packet data and statistics")
    
    def close(self):
        """Close connections and cleanup"""
        if self.influxdb:
            self.influxdb.close()

