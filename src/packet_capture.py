#!/usr/bin/env python3
"""
Packet Capture Module
Handles TShark subprocess for live packet capture and PCAP export
"""

import os
import subprocess
import threading
import time
import json
from datetime import datetime
import signal

class PacketCapture:
    def __init__(self):
        self.process = None
        self.is_running = False
        self.capture_thread = None
        self.pcap_file = None
        
    def start_capture(self, interface='eth0', capture_filter='', callback=None):
        """Start packet capture using TShark"""
        if self.is_running:
            raise Exception("Capture already running")
        
        try:
            # Create timestamp for this capture session
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Set up PCAP file if export is enabled
            if os.getenv('EXPORT_PCAP', 'True').lower() == 'true':
                self.pcap_file = f"/app/data/capture_{timestamp}.pcap"
            
            # Build TShark command
            cmd = self._build_tshark_command(interface, capture_filter)
            
            print(f"Starting capture with command: {' '.join(cmd)}")
            
            # Start TShark process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            self.is_running = True
            
            # Start reading packets in separate thread
            self.capture_thread = threading.Thread(
                target=self._read_packets,
                args=(callback,),
                daemon=True
            )
            self.capture_thread.start()
            
            print(f"Packet capture started on interface {interface}")
            
        except Exception as e:
            print(f"Failed to start capture: {e}")
            self.stop_capture()
            raise
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_running = False
        
        if self.process:
            try:
                # Send SIGTERM to gracefully stop TShark
                self.process.terminate()
                
                # Wait for process to terminate
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate gracefully
                    self.process.kill()
                    self.process.wait()
                
                print("Packet capture stopped")
            except Exception as e:
                print(f"Error stopping capture: {e}")
            finally:
                self.process = None
    
    def _build_tshark_command(self, interface, capture_filter):
        """Build TShark command with appropriate options"""
        cmd = [
            'tshark',
            '-i', interface,
            '-T', 'ek',  # Output in Elasticsearch JSON format for -e field extraction
            '-e', 'frame.time_epoch',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'ip.proto',
            '-e', 'frame.protocols',
            '-e', 'frame.len',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'dns.qry.name',
            '-e', 'http.host',
            '-e', 'http.request.method',
            '-e', 'http.response.code'
        ]
        
        # Add capture filter if specified
        if capture_filter:
            cmd.extend(['-f', capture_filter])
        
        # Add PCAP output if enabled
        # Use -P to also print to stdout while writing to file
        if self.pcap_file:
            cmd.extend(['-w', self.pcap_file, '-P'])
        
        # Continuous capture (no packet limit)
        duration = os.getenv('CAPTURE_DURATION', '0')
        if duration != '0':
            cmd.extend(['-a', f'duration:{duration}'])
        
        return cmd
    
    def _read_packets(self, callback):
        """Read packets from TShark output and process them"""
        if not self.process:
            return
        
        try:
            while self.is_running and self.process.poll() is None:
                # Read line from TShark output
                line = self.process.stdout.readline()
                
                if not line:
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                # -T ek outputs two lines per packet:
                # 1. Index line: {"index":...}
                # 2. Data line: {"timestamp":..., "layers":...}
                # We only care about lines that have "layers"
                try:
                    if '"layers"' in line:
                        packet_data = json.loads(line)
                        if callback and 'layers' in packet_data:
                            self._process_packet_data(packet_data, callback)
                except json.JSONDecodeError as e:
                    print(f"JSON decode error: {e}")
                    continue
                except Exception as e:
                    print(f"Error processing packet: {e}")
                    continue
        
        except Exception as e:
            print(f"Error reading packets: {e}")
        finally:
            print("Packet reading thread stopped")
    
    def _process_packet_data(self, packet, callback):
        """Process individual packet data and call callback"""
        try:
            # In -T ek format, layers are directly in the packet, not under _source
            layers = packet.get('layers', {})
            
            # Field names in -T ek format use underscores instead of dots
            packet_info = {
                'timestamp': float(layers.get('frame_time_epoch', [time.time()])[0]),
                'src_ip': layers.get('ip_src', [''])[0],
                'dst_ip': layers.get('ip_dst', [''])[0],
                'protocol': layers.get('ip_proto', [''])[0],
                'protocols': layers.get('frame_protocols', [''])[0],
                'length': int(layers.get('frame_len', [0])[0]),
                'src_port': layers.get('tcp_srcport', layers.get('udp_srcport', ['']))[0],
                'dst_port': layers.get('tcp_dstport', layers.get('udp_dstport', ['']))[0],
                'dns_query': layers.get('dns_qry_name', [''])[0],
                'http_host': layers.get('http_host', [''])[0],
                'http_method': layers.get('http_request_method', [''])[0],
                'http_response': layers.get('http_response_code', [''])[0]
            }
            
            # Call the callback function with processed packet data
            callback(packet_info)
            
        except Exception as e:
            print(f"Error processing packet data: {e}")
    
    def get_pcap_file(self):
        """Get the current PCAP file path"""
        return self.pcap_file
    
    def is_capture_running(self):
        """Check if capture is currently running"""
        return self.is_running and self.process and self.process.poll() is None

