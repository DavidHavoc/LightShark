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
            '-T', 'json',  # Output in JSON format
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
        if self.pcap_file:
            cmd.extend(['-w', self.pcap_file])
        
        # Continuous capture (no packet limit)
        duration = os.getenv('CAPTURE_DURATION', '0')
        if duration != '0':
            cmd.extend(['-a', f'duration:{duration}'])
        
        return cmd
    
    def _read_packets(self, callback):
        """Read packets from TShark output and process them"""
        if not self.process:
            return
        
        buffer = ""
        
        try:
            while self.is_running and self.process.poll() is None:
                # Read line from TShark output
                line = self.process.stdout.readline()
                
                if not line:
                    break
                
                buffer += line
                
                # Try to parse complete JSON objects
                while True:
                    try:
                        # Find complete JSON object
                        start = buffer.find('[')
                        if start == -1:
                            break
                        
                        # Find matching closing bracket
                        bracket_count = 0
                        end = start
                        for i, char in enumerate(buffer[start:], start):
                            if char == '[':
                                bracket_count += 1
                            elif char == ']':
                                bracket_count -= 1
                                if bracket_count == 0:
                                    end = i + 1
                                    break
                        
                        if bracket_count == 0:
                            # Parse JSON packet data
                            json_str = buffer[start:end]
                            packet_data = json.loads(json_str)
                            
                            # Process each packet in the array
                            for packet in packet_data:
                                if callback:
                                    self._process_packet_data(packet, callback)
                            
                            # Remove processed data from buffer
                            buffer = buffer[end:]
                        else:
                            break
                            
                    except json.JSONDecodeError:
                        # If JSON is incomplete, wait for more data
                        break
                    except Exception as e:
                        print(f"Error processing packet: {e}")
                        # Skip this packet and continue
                        buffer = buffer[start + 1:] if start >= 0 else ""
                        break
        
        except Exception as e:
            print(f"Error reading packets: {e}")
        finally:
            print("Packet reading thread stopped")
    
    def _process_packet_data(self, packet, callback):
        """Process individual packet data and call callback"""
        try:
            # Extract packet information
            layers = packet.get('_source', {}).get('layers', {})
            
            packet_info = {
                'timestamp': float(layers.get('frame.time_epoch', [time.time()])[0]),
                'src_ip': layers.get('ip.src', [''])[0],
                'dst_ip': layers.get('ip.dst', [''])[0],
                'protocol': layers.get('ip.proto', [''])[0],
                'protocols': layers.get('frame.protocols', [''])[0],
                'length': int(layers.get('frame.len', [0])[0]),
                'src_port': layers.get('tcp.srcport', layers.get('udp.srcport', ['']))[0],
                'dst_port': layers.get('tcp.dstport', layers.get('udp.dstport', ['']))[0],
                'dns_query': layers.get('dns.qry.name', [''])[0],
                'http_host': layers.get('http.host', [''])[0],
                'http_method': layers.get('http.request.method', [''])[0],
                'http_response': layers.get('http.response.code', [''])[0]
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

