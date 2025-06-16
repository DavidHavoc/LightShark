#!/usr/bin/env python3
"""
IP Enrichment Module
Handles IP geolocation and reputation checking with API integration
"""

import os
import requests
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict

class IPEnrichment:
    def __init__(self, data_processor=None):
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY', '')
        self.maxmind_license_key = os.getenv('MAXMIND_LICENSE_KEY', '')
        
        # Cache for enrichment results
        self.enrichment_cache = {}
        self.cache_lock = threading.Lock()
        
        # Reference to data processor for accessing packet data
        self.data_processor = data_processor
        
        # Rate limiting
        self.api_calls = defaultdict(list)
        self.rate_limits = {
            'virustotal': {'calls': 4, 'period': 60},  # 4 calls per minute
            'abuseipdb': {'calls': 1000, 'period': 86400},  # 1000 calls per day
            'ip_api': {'calls': 45, 'period': 60}  # 45 calls per minute
        }
        
    def set_data_processor(self, data_processor):
        """Set reference to data processor"""
        self.data_processor = data_processor
    
    def enrich_ip(self, ip_address):
        """Enrich a single IP address with geolocation and reputation data"""
        with self.cache_lock:
            # Check cache first
            if ip_address in self.enrichment_cache:
                cached_result = self.enrichment_cache[ip_address]
                # Check if cache is still valid (24 hours)
                cache_time = datetime.fromisoformat(cached_result['timestamp'])
                if datetime.now() - cache_time < timedelta(hours=24):
                    return cached_result
        
        result = {
            'ip': ip_address,
            'timestamp': datetime.now().isoformat(),
            'geolocation': self._get_geolocation(ip_address),
            'reputation': self._get_reputation(ip_address),
            'enriched': True
        }
        
        # Cache the result
        with self.cache_lock:
            self.enrichment_cache[ip_address] = result
        
        return result
    
    def enrich_recent_ips(self, limit=50):
        """Enrich recent IPs from packet data"""
        if not self.data_processor:
            return {'error': 'Data processor not available'}
        
        try:
            # Get recent packets
            recent_packets = self.data_processor.get_recent_packets(limit * 2)
            
            # Extract unique IPs
            unique_ips = set()
            for packet in recent_packets:
                src_ip = packet.get('src_ip', '')
                dst_ip = packet.get('dst_ip', '')
                if src_ip and self._is_public_ip(src_ip):
                    unique_ips.add(src_ip)
                if dst_ip and self._is_public_ip(dst_ip):
                    unique_ips.add(dst_ip)
            
            # Limit to requested number
            unique_ips = list(unique_ips)[:limit]
            
            # Enrich each IP
            enriched_results = []
            for ip in unique_ips:
                try:
                    result = self.enrich_ip(ip)
                    enriched_results.append(result)
                    # Add small delay to respect rate limits
                    time.sleep(0.1)
                except Exception as e:
                    print(f"Failed to enrich IP {ip}: {e}")
            
            return {
                'status': 'completed',
                'enriched_count': len(enriched_results),
                'total_unique_ips': len(unique_ips),
                'results': enriched_results
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _is_public_ip(self, ip):
        """Check if IP is a public IP address"""
        if not ip:
            return False
        
        # Skip private IP ranges
        private_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
            '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.',
            '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.',
            '127.', '169.254.', '224.', '225.', '226.', '227.', '228.',
            '229.', '230.', '231.', '232.', '233.', '234.', '235.', '236.',
            '237.', '238.', '239.', '240.', '241.', '242.', '243.', '244.',
            '245.', '246.', '247.', '248.', '249.', '250.', '251.', '252.',
            '253.', '254.', '255.'
        ]
        
        return not any(ip.startswith(prefix) for prefix in private_ranges)
    
    def _check_rate_limit(self, service):
        """Check if we can make an API call for the service"""
        current_time = time.time()
        rate_limit = self.rate_limits.get(service, {'calls': 1, 'period': 60})
        
        # Clean old calls
        cutoff_time = current_time - rate_limit['period']
        self.api_calls[service] = [
            call_time for call_time in self.api_calls[service]
            if call_time > cutoff_time
        ]
        
        # Check if we can make another call
        return len(self.api_calls[service]) < rate_limit['calls']
    
    def _record_api_call(self, service):
        """Record an API call for rate limiting"""
        self.api_calls[service].append(time.time())
    
    def _get_geolocation(self, ip_address):
        """Get geolocation data for IP address"""
        if not self._check_rate_limit('ip_api'):
            return {'error': 'Rate limit exceeded for geolocation service'}
        
        try:
            self._record_api_call('ip_api')
            
            # Use ip-api.com for free geolocation
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', ''),
                        'country_code': data.get('countryCode', ''),
                        'region': data.get('regionName', ''),
                        'city': data.get('city', ''),
                        'latitude': data.get('lat', 0),
                        'longitude': data.get('lon', 0),
                        'isp': data.get('isp', ''),
                        'org': data.get('org', ''),
                        'as': data.get('as', ''),
                        'timezone': data.get('timezone', ''),
                        'source': 'ip-api.com'
                    }
                else:
                    return {'error': data.get('message', 'Geolocation lookup failed')}
            
        except Exception as e:
            print(f"Geolocation lookup failed for {ip_address}: {e}")
        
        return {'error': 'Geolocation lookup failed'}
    
    def _get_reputation(self, ip_address):
        """Get reputation data for IP address"""
        reputation_data = {
            'malicious': False,
            'reputation_score': 0,
            'sources': [],
            'details': {}
        }
        
        # VirusTotal lookup (if API key is provided)
        if self.virustotal_api_key and self._check_rate_limit('virustotal'):
            vt_result = self._check_virustotal(ip_address)
            if vt_result and 'error' not in vt_result:
                reputation_data['sources'].append('virustotal')
                reputation_data['details']['virustotal'] = vt_result
                if vt_result.get('malicious', False):
                    reputation_data['malicious'] = True
                    reputation_data['reputation_score'] += 50
        
        # AbuseIPDB lookup (if API key is provided)
        if self.abuseipdb_api_key and self._check_rate_limit('abuseipdb'):
            abuse_result = self._check_abuseipdb(ip_address)
            if abuse_result and 'error' not in abuse_result:
                reputation_data['sources'].append('abuseipdb')
                reputation_data['details']['abuseipdb'] = abuse_result
                if abuse_result.get('malicious', False):
                    reputation_data['malicious'] = True
                    reputation_data['reputation_score'] += abuse_result.get('abuseipdb_confidence', 0)
        
        return reputation_data
    
    def _check_virustotal(self, ip_address):
        """Check IP reputation using VirusTotal API"""
        try:
            self._record_api_call('virustotal')
            
            headers = {'x-apikey': self.virustotal_api_key}
            response = requests.get(
                f"https://www.virustotal.com/vtapi/v2/ip-address/report",
                params={'apikey': self.virustotal_api_key, 'ip': ip_address},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                positives = data.get('positives', 0)
                total = data.get('total', 0)
                
                return {
                    'positives': positives,
                    'total': total,
                    'malicious': positives > 0,
                    'detection_ratio': f"{positives}/{total}" if total > 0 else "0/0",
                    'scans': data.get('scans', {})
                }
            elif response.status_code == 204:
                return {'error': 'Rate limit exceeded'}
            else:
                return {'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            print(f"VirusTotal lookup failed for {ip_address}: {e}")
            return {'error': str(e)}
    
    def _check_abuseipdb(self, ip_address):
        """Check IP reputation using AbuseIPDB API"""
        try:
            self._record_api_call('abuseipdb')
            
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip_address, 'maxAgeInDays': 90, 'verbose': ''},
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                confidence = data.get('abuseConfidencePercentage', 0)
                
                return {
                    'confidence_percentage': confidence,
                    'total_reports': data.get('totalReports', 0),
                    'malicious': confidence > 50,
                    'country_code': data.get('countryCode', ''),
                    'usage_type': data.get('usageType', ''),
                    'isp': data.get('isp', ''),
                    'domain': data.get('domain', ''),
                    'is_whitelisted': data.get('isWhitelisted', False)
                }
            elif response.status_code == 429:
                return {'error': 'Rate limit exceeded'}
            else:
                return {'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            print(f"AbuseIPDB lookup failed for {ip_address}: {e}")
            return {'error': str(e)}
    
    def get_suspicious_ips(self, threshold=50):
        """Get list of suspicious IPs based on reputation scores"""
        suspicious_ips = []
        
        with self.cache_lock:
            for ip, data in self.enrichment_cache.items():
                reputation = data.get('reputation', {})
                if reputation.get('malicious', False) or reputation.get('reputation_score', 0) > threshold:
                    suspicious_ips.append({
                        'ip': ip,
                        'reputation_score': reputation.get('reputation_score', 0),
                        'malicious': reputation.get('malicious', False),
                        'sources': reputation.get('sources', []),
                        'geolocation': data.get('geolocation', {})
                    })
        
        # Sort by reputation score
        suspicious_ips.sort(key=lambda x: x['reputation_score'], reverse=True)
        return suspicious_ips
    
    def get_geo_tagged_ips(self):
        """Get IPs with geolocation data for mapping"""
        geo_ips = []
        
        with self.cache_lock:
            for ip, data in self.enrichment_cache.items():
                geolocation = data.get('geolocation', {})
                if geolocation.get('latitude') and geolocation.get('longitude'):
                    geo_ips.append({
                        'ip': ip,
                        'latitude': geolocation.get('latitude'),
                        'longitude': geolocation.get('longitude'),
                        'country': geolocation.get('country', ''),
                        'city': geolocation.get('city', ''),
                        'isp': geolocation.get('isp', ''),
                        'reputation_score': data.get('reputation', {}).get('reputation_score', 0)
                    })
        
        return geo_ips
    
    def get_enrichment_stats(self):
        """Get statistics about enrichment operations"""
        with self.cache_lock:
            total_enriched = len(self.enrichment_cache)
            geo_enriched = sum(1 for data in self.enrichment_cache.values() 
                             if data.get('geolocation', {}).get('latitude'))
            reputation_enriched = sum(1 for data in self.enrichment_cache.values() 
                                    if data.get('reputation', {}).get('sources'))
            suspicious_count = len(self.get_suspicious_ips())
        
        return {
            'total_enriched_ips': total_enriched,
            'geo_enriched': geo_enriched,
            'reputation_enriched': reputation_enriched,
            'suspicious_ips': suspicious_count,
            'apis_configured': {
                'virustotal': bool(self.virustotal_api_key),
                'abuseipdb': bool(self.abuseipdb_api_key),
                'maxmind': bool(self.maxmind_license_key)
            },
            'rate_limit_status': {
                service: {
                    'calls_made': len(calls),
                    'limit': self.rate_limits[service]['calls'],
                    'period': self.rate_limits[service]['period']
                }
                for service, calls in self.api_calls.items()
            }
        }
    
    def clear_cache(self):
        """Clear enrichment cache"""
        with self.cache_lock:
            self.enrichment_cache.clear()
        return {'status': 'cache_cleared'}
    
    def export_enrichment_data(self):
        """Export enrichment data for analysis"""
        with self.cache_lock:
            return {
                'export_timestamp': datetime.now().isoformat(),
                'total_ips': len(self.enrichment_cache),
                'enrichment_data': dict(self.enrichment_cache)
            }

