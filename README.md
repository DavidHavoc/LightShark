# Network Traffic Analyzer

A comprehensive Dockerized network traffic analyzer that captures live packets with TShark, parses metadata, stores it in InfluxDB, and visualizes insights in real-time using Grafana dashboards.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Dashboard Guide](#dashboard-guide)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Overview

This network traffic analyzer provides real-time monitoring and analysis of network traffic with the following key capabilities:

- **Live Packet Capture**: Uses TShark to capture network packets in real-time
- **Metadata Extraction**: Parses and extracts key packet metadata (IP addresses, protocols, ports, etc.)
- **Time-Series Storage**: Stores data in InfluxDB for efficient time-series analysis
- **Real-Time Visualization**: Grafana dashboards for comprehensive traffic analysis
- **IP Enrichment**: Optional geolocation and reputation checking for IP addresses
- **Data Export**: Export captured data in CSV, JSON, and PCAP formats
- **Containerized Deployment**: Fully containerized with Docker Compose



## Features

### Core Features
- **Real-time packet capture** using TShark subprocess
- **Metadata parsing** for IP addresses, protocols, ports, and application data
- **Time-series data storage** in InfluxDB with automatic batching
- **Interactive Grafana dashboards** with multiple visualization panels
- **RESTful API** for programmatic access to data and controls

### Advanced Features
- **IP Geolocation** using free and premium APIs (ip-api.com, MaxMind)
- **IP Reputation Checking** via VirusTotal and AbuseIPDB APIs
- **Suspicious IP Detection** with configurable thresholds
- **Data Export** in multiple formats (CSV, JSON, PCAP)
- **Rate Limiting** for API calls to respect service limits
- **Caching** for enrichment data to improve performance

### Dashboard Panels
- **Top Source IPs**: Most active source IP addresses
- **Top Destination IPs**: Most contacted destination IPs
- **Traffic Over Time**: Time-series visualization of packet counts
- **Protocol Distribution**: Pie chart of protocol usage
- **Suspicious IPs**: Table of IPs with reputation issues
- **Geolocation Map**: World map showing IP locations (with plugin)
- **Export Controls**: Direct download links for data export
- **System Status**: Real-time system monitoring

## Architecture

The system consists of four main components:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   TShark        │    │   Python App    │    │   InfluxDB      │
│   (Capture)     │───▶│   (Processing)  │───▶│   (Storage)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   Grafana       │
                       │   (Visualization)│
                       └─────────────────┘
```

### Component Details

1. **TShark Capture Layer**
   - Captures live network packets using TShark subprocess
   - Outputs packet data in JSON format for parsing
   - Supports capture filters and interface selection
   - Optional PCAP file export for full packet analysis

2. **Python Processing Layer**
   - Flask web application with RESTful API
   - Packet metadata extraction and parsing
   - InfluxDB integration with batched writes
   - IP enrichment with external APIs
   - Data export functionality

3. **InfluxDB Storage Layer**
   - Time-series database optimized for network data
   - Automatic data retention and compression
   - Efficient querying for dashboard visualization
   - Supports complex aggregations and time-based queries

4. **Grafana Visualization Layer**
   - Pre-configured dashboards for network analysis
   - Real-time data refresh and interactive panels
   - Export capabilities and alerting support
   - Extensible with additional plugins


## Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+ recommended)
- **Memory**: Minimum 4GB RAM (8GB+ recommended for high traffic)
- **Storage**: 10GB+ free space for data storage
- **Network**: Interface with packet capture capabilities

### Software Dependencies
- **Docker**: Version 20.10 or later
- **Docker Compose**: Version 1.29 or later
- **Network Privileges**: Root access or CAP_NET_RAW capability for packet capture

### Optional API Keys
For enhanced IP enrichment features, obtain API keys from:
- **VirusTotal**: [virustotal.com](https://www.virustotal.com/gui/join-us)
- **AbuseIPDB**: [abuseipdb.com](https://www.abuseipdb.com/api)
- **MaxMind**: [maxmind.com](https://www.maxmind.com/en/geolite2/signup)

## Installation

### Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd network-traffic-analyzer
   ```

2. **Configure environment variables**
   ```bash
   cp .env.template .env
   # Edit .env file with your API keys and settings
   nano .env
   ```

3. **Start the services**
   ```bash
   docker-compose up -d
   ```

4. **Access the dashboards**
   - Grafana: http://localhost:3000 (admin/admin123)
   - Flask API: http://localhost:5000
   - InfluxDB: http://localhost:8086

### Detailed Installation Steps

#### Step 1: Install Docker and Docker Compose

**https://docs.docker.com/engine/install/**

#### Step 2: Download and Configure

```bash
# Download the project
git clone <repository-url>
cd network-traffic-analyzer

# Make scripts executable
chmod +x test_simple.py

# Verify project structure
python3 test_simple.py
```

#### Step 3: Environment Configuration

```bash
# Copy environment template
cp .env.template .env

# Edit configuration file
nano .env
```

**Key configuration options:**
```bash
# Network interface for packet capture
CAPTURE_INTERFACE=eth0

# API keys for IP enrichment (optional)
VIRUSTOTAL_API_KEY=your_api_key_here
ABUSEIPDB_API_KEY=your_api_key_here

# Application settings
DEBUG=False
LOG_LEVEL=INFO
```


## Configuration

### Environment Variables

The application uses environment variables for configuration. Edit the `.env` file to customize settings:

#### Network Capture Settings
```bash
# Network interface to capture packets from
CAPTURE_INTERFACE=eth0

# Optional capture filter (BPF syntax)
CAPTURE_FILTER=

# Capture duration (0 for continuous)
CAPTURE_DURATION=0
```

#### Database Configuration
```bash
# InfluxDB connection settings (automatically configured by Docker Compose)
INFLUXDB_URL=http://localhost:8086
INFLUXDB_TOKEN=network-analyzer-token-123456789
INFLUXDB_ORG=network-analyzer
INFLUXDB_BUCKET=network-traffic
```

#### API Keys for IP Enrichment
```bash
# VirusTotal API key for malware detection
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# AbuseIPDB API key for IP reputation
ABUSEIPDB_API_KEY=your_abuseipdb_api_key

# MaxMind license key for geolocation
MAXMIND_LICENSE_KEY=your_maxmind_license_key
```

#### Application Settings
```bash
# Flask application port
FLASK_PORT=5000

# Debug mode (set to False in production)
DEBUG=False

# Logging level
LOG_LEVEL=INFO

# Data export settings
EXPORT_CSV=True
EXPORT_JSON=True
EXPORT_PCAP=True
MAX_EXPORT_SIZE=100MB
```

### Docker Compose Configuration

The `docker-compose.yml` file defines the service architecture. Key configurations:

#### Network Mode
The traffic analyzer container uses `host` network mode for packet capture:
```yaml
traffic-analyzer:
  network_mode: host
  privileged: true
  cap_add:
    - NET_ADMIN
    - NET_RAW
```

#### Volume Mounts
Data persistence is handled through Docker volumes:
```yaml
volumes:
  - ./data:/app/data          # Captured data and exports
  - ./logs:/app/logs          # Application logs
  - ./config:/app/config      # Configuration files
```

## Usage

### Starting the System

1. **Start all services**
   ```bash
   docker-compose up -d
   ```

2. **Check service status**
   ```bash
   docker-compose ps
   ```

3. **View logs**
   ```bash
   # All services
   docker-compose logs -f

   # Specific service
   docker-compose logs -f traffic-analyzer
   ```

### Accessing the Interfaces

#### Grafana Dashboard
- **URL**: http://localhost:3000
- **Username**: admin
- **Password**: admin123

**Available Dashboards:**
- **Network Traffic Overview**: Main dashboard with all key metrics
- **Network Geolocation**: Geographic visualization of IP addresses

#### Flask API
- **URL**: http://localhost:5000
- **Health Check**: http://localhost:5000/api/status

#### InfluxDB
- **URL**: http://localhost:8086
- **Organization**: network-analyzer
- **Bucket**: network-traffic

### Basic Operations

#### Starting Packet Capture
```bash
# Start capture via API
curl -X POST http://localhost:5000/api/capture/start \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth0", "filter": ""}'

# Check capture status
curl http://localhost:5000/api/status
```

#### Stopping Packet Capture
```bash
curl -X POST http://localhost:5000/api/capture/stop
```

#### Triggering IP Enrichment
```bash
# Enrich recent IPs
curl -X POST http://localhost:5000/api/enrichment/trigger \
  -H "Content-Type: application/json" \
  -d '{"limit": 50}'

# Enrich specific IP
curl -X POST http://localhost:5000/api/enrichment/trigger \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'
```

#### Exporting Data
```bash
# Download CSV export
curl -O http://localhost:5000/api/data/export/csv

# Download JSON export
curl -O http://localhost:5000/api/data/export/json

# Download PCAP file
curl -O http://localhost:5000/api/data/export/pcap
```

### Advanced Usage

#### Custom Capture Filters
Use Berkeley Packet Filter (BPF) syntax for targeted capture:
```bash
# Capture only HTTP traffic
curl -X POST http://localhost:5000/api/capture/start \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth0", "filter": "port 80 or port 443"}'

# Capture traffic to/from specific IP
curl -X POST http://localhost:5000/api/capture/start \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth0", "filter": "host 192.168.1.100"}'
```

#### Monitoring System Performance
```bash
# Check system statistics
curl http://localhost:5000/api/stats/summary

# Check InfluxDB statistics
curl http://localhost:5000/api/stats/influxdb

# Check enrichment statistics
curl http://localhost:5000/api/enrichment/stats
```


## API Documentation

The Flask application provides a comprehensive RESTful API for controlling the traffic analyzer and accessing data.

### Base URL
```
http://localhost:5000
```

### Authentication
Currently, no authentication is required. In production environments, consider implementing API authentication.

### Endpoints

#### System Status
```http
GET /api/status
```
Returns current system status including capture state and packet counts.

**Response:**
```json
{
  "capturing": true,
  "packets_captured": 15420,
  "uptime": 3600
}
```

#### Packet Capture Control

**Start Capture**
```http
POST /api/capture/start
Content-Type: application/json

{
  "interface": "eth0",
  "filter": "port 80 or port 443"
}
```

**Stop Capture**
```http
POST /api/capture/stop
```

#### Statistics and Data

**Summary Statistics**
```http
GET /api/stats/summary
```

**InfluxDB Statistics**
```http
GET /api/stats/influxdb?time_range=1h
```

#### IP Enrichment

**Trigger Enrichment**
```http
POST /api/enrichment/trigger
Content-Type: application/json

{
  "limit": 50
}
```

**Get Suspicious IPs**
```http
GET /api/enrichment/suspicious?threshold=50
```

**Get Geo-tagged IPs**
```http
GET /api/enrichment/geo
```

**Enrichment Statistics**
```http
GET /api/enrichment/stats
```

#### Data Export

**Export CSV**
```http
GET /api/data/export/csv
```

**Export JSON**
```http
GET /api/data/export/json
```

**Export PCAP**
```http
GET /api/data/export/pcap
```

#### Utility Functions

**Refresh Dashboard Data**
```http
POST /api/refresh/trigger
```

**Clear Enrichment Cache**
```http
POST /api/enrichment/clear
```

## Dashboard Guide

### Network Traffic Overview Dashboard

This is the main dashboard providing comprehensive network traffic analysis.

#### Panel Descriptions

**1. Protocols Used (Pie Chart)**
- Displays distribution of network protocols
- Data source: InfluxDB aggregation by protocol field
- Refresh: Every 5 seconds

**2. Top Source IPs (Table)**
- Shows most active source IP addresses
- Sortable by packet count
- Configurable time range

**3. Traffic Over Time (Time Series)**
- Line graph showing packet counts over time
- 1-minute aggregation windows
- Useful for identifying traffic patterns and spikes

**4. Top Destination IPs (Table)**
- Most contacted destination IP addresses
- Helps identify popular services and potential data exfiltration

**5. Suspicious IPs (Table)**
- IPs flagged by reputation services
- Color-coded by threat level
- Requires IP enrichment to be enabled

**6. Export Links (Text Panel)**
- Direct download buttons for data export
- Supports CSV, JSON, and PCAP formats

**7. Refresh Controls (Text Panel)**
- Manual refresh button for dashboard data
- IP enrichment trigger button

**8. System Status (Text Panel)**
- Real-time system status display
- Shows capture state and packet counts

### Network Geolocation Dashboard

Specialized dashboard for geographic analysis of network traffic.

#### Panel Descriptions

**1. World Map (Placeholder)**
- Geographic visualization of IP locations
- Requires Worldmap Panel plugin installation
- Shows IP distribution by country

**2. Geolocation Table**
- Detailed table of IP geolocation data
- Includes country, city, and ISP information

**3. Country Distribution**
- Statistical breakdown by country
- Shows top countries by IP count

### Customizing Dashboards

#### Adding New Panels
1. Open Grafana at http://localhost:3000
2. Navigate to the desired dashboard
3. Click "Add Panel" in the top menu
4. Configure data source and query
5. Choose visualization type and styling

#### Modifying Queries
Example InfluxDB Flux query for custom metrics:
```flux
from(bucket: "network-traffic")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "network_packet")
  |> filter(fn: (r) => r._field == "length")
  |> group(columns: ["src_ip"])
  |> sum()
  |> sort(columns: ["_value"], desc: true)
  |> limit(n: 10)
```

#### Installing Additional Plugins
```bash
# Install Worldmap Panel plugin
docker-compose exec grafana grafana-cli plugins install grafana-worldmap-panel

# Restart Grafana
docker-compose restart grafana
```


## Troubleshooting

### Common Issues and Solutions

#### 1. Permission Denied for Packet Capture

**Problem**: TShark cannot capture packets due to insufficient permissions.

**Solution**:
```bash
# Option 1: Run with privileged mode (already configured in docker-compose.yml)
docker-compose up -d

# Option 2: Grant capabilities to the user
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Option 3: Add user to wireshark group
sudo usermod -a -G wireshark $USER
```

#### 2. InfluxDB Connection Failed

**Problem**: Cannot connect to InfluxDB database.

**Solutions**:
```bash
# Check if InfluxDB container is running
docker-compose ps influxdb

# Check InfluxDB logs
docker-compose logs influxdb

# Restart InfluxDB service
docker-compose restart influxdb

# Verify InfluxDB is accessible
curl http://localhost:8086/health
```

#### 3. No Network Interface Found

**Problem**: Specified network interface doesn't exist.

**Solutions**:
```bash
# List available interfaces
ip link show

# Update .env file with correct interface
nano .env
# Set CAPTURE_INTERFACE=<correct_interface_name>

# Restart the application
docker-compose restart traffic-analyzer
```

#### 4. Grafana Dashboard Not Loading

**Problem**: Grafana dashboards show no data or fail to load.

**Solutions**:
```bash
# Check Grafana logs
docker-compose logs grafana

# Verify InfluxDB data source configuration
# Navigate to Grafana > Configuration > Data Sources

# Test InfluxDB connection
curl -X POST http://localhost:3000/api/datasources/proxy/1/query \
  -H "Content-Type: application/json" \
  -d '{"query": "SHOW DATABASES"}'

# Restart Grafana
docker-compose restart grafana
```

#### 5. High Memory Usage

**Problem**: System consuming too much memory.

**Solutions**:
```bash
# Reduce packet buffer size in .env
MAX_PACKETS_MEMORY=5000

# Implement data retention policy in InfluxDB
# Add to docker-compose.yml influxdb environment:
DOCKER_INFLUXDB_INIT_RETENTION=7d

# Monitor memory usage
docker stats
```

#### 6. API Enrichment Not Working

**Problem**: IP enrichment features not functioning.

**Solutions**:
```bash
# Verify API keys in .env file
cat .env | grep API_KEY

# Check enrichment statistics
curl http://localhost:5000/api/enrichment/stats

# Test individual IP enrichment
curl -X POST http://localhost:5000/api/enrichment/trigger \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'

# Check rate limiting status
curl http://localhost:5000/api/enrichment/stats
```

### Performance Optimization

#### 1. Capture Filter Optimization
Use specific BPF filters to reduce processing load:
```bash
# Capture only TCP traffic
CAPTURE_FILTER="tcp"

# Exclude local traffic
CAPTURE_FILTER="not host 127.0.0.1 and not net 192.168.0.0/16"

# Focus on specific ports
CAPTURE_FILTER="port 80 or port 443 or port 22"
```

#### 2. InfluxDB Optimization
```bash
# Increase batch size for better performance
# In influxdb_handler.py, modify:
self.buffer_size = 500  # Increase from 100

# Adjust write interval
self.write_interval = 5  # Decrease from 10 seconds
```

#### 3. System Resource Monitoring
```bash
# Monitor Docker container resources
docker stats

# Check disk usage
df -h

# Monitor network interface statistics
cat /proc/net/dev
```

### Logging and Debugging

#### Enable Debug Mode
```bash
# Edit .env file
DEBUG=True
LOG_LEVEL=DEBUG

# Restart application
docker-compose restart traffic-analyzer
```

#### View Application Logs
```bash
# Real-time logs
docker-compose logs -f traffic-analyzer

# Specific time range
docker-compose logs --since="1h" traffic-analyzer

# Save logs to file
docker-compose logs traffic-analyzer > analyzer.log
```

#### Database Debugging
```bash
# Connect to InfluxDB CLI
docker-compose exec influxdb influx

# List buckets
influx bucket list

# Query recent data
influx query 'from(bucket:"network-traffic") |> range(start: -1h) |> limit(n:10)'
```

### Security Considerations

#### 1. Production Deployment
- Change default passwords in docker-compose.yml
- Implement API authentication
- Use HTTPS for web interfaces
- Restrict network access with firewall rules

#### 2. Data Privacy
- Implement data retention policies
- Consider packet data anonymization
- Secure API keys and credentials
- Regular security updates

#### 3. Network Security
```bash
# Limit capture to specific interfaces
CAPTURE_INTERFACE=eth1

# Use restrictive capture filters
CAPTURE_FILTER="not port 22"  # Exclude SSH traffic

# Monitor for suspicious activity
curl http://localhost:5000/api/enrichment/suspicious
```

## Contributing

We welcome contributions to improve the Network Traffic Analyzer! Here's how you can help:

### Development Setup
```bash
# Clone the repository
git clone <repository-url>
cd network-traffic-analyzer

# Install development dependencies
pip3 install -r requirements.txt

# Run tests
python3 test_simple.py
```

### Contribution Guidelines
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Areas for Contribution
- Additional visualization panels
- New IP enrichment data sources
- Performance optimizations
- Security enhancements
- Documentation improvements
- Bug fixes and testing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **TShark/Wireshark** - Network packet capture and analysis
- **InfluxDB** - Time-series database for network data
- **Grafana** - Visualization and dashboarding platform
- **Flask** - Web framework for the API layer
- **Docker** - Containerization platform

## Support

For support and questions:
- Create an issue in the GitHub repository
- Check the troubleshooting section above
- Review the API documentation for integration help

---

**Note**: This tool is designed for network monitoring and security analysis. Ensure you have proper authorization before capturing network traffic in any environment.

