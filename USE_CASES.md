# LightShark Use Cases

LightShark is designed to be a "drop-in" network debugger for Docker-based microservice architectures.

## 1. "Compiling" LightShark into Existing Projects (Primary Use Case)

The most powerful way to use LightShark is to integrate it directly into your existing `docker-compose.yml` stack. This allows you to inspect traffic between your own services (e.g., API <-> DB, Frontend <-> Backend) without changing a single line of your application code.

### Integrating via Sidecar Pattern

To debug a specific container (e.g., `my-backend-api`), add the `traffic-analyzer` service to your compose file and use `network_mode: service:target-container`.

#### Step-by-Step Integration:

1. Copy the `lightshark-traffic-analyzer` Docker image or build context to your project.
2. Add the following services to your `docker-compose.yml`:

```yaml
services:
  # Your existing service
  my-backend-api:
    image: my-company/backend:latest
    networks:
      - app-net

  # --- LightShark Integration ---
  
  # Network Sidecar - Attaches to 'my-backend-api' network stack
  debug-analyzer:
    build: 
      context: ./path/to/lightshark # Point to LightShark source
    network_mode: service:my-backend-api  # <--- MAGIC TRICK: Sees all traffic of my-backend-api
    environment:
      - INFLUXDB_URL=http://influxdb:8086
      - CAPTURE_INTERFACE=eth0
    depends_on:
      - influxdb

  # Data Storage
  influxdb:
    image: influxdb:2.7
    ports:
      - "8086:8086"
    environment:
      - DOCKER_INFLUXDB_INIT_MODE=setup
      - DOCKER_INFLUXDB_INIT_USERNAME=admin
      - DOCKER_INFLUXDB_INIT_PASSWORD=password123
      - DOCKER_INFLUXDB_INIT_ORG=network-analyzer
      - DOCKER_INFLUXDB_INIT_BUCKET=network-traffic
      - DOCKER_INFLUXDB_INIT_ADMIN_TOKEN=my-token
    networks:
      - app-net

  # Visualization
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - ./lightshark/dashboards:/var/lib/grafana/dashboards
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    depends_on:
      - influxdb
    networks:
      - app-net
```

### Why doing this is useful?

1.  **Zero-Code Instrumentation:** You don't need to add logging libraries, OpenTelemetry, or print statements to your code.
2.  **Full Logic Visibility:** You see the *actual* HTTP requests and responses flowing between containers.
    *   *Frontend getting 500s?* See the exact JSON response body from the backend.
    *   *Slow database queries?* See the exact SQL sent over the wire and how long the TCP packet took.
3.  **Debug Production/Stage Issues:** You can deploy this sidecar to a staging environment to capture traffic for hard-to-reproduce bugs.

## 2. Standalone Network Analysis (Host Mode)

On Linux systems, you can run LightShark in "Host Mode" to monitor the physical network interface of the server.

```yaml
traffic-analyzer:
  network_mode: host  # Monitors the actual Host machine's traffic
  privileged: true
```

*Note: On Windows and macOS, `network_mode: host` only monitors the Docker VM's network, not the host's Wi-Fi/Ethernet, due to OS limitations.*

## 3. Security Auditing

Use LightShark to identify suspicious outgoing connections from your containers.

*   **Detect Crypto Miners:** Spot containers connecting to known mining pool ports.
*   **Data Exfiltration:** See if your database container is initiating connections to unknown external IPs.
*   **Legacy Protocol Detection:** Identify services still using unencrypted HTTP or FTP.
