FROM python:3.11-slim

# Install system dependencies including TShark and build tools for Python packages
RUN apt-get update && apt-get install -y \
    tshark \
    tcpdump \
    net-tools \
    curl \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create necessary directories
RUN mkdir -p /app/data /app/logs

# Set environment variables
ENV PYTHONPATH=/app
ENV FLASK_APP=src/app.py
ENV FLASK_ENV=production

# Expose port for Flask application
EXPOSE 5001

# Run the application
CMD ["python", "src/app.py"]

