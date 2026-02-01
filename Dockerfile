FROM python:3.11-alpine

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir requests urllib3

# Copy the monitor script
COPY monitor.py .

# Run the monitor
CMD ["python", "-u", "monitor.py"]
