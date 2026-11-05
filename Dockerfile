FROM python:3.12-alpine

WORKDIR /app

# Install dependencies from the same file CI tests against
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the monitor script
COPY monitor.py .

# Run the monitor
CMD ["python", "-u", "monitor.py"]
