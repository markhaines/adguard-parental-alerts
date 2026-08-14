FROM python:3.11-alpine

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN addgroup -S monitor && adduser -S -G monitor monitor

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the monitor script
COPY monitor.py .
USER monitor

# Run the monitor
CMD ["python", "monitor.py"]
