FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies for scientific Python & DB drivers
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       gcc \
       libpq-dev \
       default-libmysqlclient-dev \
       unixodbc-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source
COPY . .

EXPOSE 5000
ENV PORT=5000

# Run with Gunicorn single worker (compatible with Flask-SocketIO threading mode)
CMD ["gunicorn", "-w", "1", "--bind", "0.0.0.0:5000", "--timeout", "120", "app_flask:app"]

