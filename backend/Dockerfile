# Phase 0 — Docker configuration for Google Cloud Run deployment
# Builds a minimal Python 3.12 image that runs the FastAPI backend on $PORT.
# Cloud Run injects $PORT at runtime (default 8080).

FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install dependencies first (layer cache optimization)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Cloud Run provides $PORT; uvicorn binds to it
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
