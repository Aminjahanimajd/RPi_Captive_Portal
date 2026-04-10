FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create persistent data directories
RUN mkdir -p /data/db /data/keys /data/secure_store

ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV DATABASE=/data/db/portal.db
ENV DATA_DIR=/data

EXPOSE 5000

CMD ["python", "app.py"]
