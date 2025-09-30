# Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System deps for secp256k1 / cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libsecp256k1-dev libssl-dev libffi-dev \
  && rm -rf /var/lib/apt/lists/*

# Set workdir first
WORKDIR /app

# 1) Copy requirements first (better caching)
COPY requirements.txt ./requirements.txt

# 2) Install Python deps
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r ./requirements.txt

# 3) Copy the rest of your app
COPY . .

# DNS ports (UDP + TCP)
EXPOSE 53/udp
EXPOSE 53/tcp

# Run your resolver (adjust path if your script is elsewhere)
CMD ["python", "npubresolver.py"]
