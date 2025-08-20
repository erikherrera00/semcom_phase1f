FROM python:3.11-slim

ENV PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# OS deps for building wheels & common libs used by our deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc g++ make \
    python3-dev \
    protobuf-compiler \
    libffi-dev libssl-dev \
    libfreetype6-dev libpng-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt requirements-dev.txt ./

# Upgrade pip toolchain
RUN python -m pip install --upgrade pip setuptools wheel

# Install runtime deps (keep separate so failures are clear)
RUN pip install --no-cache-dir -r requirements.txt

# Install dev/test tools (flake8, pytest, mypy)
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy the rest of the source
COPY . .

# Generate protobufs
RUN python -m grpc_tools.protoc -I proto --python_out=. proto/semantic.proto

# Default command (overridden by compose)
CMD ["python", "-u", "securecomms.py", "--help"]

