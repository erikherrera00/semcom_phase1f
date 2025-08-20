FROM python:3.11-slim

ENV PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# OS deps needed for building wheels & for matplotlib / cryptography / zfec
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc g++ make \
    protobuf-compiler \
    libffi-dev libssl-dev \
    libfreetype6-dev libpng-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# First copy only requirements for better layer caching
COPY requirements.txt requirements-dev.txt ./

# Upgrade pip tooling; then install runtime + (optionally) dev deps
RUN python -m pip install --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -r requirements-dev.txt

# Now copy the source code
COPY . .

# Generate protobufs
RUN python -m grpc_tools.protoc -I proto --python_out=. proto/semantic.proto

# Default (can be overridden by docker run/compose)
CMD ["python","-u","securecomms.py","--help"]

