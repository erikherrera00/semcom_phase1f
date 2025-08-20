FROM python:3.11-slim

WORKDIR /app

# Build tools + protoc for zfec/protobuf
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Compile proto at build time
RUN python -m grpc_tools.protoc -I proto --python_out=. proto/semantic.proto

CMD ["python", "securecomms.py", "--help"]

