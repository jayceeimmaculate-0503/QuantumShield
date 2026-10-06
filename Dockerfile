FROM python:3.14-slim

# System dependencies required to build liboqs
RUN apt-get update && apt-get install -y \
    git \
    cmake \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs
WORKDIR /tmp

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cmake -S liboqs -B liboqs/build \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_INSTALL_PREFIX=/usr/local && \
    cmake --build liboqs/build --parallel 2 && \
    cmake --install liboqs/build && \
    ldconfig && \
    rm -rf /tmp/liboqs

# QuantumShield application
WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=10000

CMD gunicorn --bind 0.0.0.0:$PORT app:app