FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive


RUN dpkg --add-architecture i386 && \
    apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    gcc \
    g++ \
    make \
    git \
    curl \
    wget \
    strace \
    ltrace \
    gdb \
    gdbserver \
    netcat-openbsd \
    tcpdump \
    wireshark-common \
    tshark \
    procps \
    iputils-ping \
    net-tools \
    file \
    binutils \
    libc6-dev \
    libssl-dev \
    libffi-dev \
    wine \
    wine32 \
    wine64 \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    frida>=16.0.0 \
    frida-tools>=12.0.0 \
    angr>=9.2.0 \
    cle>=9.1.0 \
    pyelftools>=0.29 \
    psutil>=5.9.0 \
    pyshark>=0.4.5 \
    websockets>=11.0.0

RUN mkdir -p /app/frida_scripts
RUN mkdir -p /app/data
RUN mkdir -p /app/artifacts

RUN groupadd -r reuser && useradd -r -g reuser reuser
RUN chown -R reuser:reuser /app

WORKDIR /app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080 || exit 1

USER reuser
CMD ["python3", "-m", "http.server", "8080"]
