FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV WINEDEBUG=-all


RUN dpkg --add-architecture i386 && \
    apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    wine \
    wine32 \
    wine64 \
    winetricks \
    cabextract \
    curl \
    wget \
    file \
    binutils \
    procps \
    && rm -rf /var/lib/apt/lists/*


RUN wine --version || true


RUN pip3 install --no-cache-dir \
    frida>=16.0.0 \
    frida-tools>=12.0.0 \
    psutil>=5.9.0


RUN mkdir -p /app/data
RUN mkdir -p /app/artifacts


RUN echo '#!/bin/bash\n\
wine "$@"' > /usr/local/bin/wine-wrapper && \
    chmod +x /usr/local/bin/wine-wrapper

WORKDIR /app


HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wine --version || exit 1


CMD ["tail", "-f", "/dev/null"]
