FROM ubuntu:22.04


ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC


RUN apt-get update && apt-get install -y \
    wget \
    curl \
    unzip \
    python3.10 \
    python3-pip \
    python3-venv \
    openjdk-21-jdk \
    git \
    && rm -rf /var/lib/apt/lists/*


ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH


WORKDIR /opt
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip \
    && unzip -q ghidra_12.0.4_PUBLIC_20260303.zip \
    && rm ghidra_12.0.4_PUBLIC_20260303.zip \
    && mv ghidra_12.0.4_PUBLIC ghidra

ENV GHIDRA_HOME=/opt/ghidra
ENV GHIDRA_BIN=/opt/ghidra/support/analyzeHeadless


WORKDIR /app


COPY requirements.txt .


RUN pip3 install --no-cache-dir -r requirements.txt

RUN pip3 install --no-index --find-links=/opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist pyghidra


RUN mkdir -p /data/ghidra_projects \
    /app/ghidra_scripts \
    /app/core/mcp \
    /srv/mcp \
    /root/.ghidra


RUN echo "VMARGS=-Xmx8G" > /root/.ghidra/.ghidra_12.0.4.preferences && \
    echo "PREFERENCES_KEY=GhidraKeyring" >> /root/.ghidra/.ghidra_12.0.4.preferences && \
    echo "GhidraKeyring=NO_KEYRING" >> /root/.ghidra/.ghidra_12.0.4.preferences


COPY core/ /app/core/
COPY ghidra_scripts/ /app/ghidra_scripts/


COPY core/mcp/tools.json /srv/mcp/
COPY core/mcp/ghidra_tool_descriptor.json /srv/mcp/


ENV PYTHONUNBUFFERED=1
ENV GHIDRA_SCRIPTS=/app/ghidra_scripts
ENV DATA_DIR=/data/ghidra_projects
ENV MAX_UPLOAD_SIZE=209715200
ENV PYTHONPATH=/opt/ghidra/Ghidra/Features/PyGhidra:/opt/ghidra/Ghidra/Features/PyGhidra/lib


EXPOSE 8000


HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "core.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
