FROM python:3.12-slim

LABEL maintainer="icepaule"
LABEL description="Ice-Leak-Monitoring - Corporate Data Leak Detection"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Europe/Berlin

# System deps + git
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates tzdata pipx \
    && rm -rf /var/lib/apt/lists/*

# TruffleHog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Gitleaks
ARG GITLEAKS_VERSION=8.30.0
RUN curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# Subfinder (subdomain enumeration) - install via Go binary from GitHub releases
RUN SUBFINDER_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    curl -sSfL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -o /tmp/subfinder.zip && \
    apt-get update && apt-get install -y --no-install-recommends unzip && \
    unzip /tmp/subfinder.zip -d /tmp/subfinder && \
    mv /tmp/subfinder/subfinder /usr/local/bin/subfinder && \
    chmod +x /usr/local/bin/subfinder && \
    rm -rf /tmp/subfinder.zip /tmp/subfinder && \
    apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Blackbird OSINT (standalone script from GitHub)
RUN git clone --depth=1 https://github.com/p1ngul1n0/blackbird.git /opt/blackbird \
    && pip install --no-cache-dir -r /opt/blackbird/requirements.txt \
    && ln -s /opt/blackbird/blackbird.py /usr/local/bin/blackbird \
    && chmod +x /opt/blackbird/blackbird.py

WORKDIR /opt/app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY app/ ./app/
COPY static/ ./static/
COPY scripts/ ./scripts/

RUN chmod +x scripts/*.sh

# Data volume
RUN mkdir -p /data
VOLUME /data

EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD ["/opt/app/scripts/healthcheck.sh"]

ENTRYPOINT ["/opt/app/scripts/entrypoint.sh"]
