# ------------------------------
# Base Image
# ------------------------------
FROM python:3.12-slim

# ------------------------------
# Python runtime safety
# ------------------------------
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ------------------------------
# System dependencies (minimal + required)
# ------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    unzip \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------
# Install Nuclei (PINNED + CURRENT)
# ------------------------------
ENV NUCLEI_VERSION=3.6.2

RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip \
    -o nuclei.zip \
    && unzip nuclei.zip \
    && mv nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm nuclei.zip \
    && nuclei -version

# ------------------------------
# Install Syft (SBOM)
# ------------------------------
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ------------------------------
# Install Grype (SCA)
# ------------------------------
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ------------------------------
# Application setup
# ------------------------------
WORKDIR /app
ENV PYTHONPATH=/app

# ------------------------------
# Python dependencies (cacheable layer)
# ------------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir semgrep

# ------------------------------
# Non-root execution (MANDATORY for scanners)
# ------------------------------
RUN useradd -m scanner \
    && chown -R scanner:scanner /app

USER scanner

# ------------------------------
# Nuclei templates (as non-root)
# ------------------------------
RUN nuclei -update-templates

# ------------------------------
# Copy application code
# ------------------------------
COPY --chown=scanner:scanner . .

# ------------------------------
# Default command
# ------------------------------
CMD ["python", "scripts/check_all_scans.py"]
