# Use a lightweight Python base image
FROM python:3.12-slim

# Prevent Python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
# Prevent Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1

# 1️⃣ Install System Dependencies
# [FIX] Added nodejs and npm for JS/TS support
RUN apt-get update && apt-get install -y \
    git \
    curl \
    unzip \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# 2️⃣ Install Nuclei (DAST Tool)
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip -o nuclei.zip && \
    unzip nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei.zip && \
    nuclei -version

# 3️⃣ Install OSV Scanner (Go Binary)
RUN curl -L "https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_1.9.2_linux_amd64" -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# 4️⃣ Set Up Application Directory
WORKDIR /app
ENV PYTHONPATH=/app
# 4️⃣ Install Universal SBOM Generator (cdxgen)
# This single tool replaces cyclonedx-py and cyclonedx-npm for most use cases
RUN npm install -g @cyclonedx/cdxgen


# 5️⃣ Install Python Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6️⃣ Install Security Tools
# [FIX] Python SCA tool
RUN pip install --no-cache-dir \
    semgrep \
    cyclonedx-bom

# [FIX] Node.js SCA tool (Global install)
RUN npm install -g @cyclonedx/cyclonedx-npm

# 7️⃣ Security Best Practice: Create a non-root user
RUN useradd -m scanner && \
    chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# 8️⃣ Copy Source Code
COPY . .

# 9️⃣ Default Command
CMD ["python", "scripts/check_all_scans.py"]