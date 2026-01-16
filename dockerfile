# Use a lightweight Python base image
FROM python:3.12-slim

# Prevent Python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
# Prevent Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1

# 1️⃣ Install System Dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# 2️⃣ Install Nuclei (DAST Tool)
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip -o nuclei.zip && \
    unzip nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei.zip && \
    nuclei -version

# 3️⃣ Set Up Application Directory
WORKDIR /app

# [CRITICAL] Add /app to PYTHONPATH so imports work correctly
ENV PYTHONPATH=/app

# 4️⃣ Install Python Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5️⃣ Install Security Tools (Python)
# Removed 'pip-audit' as discussed
RUN pip install --no-cache-dir \
    semgrep \
    cyclonedx-bom

# 6️⃣ Install OSV Scanner (Go Binary)
# This MUST be a separate RUN command
RUN curl -L "https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_1.9.2_linux_amd64" -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# 7️⃣ Security Best Practice: Create a non-root user
RUN useradd -m scanner && \
    chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# 8️⃣ Copy Source Code
COPY . .

# 9️⃣ Default Command
CMD ["python", "scripts/check_all_scans.py"]