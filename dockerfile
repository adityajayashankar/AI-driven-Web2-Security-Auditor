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
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# 2️⃣ Install Nuclei (DAST Tool)
# Note: Added '-o' to unzip to force overwrite
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip -o nuclei.zip && \
    unzip -o nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei.zip && \
    nuclei -version

# Pre-download Nuclei templates
RUN nuclei -update-templates

# 3️⃣ Install Syft (SBOM Generator)
# [FIX] Replaces cdxgen. Works for Python, JS, Go, Java, etc.
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# 4️⃣ Install Grype (Vulnerability Scanner)
# [FIX] Replaces osv-scanner. Consumes Syft SBOMs.
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# 5️⃣ Set Up Application Directory
WORKDIR /app
ENV PYTHONPATH=/app

# 6️⃣ Install Python Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 7️⃣ Install Security Tools
# Semgrep is still needed for SAST
RUN pip install --no-cache-dir semgrep

# 8️⃣ Security Best Practice: Create a non-root user
RUN useradd -m scanner && \
    chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# 9️⃣ Copy Source Code
COPY . .

# 🔟 Default Command
CMD ["python", "scripts/check_all_scans.py"]