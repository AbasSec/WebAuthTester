# STAGE 1: BUILDER
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# STAGE 2: RUNTIME
FROM python:3.12-slim
RUN useradd -m auditor
USER auditor
WORKDIR /home/auditor/app

# Copy installed packages from builder
COPY --from=builder /root/.local /home/auditor/.local
ENV PATH=/home/auditor/.local/bin:$PATH

# Copy application source
COPY . .

# Ensure wordlists directory exists for volume mounting
RUN mkdir -p wordlists

ENTRYPOINT ["python3", "main.py"]
