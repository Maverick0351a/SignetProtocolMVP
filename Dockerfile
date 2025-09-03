# Runtime image (pinned by digest for reproducibility)
# Obtain digest with: crane digest python:3.12-slim
FROM python@sha256:REPLACE_WITH_REAL_DIGEST

# Install only runtime dependencies (libsodium for PyNaCl)
RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates libsodium23 \
	&& rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1 \
	PYTHONPATH=/app/src

WORKDIR /app

# Copy only requirements first for better layer caching
COPY requirements.txt ./
# For stronger supply-chain guarantees, consider generating a hashed requirements file
# and using --require-hashes. Example (replace after generating hashes):
# RUN pip install --no-cache-dir --upgrade pip \
# 	&& pip install --no-cache-dir --require-hashes -r requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
	&& pip install --no-cache-dir -r requirements.txt

# Create non-root user and group (uid:gid 1001)
RUN groupadd -g 1001 appuser && useradd -u 1001 -g appuser -m appuser

# Create runtime dirs with correct ownership
RUN mkdir -p /app/src /app/storage /app/keys \
	&& chown -R appuser:appuser /app

# Copy only necessary source (avoid copying tests, docs, etc.)
COPY src/signet_api ./src/signet_api
COPY src/signet_cli ./src/signet_cli
COPY src/signet_sdk ./src/signet_sdk

# Switch to non-root user
USER appuser

EXPOSE 8000
CMD ["uvicorn", "signet_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
