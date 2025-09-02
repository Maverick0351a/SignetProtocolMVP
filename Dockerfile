# Runtime image
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends     ca-certificates libsodium23 &&     rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip &&     pip install --no-cache-dir -r requirements.txt

COPY src ./src
ENV PYTHONPATH=/app/src

EXPOSE 8000
CMD ["uvicorn", "signet_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
