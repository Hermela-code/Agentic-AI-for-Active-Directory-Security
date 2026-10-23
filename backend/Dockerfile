FROM python:3.11-slim

WORKDIR /app

# Install system dependencies needed for network tools and health probing
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    netcat-traditional \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend and agent source code
COPY . .

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]