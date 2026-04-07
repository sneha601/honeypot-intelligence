FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default ports (mapped to real ports in docker-compose)
EXPOSE 2222 2121 8080

CMD ["python", "main.py"]
