FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY tls_scanner ./tls_scanner

USER nobody
ENTRYPOINT ["python", "-m", "tls_scanner.main"]
