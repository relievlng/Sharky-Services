FROM python:3.12-slim

WORKDIR /app

# Install deps first so this layer caches across code changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure the data dir exists even before a volume is attached, so the app can
# boot on first run. A mounted volume simply overlays this path.
RUN mkdir -p /app/data

# Persist the SQLite DB and logs by attaching a Railway Volume (or a Docker
# bind-mount on a VPS) at /app/data. Railway rejects the Docker VOLUME keyword
# at build validation, so the mount is configured in the host, not here.
ENV DB_PATH=/app/data/licenses.db
ENV LOG_FILE=/app/data/xzx-delivery.log
ENV PRODUCTS_DIR=/app/products

# Railway/most hosts set PORT; the app already reads it
EXPOSE 8080

CMD ["python", "bot.py"]
