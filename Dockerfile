FROM python:3.12-slim

WORKDIR /app

# Install deps first so this layer caches across code changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Persist the SQLite DB and logs across restarts by mounting a volume here
VOLUME ["/app/data"]
ENV DB_PATH=/app/data/licenses.db
ENV LOG_FILE=/app/data/xzx-delivery.log
ENV PRODUCTS_DIR=/app/products

# Railway/most hosts set PORT; the app already reads it
EXPOSE 8080

CMD ["python", "bot.py"]
