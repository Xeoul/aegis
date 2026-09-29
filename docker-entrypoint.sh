#!/bin/sh
set -e
# Seed demo data on first start (idempotent), then serve.
python seed_data.py > /dev/null
# Hosting platforms (Render, Railway, Fly) pass the port to listen on in $PORT.
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --proxy-headers --forwarded-allow-ips='*'
