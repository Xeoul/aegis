#!/bin/sh
set -e
# Seed demo data on first start (idempotent), then serve.
python seed_data.py > /dev/null
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers
