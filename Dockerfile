FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AEGIS_DATABASE_URL=sqlite:////data/aegis_jit.db

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY policies ./policies
COPY scripts ./scripts
COPY seed_data.py docker-entrypoint.sh ./

# Run as an unprivileged user; only /data (the SQLite volume) is writable.
RUN useradd --system --uid 10001 aegis \
    && mkdir /data && chown aegis /data \
    && chmod +x docker-entrypoint.sh
USER aegis
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
ENTRYPOINT ["./docker-entrypoint.sh"]
