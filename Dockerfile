# Attestation guard service — stdlib only, no third-party runtime packages,
# so the image builds without contacting a package index.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_PORT=8080 \
    APP_HOST=0.0.0.0 \
    DB_PATH=/data/attestations.db \
    KEYS_PATH=/app/deploy/keys.json

WORKDIR /app

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data /app \
    && chown -R appuser:appuser /data /app

COPY --chown=appuser:appuser app ./app
COPY --chown=appuser:appuser scripts ./scripts
COPY --chown=appuser:appuser tests ./tests
COPY --chown=appuser:appuser deploy/keys.json ./deploy/keys.json

USER appuser

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
  CMD python3 -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status==200 else 1)"

CMD ["python3", "-m", "app.server"]
