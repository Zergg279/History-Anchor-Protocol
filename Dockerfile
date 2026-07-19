FROM python:3.12-slim

LABEL org.opencontainers.image.title="History Anchor Protocol" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HAP_DATA_DIR=/data \
    HAP_ROLE=observer

RUN groupadd --gid 10001 hap \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin hap \
    && mkdir -p /data \
    && chown -R hap:hap /data

COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

COPY pyproject.toml README.md LICENSE ./
COPY hap ./hap
RUN pip install --no-cache-dir --no-deps .

USER 10001:10001
EXPOSE 8339
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8339/healthz', timeout=3).read()" || exit 1

CMD ["uvicorn", "hap.api:app", "--host", "0.0.0.0", "--port", "8339", "--no-proxy-headers", "--no-server-header", "--limit-concurrency", "100", "--timeout-keep-alive", "5"]
