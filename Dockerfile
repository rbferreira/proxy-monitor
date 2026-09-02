FROM python:3.12-slim

WORKDIR /app

# curl is here for the HEALTHCHECK below. Many orchestrators also inject their
# own curl/wget-based probe and mark the container unhealthy without it, even
# while the app is perfectly up.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY proxy_validator.py settings.py auth.py i18n.py app.py ./

ENV PYTHONUNBUFFERED=1 \
    OUTPUT_FILE=/data/proxies.txt

EXPOSE 8069

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8069/health || exit 1

# One worker on purpose: the scheduler and the proxy state live in memory in
# this process. More workers would mean concurrent validations and each worker
# reporting a different list.
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--timeout", "120", "--bind", "0.0.0.0:8069", "app:app"]
