# syntax=docker/dockerfile:1

# ---- base runtime: zero third-party dependencies for the server ----------
FROM python:3.11-slim AS base
WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080
COPY app/ ./app/
EXPOSE 8080
HEALTHCHECK --interval=3s --timeout=2s --start-period=3s --retries=10 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status==200 else 1)"
CMD ["python3", "app/server.py"]

# ---- one-shot verify gate: adds pytest plus tests and smoke scripts ------
FROM base AS verify
RUN pip install --no-cache-dir pytest==9.1.1
COPY tests/ ./tests/
COPY scripts/ ./scripts/
CMD ["sh", "scripts/verify.sh"]
