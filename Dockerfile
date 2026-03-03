# ── Build stage ───────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

# libpq-dev is required by psycopg[binary]
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer-cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── App stage ─────────────────────────────────────────────────────────────
COPY . .

# Create the log directory expected in staging/prod
RUN mkdir -p /var/log/pcp_manager

EXPOSE 5000

# ENVIRONMENT env var is injected by the Container App (staging | prod).
# set_env.py reads it from os.environ when no positional arg is supplied.
CMD ["python", "app.py"]
