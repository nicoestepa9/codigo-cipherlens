#!/bin/sh
set -eu

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
    alembic upgrade head
fi

# Un unico worker es obligatorio: schedulers, rate limits y tareas en curso
# viven en memoria y no estan coordinados entre procesos.
exec uvicorn tls_analyzer.api.main:app \
    --host 0.0.0.0 \
    --port "${PORT:-8000}" \
    --workers 1 \
    --proxy-headers \
    --forwarded-allow-ips="*"
