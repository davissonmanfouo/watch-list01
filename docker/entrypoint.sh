#!/bin/sh
set -e

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
  python manage.py migrate
fi

if [ "${RUN_SEED:-false}" = "true" ]; then
  python manage.py seed_data
fi

exec gunicorn todo.wsgi:application \
  --bind 0.0.0.0:"${DJANGO_PORT:-8000}" \
  --workers "${GUNICORN_WORKERS:-3}" \
  --threads "${GUNICORN_THREADS:-2}" \
  --timeout "${GUNICORN_TIMEOUT:-60}" \
  --access-logfile - \
  --error-logfile -
