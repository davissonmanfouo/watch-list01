#!/bin/sh
set -e

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
  python manage.py migrate
fi

if [ "${RUN_SEED:-true}" = "true" ]; then
  python manage.py seed_data
fi

exec python manage.py runserver 0.0.0.0:"${DJANGO_PORT:-8000}"
